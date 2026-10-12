import { Queue,Worker } from 'bullmq';
import { Redis } from 'ioredis';
import { connect,JSONCodec,RetentionPolicy,StorageType,nanos,type NatsConnection,type Msg,credsAuthenticator } from 'nats';
import { readFile } from 'node:fs/promises';
import { and,eq,inArray,lt,ne,sql } from 'drizzle-orm';
import { z } from 'zod';
import type { DB,Transaction } from '../db/index.js';
import * as s from '../db/schema.js';
import { compileBundle,type SiteBundle } from '../modules/waf/rules/rules.compiler.js';
import { lintCompiled } from '../modules/waf/rules/lint.js';

const codec=JSONCodec();
const heartbeat=z.object({node_id:z.string().uuid(),version:z.string().max(128),load:z.number(),applied:z.record(z.number().int().nonnegative())});
const ackSchema=z.object({node_id:z.string().uuid(),site_id:z.string().uuid(),revision:z.number().int().positive(),ok:z.boolean(),error:z.string().max(512).optional()});
export type WorkerOptions={redisURL:string;natsURL:string;natsCredentials?:string;region:string;lintBinary:string;queueName?:string};
const lock=async(tx:Transaction)=>{await tx.execute(sql`select pg_advisory_xact_lock(963281)`);};

export async function startWorker(db:DB,o:WorkerOptions){
  const creds=o.natsCredentials?await readFile(o.natsCredentials):undefined;
  const host=new URL(o.natsURL).hostname;if(!creds&&!['127.0.0.1','[::1]','localhost'].includes(host))throw new Error('Non-loopback NATS requires credentials');
  const nc=await connect({servers:o.natsURL,...(creds?{authenticator:credsAuthenticator(creds)}:{}),name:'waf-control',maxReconnectAttempts:-1});
  const jsm=await nc.jetstreamManager();
  try{await jsm.streams.info('WAF_CONFIG');}catch(err){if((err as {code?:string}).code!=='404')throw err;await jsm.streams.add({name:'WAF_CONFIG',subjects:['waf.config.*'],retention:RetentionPolicy.Workqueue,storage:StorageType.File,max_age:nanos(7*24*3600*1000)});}
  const js=nc.jetstream();
  const redis=new Redis(o.redisURL,{maxRetriesPerRequest:null});
  const queue=new Queue(o.queueName??'waf-compile',{connection:redis});
  let stopping=false,pumping=false;
  const tasks:Promise<unknown>[]=[];
  const subscribe=(subject:string,fn:(m:Msg)=>Promise<void>)=>{const sub=nc.subscribe(subject,{queue:'waf-control'});tasks.push((async()=>{for await(const m of sub){try{await fn(m);}catch{console.error(JSON.stringify({level:'error',message:'WAF control message failed',subject:m.subject}));}}})());};

  async function settle(tx:Transaction,siteId:string){
    const [site]=await tx.select().from(s.sites).where(eq(s.sites.id,siteId)).for('update');if(!site)return;
    const assigned=await tx.select({node:s.nodes}).from(s.siteNodes).innerJoin(s.nodes,eq(s.siteNodes.nodeId,s.nodes.id)).where(eq(s.siteNodes.siteId,siteId));
    if(!assigned.length)return;
    const min=Math.min(...assigned.map(a=>a.node.appliedRevisionMap[siteId]??0));
    if(site.status==='deleting'&&min>=site.configRevision){await tx.delete(s.sites).where(eq(s.sites.id,siteId));return;}
    await tx.update(s.sites).set({appliedRevision:Math.min(min,site.configRevision),...(min>=site.configRevision&&site.verifiedAt?{status:'active',lastError:null}:{}),updatedAt:new Date()}).where(eq(s.sites.id,siteId));
  }

  subscribe('waf.node.heartbeat.*',async m=>{
    const parsed=heartbeat.safeParse(codec.decode(m.data));if(!parsed.success)return;const h=parsed.data;
    if(m.subject!==`waf.node.heartbeat.${h.node_id}`)return;
    await db.transaction(async tx=>{await lock(tx);
      const [node]=await tx.select().from(s.nodes).where(and(eq(s.nodes.id,h.node_id),eq(s.nodes.regionId,o.region))).for('update');if(!node)return;
      const applied={...node.appliedRevisionMap};for(const[id,revision]of Object.entries(h.applied))applied[id]=Math.max(applied[id]??0,revision);
      await tx.update(s.nodes).set({version:h.version,lastHeartbeatAt:new Date(),status:node.status==='draining'?'draining':'online',appliedRevisionMap:applied,updatedAt:new Date()}).where(eq(s.nodes.id,node.id));
      const assignments=await tx.select().from(s.siteNodes).where(eq(s.siteNodes.nodeId,node.id));for(const a of assignments)await settle(tx,a.siteId);
      if(node.status==='offline'){
        const sites=await tx.select().from(s.sites).where(and(eq(s.sites.regionId,o.region),ne(s.sites.status,'deleting')));
        for(const site of sites)if(site.verifiedAt)await tx.insert(s.jobs).values({kind:'compile',siteId:site.id,revision:site.configRevision});
      }
    });
  });
  subscribe('waf.node.ack.*',async m=>{
    const parsed=ackSchema.safeParse(codec.decode(m.data));if(!parsed.success)return;const a=parsed.data;if(m.subject!==`waf.node.ack.${a.node_id}`)return;
    await db.transaction(async tx=>{await lock(tx);
      const [assigned]=await tx.select().from(s.siteNodes).where(and(eq(s.siteNodes.nodeId,a.node_id),eq(s.siteNodes.siteId,a.site_id)));if(!assigned)return;
      const [node]=await tx.select().from(s.nodes).where(and(eq(s.nodes.id,a.node_id),eq(s.nodes.regionId,o.region))).for('update');if(!node)return;
      const [site]=await tx.select().from(s.sites).where(eq(s.sites.id,a.site_id));if(!site||a.revision>site.configRevision)return;
      if(!a.ok){if(a.revision===site.configRevision)await tx.update(s.sites).set({status:'error',lastError:'Edge node rejected the configuration'}).where(eq(s.sites.id,site.id));return;}
      await tx.update(s.nodes).set({appliedRevisionMap:{...node.appliedRevisionMap,[a.site_id]:Math.max(node.appliedRevisionMap[a.site_id]??0,a.revision)}}).where(eq(s.nodes.id,node.id));await settle(tx,a.site_id);
    });
  });
  subscribe('waf.config.snapshot.*',async m=>{
    const id=m.subject.split('.').at(-1);if(!id||!z.string().uuid().safeParse(id).success)return;
    await db.transaction(async tx=>{await lock(tx);
      const [node]=await tx.select().from(s.nodes).where(and(eq(s.nodes.id,id),eq(s.nodes.regionId,o.region)));if(!node){m.respond(codec.encode({error:'Node is not registered'}));return;}
      const rows=await tx.select({bundle:s.bundles.payload}).from(s.siteNodes).innerJoin(s.sites,eq(s.siteNodes.siteId,s.sites.id)).innerJoin(s.bundles,eq(s.bundles.siteId,s.sites.id)).where(and(eq(s.siteNodes.nodeId,id),ne(s.sites.status,'deleting')));
      const info=await jsm.streams.info('WAF_CONFIG');m.respond(codec.encode({bundles:rows.map(r=>r.bundle),sequence:info.state.last_seq}));
    });
  });

  const worker=new Worker(o.queueName??'waf-compile',async task=>{
    const jobId=String(task.data.outboxId);let publicationFailed=false;
    await db.transaction(async tx=>{await lock(tx);
      const [job]=await tx.select().from(s.jobs).where(eq(s.jobs.id,jobId)).for('update');if(!job||job.status==='done')return;
      if(job.kind==='node.drain'){
        const id=z.string().uuid().parse(job.payload.nodeId);const assignments=await tx.select().from(s.siteNodes).where(eq(s.siteNodes.nodeId,id));
        for(const a of assignments)await tx.insert(s.jobs).values({kind:'compile',siteId:a.siteId});
        await tx.update(s.jobs).set({status:'done',updatedAt:new Date()}).where(eq(s.jobs.id,jobId));return;
      }
      if(!job.siteId){await tx.update(s.jobs).set({status:'error',lastError:'Job requires a later implementation phase'}).where(eq(s.jobs.id,jobId));return;}
      const [site]=await tx.select().from(s.sites).where(and(eq(s.sites.id,job.siteId),eq(s.sites.regionId,o.region))).for('update');
      if(!site || !site.verifiedAt && site.status!=='deleting'){await tx.update(s.jobs).set({status:'done'}).where(eq(s.jobs.id,jobId));return;}
      if(job.revision && job.revision<site.configRevision){await tx.update(s.jobs).set({status:'done'}).where(eq(s.jobs.id,jobId));return;}
      let payload:Record<string,unknown>;
      let assigned=await tx.select({node:s.nodes}).from(s.siteNodes).innerJoin(s.nodes,eq(s.nodes.id,s.siteNodes.nodeId)).where(eq(s.siteNodes.siteId,site.id));
      if(site.status==='deleting')payload={op:'delete',bundle:{site_id:site.id,revision:site.configRevision}};
      else{
        try{
          const [policy]=await tx.select().from(s.policies).where(and(eq(s.policies.id,site.policyId),eq(s.policies.projectId,site.projectId)));
          const origins=await tx.select().from(s.origins).where(and(eq(s.origins.siteId,site.id),eq(s.origins.projectId,site.projectId)));
          const rules=await tx.select().from(s.rules).where(and(eq(s.rules.policyId,site.policyId),eq(s.rules.projectId,site.projectId)));
          const available=await tx.select().from(s.nodes).where(and(eq(s.nodes.regionId,o.region),eq(s.nodes.kind,'edge'),eq(s.nodes.status,'online')));
          if(!available.length)throw new Error('No online edge nodes are available');
          const removed=assigned.filter(a=>!available.some(n=>n.id===a.node.id));
          if(assigned.length && (removed.length || available.some(n=>!assigned.some(a=>a.node.id===n.id)))){
            site.configRevision++;
            await tx.update(s.sites).set({configRevision:site.configRevision,updatedAt:new Date()}).where(eq(s.sites.id,site.id));
          }
          const bundle=compileBundle(site,policy,origins,rules);await lintCompiled(o.lintBinary,bundle.seclang);
          for(const a of removed){await js.publish(`waf.config.${a.node.id}`,codec.encode({op:'delete',bundle:{site_id:site.id,revision:site.configRevision}}));}
          await tx.delete(s.siteNodes).where(eq(s.siteNodes.siteId,site.id));await tx.insert(s.siteNodes).values(available.map(n=>({siteId:site.id,nodeId:n.id})));
          assigned=available.map(node=>({node}));
          await tx.insert(s.bundles).values({siteId:site.id,revision:bundle.revision,payload:bundle as unknown as Record<string,unknown>}).onConflictDoUpdate({target:s.bundles.siteId,set:{revision:bundle.revision,payload:bundle as unknown as Record<string,unknown>,updatedAt:new Date()}});
          payload={op:'upsert',bundle};
          await tx.update(s.sites).set({status:'provisioning',lastError:null}).where(eq(s.sites.id,site.id));
        }catch(err){
          const message=err instanceof Error&&err.message.includes('Phase 7')?err.message:'Configuration failed validation or no edge node is available';
          await tx.update(s.sites).set({status:'error',lastError:message}).where(eq(s.sites.id,site.id));await tx.update(s.jobs).set({status:'error',lastError:message}).where(eq(s.jobs.id,jobId));return;
        }
      }
      // Hold the same advisory lock as snapshots. Commit a compiled bundle even
      // if publication fails, so a snapshot never skips an uncommitted revision.
      try{for(const a of assigned)await js.publish(`waf.config.${a.node.id}`,codec.encode(payload),{msgID:`${a.node.id}-${site.id}-${site.configRevision}-${site.status==='deleting'?'delete':'upsert'}`});}
      catch{publicationFailed=true;}
      if(!assigned.length&&site.status==='deleting')await tx.delete(s.sites).where(eq(s.sites.id,site.id));
      await tx.update(s.jobs).set({status:publicationFailed?'queued':'done',attempts:job.attempts+1,lastError:publicationFailed?'NATS publication failed':null,updatedAt:new Date()}).where(eq(s.jobs.id,jobId));
      if(!publicationFailed&&site.status!=='deleting')await settle(tx,site.id);
    });
    if(publicationFailed)throw new Error('NATS publication failed');
  },{connection:redis,concurrency:2});
  worker.on('error',()=>console.error('WAF worker connection error'));worker.on('failed',()=>console.error('WAF job failed; retry scheduled by BullMQ'));

  async function pump(){if(stopping||pumping)return;pumping=true;try{
    const pending=await db.select().from(s.jobs).where(inArray(s.jobs.status,['pending','queued'])).limit(100);
    for(const job of pending){
      if(job.kind==='cert.issue')continue;
      await db.update(s.jobs).set({status:'queued'}).where(and(eq(s.jobs.id,job.id),eq(s.jobs.status,'pending')));
      try{await queue.add(job.kind,{outboxId:job.id},{jobId:job.id,attempts:10,backoff:{type:'exponential',delay:1000},removeOnComplete:1000,removeOnFail:1000});}
      catch{await db.update(s.jobs).set({status:'pending'}).where(and(eq(s.jobs.id,job.id),eq(s.jobs.status,'queued')));}
    }
    await db.transaction(async tx=>{await lock(tx);
      const offline=await tx.update(s.nodes).set({status:'offline',updatedAt:new Date()}).where(and(eq(s.nodes.regionId,o.region),inArray(s.nodes.status,['online','degraded']),lt(s.nodes.lastHeartbeatAt,new Date(Date.now()-29000)))).returning();
      for(const node of offline){const affected=await tx.select().from(s.siteNodes).where(eq(s.siteNodes.nodeId,node.id));for(const a of affected)await tx.insert(s.jobs).values({kind:'compile',siteId:a.siteId});}
    });
  }finally{pumping=false;}}
  const interval=setInterval(()=>void pump().catch(()=>console.error('WAF outbox pump failed')),250);
  await nc.flush();await worker.waitUntilReady();await pump();
  return {nc,async close(){stopping=true;clearInterval(interval);while(pumping)await new Promise(r=>setTimeout(r,10));await worker.close();await queue.close();await redis.quit();await nc.drain();await Promise.allSettled(tasks);}};
}
