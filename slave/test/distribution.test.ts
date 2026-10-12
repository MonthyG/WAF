import { it,expect } from 'vitest';
import { randomBytes,randomUUID } from 'node:crypto';
import { createServer,request as httpRequest } from 'node:http';
import { createServer as tcpServer } from 'node:net';
import { spawn,execFileSync,type ChildProcess } from 'node:child_process';
import { once } from 'node:events';
import { resolve } from 'node:path';
import { mkdir,writeFile } from 'node:fs/promises';
import { eq,sql } from 'drizzle-orm';
import { JSONCodec } from 'nats';
import { connect } from '../src/db/index.js';
import { migrateDatabase } from '../src/db/migrate.js';
import * as s from '../src/db/schema.js';
import { WafService } from '../src/modules/waf/waf.service.js';
import { startWorker } from '../src/workers/waf-worker.js';
import { siteInput,policyPatch,ruleInput } from '../src/modules/waf/validation.js';
import { lintRaw } from '../src/modules/waf/rules/lint.js';

async function waitFor<T>(fn:()=>Promise<T>,check:(v:T)=>boolean,timeout=10000):Promise<T>{const deadline=Date.now()+timeout;let last:T;while(Date.now()<deadline){try{last=await fn();if(check(last))return last;}catch{}await new Promise(r=>setTimeout(r,50));}throw new Error(`Condition did not converge within ${timeout} ms`);}
async function port(){const server=tcpServer();server.listen(0,'127.0.0.1');await once(server,'listening');const address=server.address();if(!address||typeof address==='string')throw new Error('port');await new Promise<void>(r=>server.close(()=>r()));return address.port;}
function container(image:string,inside:number,args:string[]){const id=execFileSync('docker',['run','--rm','-d','-p',`127.0.0.1::${inside}`,image,...args],{encoding:'utf8'}).trim();const address=execFileSync('docker',['port',id,String(inside)],{encoding:'utf8'}).trim();return{id,address};}

it('publishes valid revisions to two agents, retains good config, reloads without drops, and detects offline nodes',async()=>{
  const base=process.env.DATABASE_URL;if(!base)throw new Error('DATABASE_URL required');
  const dbName='waf_dist_'+randomBytes(8).toString('hex');const admin=connect(base);let db:ReturnType<typeof connect>|undefined;let worker:Awaited<ReturnType<typeof startWorker>>|undefined;
  const containers:string[]=[];const processes:ChildProcess[]=[];let logs='';const codec=JSONCodec();
  const origin=createServer((_req,res)=>{res.setHeader('Content-Type','application/json');res.end('{"origin":"ok"}');});
  try{
    await admin.db.execute(sql`CREATE DATABASE ${sql.identifier(dbName)}`);const databaseURL=new URL(base);databaseURL.pathname='/'+dbName;await migrateDatabase(databaseURL.toString());db=connect(databaseURL.toString());
    const nats=container('nats:2.11.8-alpine@sha256:71092f77d707a4a81b12aca5096d6b2d2e07ad16aa57c84066940a17af74f61a',4222,['-js']);containers.push(nats.id);
    const redis=container('redis:8.2.2-alpine@sha256:59b6e694653476de2c992937ebe1c64182af4728e54bb49e9b7a6c26614d8933',6379,[]);containers.push(redis.id);
    origin.listen(0,'127.0.0.1');await once(origin,'listening');const originAddress=origin.address();if(!originAddress||typeof originAddress==='string')throw new Error('origin');
    const ids=[randomUUID(),randomUUID()];const ports=await Promise.all([port(),port()]);const mgmt=await Promise.all([port(),port()]);
    await db.db.insert(s.nodes).values(ids.map((id,i)=>({id,regionId:'local-1',kind:'edge',mgmtIp:'127.0.0.1',publicIp:'127.0.0.1',version:'test'})));
    worker=await startWorker(db.db,{redisURL:'redis://'+redis.address,natsURL:'nats://'+nats.address,region:'local-1',lintBinary:resolve('../waf-node/bin/waf-lint'),queueName:'test-'+randomBytes(4).toString('hex')});
    const startAgent=(i:number)=>{const proc=spawn(resolve('../waf-node/bin/waf-agent'),['-node-id',ids[i],'-nats','nats://'+nats.address,'-listen',`127.0.0.1:${ports[i]}`,'-management',`127.0.0.1:${mgmt[i]}`],{stdio:['ignore','pipe','pipe']});processes.push(proc);proc.stdout?.on('data',b=>{logs+=String(b)});proc.stderr?.on('data',b=>{logs+=String(b)});return proc;};
    const agents=[startAgent(0),startAgent(1)];
    await waitFor(()=>db!.db.select().from(s.nodes),ns=>ns.length===2&&ns.every(n=>n.status==='online'));
    const txt=new Map<string,string[][]>();const projectId=randomUUID();const ctx={userId:'test',projectId,roles:['admin']};
    const svc=new WafService(db.db,{region:'local-1',dnsTarget:'edge.localhost',masterKey:randomBytes(32),resolveTxt:async name=>txt.get(name)??[],lint:lintRaw(resolve('../waf-node/bin/waf-lint'))});
    const site=await svc.createSite(ctx,siteInput.parse({hostname:'shop.localhost',policy:{engine_mode:'block'},origins:[{address:'127.0.0.1',scheme:'http',port:originAddress.port}]}));
    const id=String(site.id);const policyId=String(site.policy_id);const verification=site.verification as {name:string;value:string};txt.set(verification.name,[[verification.value]]);
    await svc.verifySite(ctx,id);
    const current=()=>svc.getSite(ctx,id);
    await waitFor(current,value=>value.status==='active'&&value.config_revision===value.applied_revision);
    // Node's Fetch strips Host overrides; use HTTP directly to exercise routing.
    const fetchNode=(i:number,path='/')=>new Promise<{status:number;text:()=>Promise<string>}>((resolve,reject)=>{
      const req=httpRequest({hostname:'127.0.0.1',port:ports[i],path,headers:{Host:'shop.localhost','User-Agent':'CloudInside integration test'},timeout:5000},res=>{let body='';res.on('data',chunk=>{body+=String(chunk)});res.on('end',()=>resolve({status:res.statusCode!,text:async()=>body}));res.on('error',reject);});
      req.on('error',reject);req.on('timeout',()=>req.destroy(new Error('request timeout')));req.end();
    });
    for(let i=0;i<2;i++){const benign=await fetchNode(i);expect(benign.status).toBe(200);await benign.text();const attack=await fetchNode(i,'/?q='+encodeURIComponent("' OR 1=1 UNION SELECT password FROM users--"));expect(attack.status).toBe(403);await attack.text();}
    const before=(await current()).config_revision;
    await expect(svc.createRule(ctx,policyId,ruleInput.parse({type:'raw',spec:{seclang:'SecRule ARGS "@rx [" "id:9000011,phase:2,deny"'}}))).rejects.toMatchObject({status:422});expect((await current()).config_revision).toBe(before);
    const [stored]=await db.db.select().from(s.bundles).where(eq(s.bundles.siteId,id));
    await worker.nc.jetstream().publish(`waf.config.${ids[0]}`,codec.encode({op:'upsert',bundle:{...stored.payload,revision:Number(before)+100,seclang:'InvalidDirective value'}}));
    await waitFor(async()=>{const r=await fetch(`http://127.0.0.1:${mgmt[0]}/metrics`);return r.text();},text=>text.includes('waf_agent_apply_failures_total 1'));
    const afterInvalid=await fetchNode(0,'/?q='+encodeURIComponent('<script>alert(1)</script>'));expect(afterInvalid.status).toBe(403);await afterInvalid.text();
    let requests=0,dropped=0;let loading=true;
    const load=Array.from({length:4},(_,i)=>(async()=>{while(loading){try{const response=await fetchNode(i%2,'/products?category=books');const text=await response.text();requests++;if(response.status!==200||text!=='{"origin":"ok"}')dropped++;}catch{dropped++;}await new Promise(r=>setTimeout(r,2));}})());
    const latencies:number[]=[];
    try{for(let i=0;i<10;i++){const start=performance.now();await svc.updatePolicy(ctx,policyId,policyPatch.parse({name:'Revision '+i}));await waitFor(current,value=>value.status==='active'&&value.config_revision===value.applied_revision,6000);latencies.push(performance.now()-start);}}finally{loading=false;await Promise.all(load);}
    expect(requests).toBeGreaterThan(100);expect(dropped).toBe(0);latencies.sort((a,b)=>a-b);const p95=latencies[Math.ceil(latencies.length*.95)-1];expect(p95).toBeLessThan(5000);
    const killed=performance.now();agents[1].kill('SIGKILL');await once(agents[1],'exit');
    await waitFor(()=>db!.db.select().from(s.nodes).where(eq(s.nodes.id,ids[1])),ns=>ns[0]?.status==='offline',32000);const offlineMs=performance.now()-killed;expect(offlineMs).toBeLessThan(30000);
    await waitFor(current,value=>value.status==='active'&&value.config_revision===value.applied_revision);
    agents[1]=startAgent(1);await waitFor(()=>db!.db.select().from(s.nodes),ns=>ns.every(n=>n.status==='online'));await waitFor(current,value=>value.status==='active'&&value.config_revision===value.applied_revision);
    const restarted=await fetchNode(1);expect(restarted.status).toBe(200);await restarted.text();
    await svc.deleteSite(ctx,id);
    await waitFor(async()=>{const result=await fetchNode(0);await result.text();return result.status;},status=>status===404);
    await waitFor(async()=>{const result=await fetchNode(1);await result.text();return result.status;},status=>status===404);
    await mkdir('../docs/validation',{recursive:true});await writeFile('../docs/validation/distribution.json',JSON.stringify({recorded_at:new Date().toISOString(),agents:2,revision_changes:10,propagation_ms:latencies,p95_ms:p95,requests_during_reload:requests,dropped_requests:dropped,offline_detection_ms:offlineMs,invalid_rule_rejected:true,invalid_node_bundle_retained_previous:true,restart_snapshot_verified:true,delete_verified:true},null,2)+'\n');
  }finally{
    for(const proc of processes){if(proc.exitCode===null&&proc.signalCode===null){proc.kill('SIGTERM');await Promise.race([once(proc,'exit'),new Promise(r=>setTimeout(r,3000))]);if(proc.exitCode===null&&proc.signalCode===null)proc.kill('SIGKILL');}}
    if(worker)await worker.close();await new Promise<void>(r=>origin.close(()=>r()));if(db)await db.close();
    for(const id of containers)try{execFileSync('docker',['stop','-t','1',id],{stdio:'ignore'});}catch{}
    await admin.db.execute(sql`DROP DATABASE IF EXISTS ${sql.identifier(dbName)}`);await admin.close();
    await mkdir('../.local',{recursive:true});await writeFile('../.local/distribution-test.log',logs);
  }
},90000);
