import { createHash } from 'node:crypto';
import type { RequestHandler } from 'express';
import { z } from 'zod';
import { HttpError } from '../errors.js';

export type Context={userId:string;projectId:string;roles:string[]};
declare global {namespace Express {interface Request {ctx:Context}}}
const tokenSchema=z.object({token:z.object({expires_at:z.string().datetime({offset:true}),user:z.object({id:z.string().min(1)}),project:z.object({id:z.string().uuid()}),roles:z.array(z.object({name:z.string()}))})});

export function keystoneAuth(url:string,serviceToken:()=>Promise<string>):RequestHandler {
  const cache=new Map<string,{ctx:Context;expires:number}>();
  const endpoint=new URL('v3/auth/tokens',url.endsWith('/')?url:url+'/');
  return async(req,_res,next)=>{
    try {
      const token=req.get('X-Auth-Token');
      if(!token || token.length>16384)throw new HttpError(401,'unauthorized','A valid X-Auth-Token is required');
      const key=createHash('sha256').update(token).digest('hex');
      const cached=cache.get(key);
      if(cached && cached.expires>Date.now()){req.ctx=cached.ctx;next();return;}
      cache.delete(key);
      let response:Response;
      try {response=await fetch(endpoint,{headers:{'X-Auth-Token':await serviceToken(),'X-Subject-Token':token},signal:AbortSignal.timeout(5000),redirect:'error'});}
      catch {throw new HttpError(503,'identity_unavailable','Identity service is unavailable');}
      if(response.status===404 || response.status===401)throw new HttpError(401,'unauthorized','Token is invalid or expired');
      if(!response.ok)throw new HttpError(503,'identity_unavailable','Identity service rejected validation');
      const parsed=tokenSchema.safeParse(await response.json());
      if(!parsed.success)throw new HttpError(401,'unauthorized','A project-scoped token is required');
      const t=parsed.data.token;const expires=Math.min(Date.parse(t.expires_at),Date.now()+300000);
      if(expires<=Date.now())throw new HttpError(401,'unauthorized','Token is expired');
      req.ctx={userId:t.user.id,projectId:t.project.id,roles:t.roles.map(r=>r.name)};
      // Bound memory without storing any raw token.
      if(cache.size>=10000)cache.delete(cache.keys().next().value!);
      cache.set(key,{ctx:req.ctx,expires});next();
    }catch(err){next(err);}
  };
}
export const adminOnly:RequestHandler=(req,_res,next)=>req.ctx.roles.includes('admin')?next():next(new HttpError(403,'forbidden','Administrator role required'));
