import { isIP } from 'node:net';
import { z } from 'zod';
import { extendZodWithOpenApi } from '@asteasolutions/zod-to-openapi';
extendZodWithOpenApi(z);

export const uuid=z.string().uuid();
export const hostname=z.string().trim().toLowerCase().max(253).regex(/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/,'Expected a DNS hostname, without wildcard or port');
export const pathPrefix=z.string().min(1).max(2048).regex(/^\/[a-zA-Z0-9_./~%-]*$/,'Path must start with / and contain only URL path characters');
const address=z.string().max(253).refine(v=>isIP(v)!==0 || hostname.safeParse(v).success,'Expected IP address or hostname');
export const originInput=z.object({address,port:z.number().int().min(1).max(65535),scheme:z.enum(['http','https']),weight:z.number().int().min(1).max(100).default(1),health_check_path:pathPrefix.default('/'),instance_id:uuid.nullable().optional()}).strict().openapi('OriginInput');
export const policyInput=z.object({name:z.string().trim().min(1).max(128).default('Default policy'),engine_mode:z.enum(['detect','block','off']).default('detect'),paranoia_level:z.number().int().min(1).max(4).default(1),inbound_anomaly_threshold:z.number().int().min(1).max(1000).default(5),outbound_anomaly_threshold:z.number().int().min(1).max(1000).default(4),request_body_limit_kb:z.number().int().min(1).max(131072).default(1024),inspect_response_body:z.boolean().default(false)}).strict().openapi('PolicyInput');
export const policyPatch=policyInput.partial().refine(v=>Object.keys(v).length>0,'Provide at least one setting');
export const siteInput=z.object({hostname,mode:z.literal('shared').default('shared'),origins:z.array(originInput).min(1).max(20),policy:policyInput.optional(),policy_id:uuid.optional(),tls:z.object({source:z.literal('acme')}).strict().optional()}).strict().refine(v=>!(v.policy&&v.policy_id),'Choose policy or policy_id').openapi('SiteInput');
export const sitePatch=z.object({policy_id:uuid.optional(),certificate_id:uuid.nullable().optional(),http_redirect:z.boolean().optional()}).strict().refine(v=>Object.keys(v).length>0,'Provide at least one setting');
const cidr=z.string().refine(v=>{const [ip,bits,...rest]=v.split('/');const family=isIP(ip);return family!==0 && rest.length===0 && (bits===undefined || /^\d{1,3}$/.test(bits) && +bits>=0 && +bits<=(family===4?32:128));},'Invalid IP or CIDR');
const ids=z.array(z.number().int().min(900000).max(999999)).min(1).max(100);
const base={priority:z.number().int().min(0).max(99999).default(100),enabled:z.boolean().default(true)};
const ipSpec=z.object({cidrs:z.array(cidr).min(1).max(1000)}).strict();
export const ruleInput=z.discriminatedUnion('type',[
  z.object({...base,type:z.literal('ip_allow'),spec:ipSpec}).strict(),
  z.object({...base,type:z.literal('ip_deny'),spec:ipSpec}).strict(),
  z.object({...base,type:z.literal('geo_deny'),spec:z.object({countries:z.array(z.string().regex(/^[A-Z]{2}$/)).min(1).max(249)}).strict()}).strict(),
  z.object({...base,type:z.literal('rule_exclusion'),spec:z.object({rule_ids:ids,path_prefix:pathPrefix.optional(),args:z.array(z.string().regex(/^[a-zA-Z0-9_.-]{1,128}$/)).min(1).max(100).optional()}).strict()}).strict(),
  z.object({...base,type:z.literal('path_exclusion'),spec:z.object({path_prefix:pathPrefix}).strict()}).strict(),
  z.object({...base,type:z.literal('rate_limit'),spec:z.object({key:z.enum(['ip','ip+path']),limit:z.number().int().min(1).max(1000000),window_s:z.number().int().min(1).max(86400),path_prefix:pathPrefix.optional(),action:z.enum(['block','log'])}).strict()}).strict(),
  z.object({...base,type:z.literal('raw'),spec:z.object({seclang:z.string().min(1).max(65536)}).strict()}).strict(),
]).openapi('RuleInput');
export const rulePatch=z.object({priority:base.priority.optional(),enabled:base.enabled.optional(),spec:z.record(z.unknown()).optional()}).strict().refine(v=>Object.keys(v).length>0,'Provide at least one setting');
export const certificateInput=z.discriminatedUnion('source',[
  z.object({source:z.literal('upload'),domains:z.array(hostname).min(1).max(100),cert_pem:z.string().min(1).max(65536),key_pem:z.string().min(1).max(32768)}).strict(),
  z.object({source:z.literal('acme'),domains:z.array(hostname).min(1).max(100)}).strict(),
]).openapi('CertificateInput');

export function camel<T=Record<string,unknown>>(data:Record<string,unknown>):T {return Object.fromEntries(Object.entries(data).map(([k,v])=>[k.replace(/_([a-z])/g,(_,c:string)=>c.toUpperCase()),v])) as T;}
export function dto<T extends Record<string,unknown>>(data:T):Record<string,unknown> {return Object.fromEntries(Object.entries(data).filter(([k])=>k!=='keyPemEncrypted').map(([k,v])=>[k.replace(/[A-Z]/g,c=>'_'+c.toLowerCase()),v]));}
