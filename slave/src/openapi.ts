import { fileURLToPath } from 'node:url';
import { mkdir, writeFile } from 'node:fs/promises';
import { OpenAPIRegistry,OpenApiGeneratorV3 } from '@asteasolutions/zod-to-openapi';
import { z } from 'zod';
import * as v from './modules/waf/validation.js';

export function openapi(){
  const r=new OpenAPIRegistry();r.registerComponent('securitySchemes','KeystoneToken',{type:'apiKey',in:'header',name:'X-Auth-Token'});
  const routes:Array<[string,string,z.ZodTypeAny?,number?]>=[
    ['get','/sites'],['post','/sites',v.siteInput,202],['get','/sites/{id}'],['patch','/sites/{id}',v.sitePatch],['delete','/sites/{id}',undefined,202],['post','/sites/{id}/verify',undefined,202],
    ['get','/sites/{id}/origins'],['post','/sites/{id}/origins',v.originInput,201],['delete','/sites/{id}/origins/{originId}',undefined,204],
    ['get','/policies'],['post','/policies',v.policyInput,201],['get','/policies/{id}'],['patch','/policies/{id}',v.policyPatch],['delete','/policies/{id}',undefined,204],
    ['get','/policies/{id}/rules'],['post','/policies/{id}/rules',v.ruleInput,201],['patch','/policies/{id}/rules/{ruleId}',v.rulePatch],['delete','/policies/{id}/rules/{ruleId}',undefined,204],
    ['get','/certificates'],['post','/certificates',v.certificateInput,202],['get','/certificates/{id}'],['delete','/certificates/{id}',undefined,204],['get','/nodes'],['post','/nodes/{id}/drain',undefined,202],
  ];
  const error=z.object({error:z.object({code:z.string(),message:z.string(),details:z.unknown().optional()})});
  for(const[method,path,body,status=200]of routes){const params=Object.fromEntries([...path.matchAll(/\{(\w+)\}/g)].map(m=>[m[1],v.uuid]));r.registerPath({method:method as 'get'|'post'|'patch'|'delete',path,summary:method.toUpperCase()+' '+path,security:[{KeystoneToken:[]}],request:{...(body?{body:{required:true,content:{'application/json':{schema:body}}}}:{}),...(Object.keys(params).length?{params:z.object(params)}:{})},responses:{[status]:{description:status===202?'Accepted for asynchronous processing':'Success',...(status===204?{}:{content:{'application/json':{schema:z.record(z.unknown())}}})},401:{description:'Missing, invalid, expired, or unscoped Keystone token',content:{'application/json':{schema:error}}},403:{description:'Administrator role required'},404:{description:'Not found in the token project and current region'},409:{description:'Resource conflict or resource in use'},422:{description:'Validation error',content:{'application/json':{schema:error}}}}});}
  return new OpenApiGeneratorV3(r.definitions).generateDocument({openapi:'3.0.3',info:{title:'CloudInside WAF API',version:'0.1.0',description:'Phase 2 control-plane API. Tenant operations are always scoped to the token project, including administrator tokens; node operations require admin.'},servers:[{url:'/v1/waf'},{url:'/waf/v1'}]});
}
if(process.argv[1]===fileURLToPath(import.meta.url)){await mkdir('../docs',{recursive:true});await writeFile('../docs/openapi.json',JSON.stringify(openapi(),null,2)+'\n');console.log('Generated docs/openapi.json');}
