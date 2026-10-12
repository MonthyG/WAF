import { fileURLToPath } from 'node:url';
import { connect } from '../db/index.js';
import { startWorker } from './waf-worker.js';
function required(name:string){const value=process.env[name];if(!value)throw new Error(`${name} is required`);return value;}
const conn=connect(required('DATABASE_URL'));
const worker=await startWorker(conn.db,{redisURL:required('REDIS_URL'),natsURL:required('NATS_URL'),natsCredentials:process.env.NATS_CREDENTIALS,region:process.env.WAF_REGION??'local-1',lintBinary:process.env.WAF_LINT_BINARY??fileURLToPath(new URL('../../../waf-node/bin/waf-lint',import.meta.url))});
console.log('WAF worker ready');
for(const signal of ['SIGINT','SIGTERM'] as const)process.once(signal,async()=>{await worker.close();await conn.close();process.exit(0);});
