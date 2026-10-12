import postgres from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';
import * as schema from './schema.js';

export function connect(url: string) {
  const client = postgres(url, { max:10, idle_timeout:20, connect_timeout:5 });
  return { db:drizzle(client,{schema}), close:()=>client.end({timeout:5}) };
}
export type DB = ReturnType<typeof connect>['db'];
export type Transaction = Parameters<Parameters<DB['transaction']>[0]>[0];
