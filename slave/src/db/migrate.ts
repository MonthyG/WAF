import { fileURLToPath } from 'node:url';
import { migrate } from 'drizzle-orm/postgres-js/migrator';
import { connect } from './index.js';

export async function migrateDatabase(url: string) {
  const conn = connect(url);
  try {
    await migrate(conn.db, {
      migrationsFolder: fileURLToPath(new URL('./migrations', import.meta.url)),
    });
  } finally {
    await conn.close();
  }
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');
  await migrateDatabase(process.env.DATABASE_URL);
  console.log('WAF migrations applied');
}
