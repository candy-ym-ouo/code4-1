#!/usr/bin/env node
// Test-only helper used by ops/smoke-test.mjs to expire sessions directly in
// PostgreSQL. Usage: node exec-sql.mjs "SELECT ...". Not loaded by the server.
import pg from "pg";

const sql = process.argv[2];
if (!sql) {
  console.error("usage: exec-sql.mjs <sql>");
  process.exit(2);
}

const client = new pg.Client({
  connectionString: process.env.DATABASE_URL ?? "postgresql://handcraft:change-me@localhost:55432/handcraft"
});
await client.connect();
try {
  const result = await client.query(sql);
  if (result.rows.length) console.log(JSON.stringify(result.rows));
} finally {
  await client.end();
}
