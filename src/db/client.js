import "server-only";

import { drizzle } from "drizzle-orm/node-postgres";
import pg from "pg";
import * as schema from "./schema.js";

const { Pool } = pg;

let pool;
let database;

export function db() {
  if (database) {
    return database;
  }

  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    throw new Error("DATABASE_URL is required");
  }

  pool = new Pool({
    connectionString,
    max: connectionPoolSize(),
  });
  database = drizzle(pool, { schema });
  return database;
}

export async function closeDb() {
  if (!pool) {
    return;
  }

  await pool.end();
  pool = undefined;
  database = undefined;
}

function connectionPoolSize() {
  const configured = Number(process.env.DATABASE_POOL_SIZE || 10);
  return Number.isFinite(configured) && configured > 0 ? Math.min(configured, 25) : 10;
}
