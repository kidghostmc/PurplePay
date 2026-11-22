import { neon } from '@neondatabase/serverless';
import { AppError } from './security.js';
let sql;
let initializing;
export async function database() {
  if (!process.env.DATABASE_URL) throw new AppError(503, 'O administrador precisa concluir a configuração do serviço.');
  sql ||= neon(process.env.DATABASE_URL);
  if (!initializing) {
    initializing = initializeDatabase(sql).catch(error => { initializing = null; throw error; });
  }
  await initializing;
  return sql;
}
export function initializeDatabase(sql) {
  return sql.transaction([
      sql`CREATE TABLE IF NOT EXISTS pp_attendants (
        id SERIAL PRIMARY KEY, nome TEXT NOT NULL, pct NUMERIC(5,2) NOT NULL CHECK(pct > 0 AND pct <= 100),
        tel TEXT NOT NULL, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, active BOOLEAN NOT NULL DEFAULT true
      )`,
      sql`CREATE TABLE IF NOT EXISTS pp_sessions (
        token_hash TEXT PRIMARY KEY, role TEXT NOT NULL CHECK(role IN ('mod','at')), aid INTEGER,
        expires_at TIMESTAMPTZ NOT NULL
      )`,
      sql`CREATE TABLE IF NOT EXISTS pp_orders (
        id UUID PRIMARY KEY, external_id TEXT UNIQUE NOT NULL, creator TEXT NOT NULL,
        aid INTEGER REFERENCES pp_attendants(id), pct NUMERIC(5,2) NOT NULL DEFAULT 0,
        amount_cents INTEGER NOT NULL CHECK(amount_cents >= 100),
        status TEXT NOT NULL DEFAULT 'creating', nexus_id TEXT UNIQUE,
        pix_code TEXT, qr_image TEXT, expires_at TIMESTAMPTZ, paid_at TIMESTAMPTZ,
        fee_cents INTEGER, net_cents INTEGER, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_checked_at TIMESTAMPTZ
      )`,
      sql`CREATE INDEX IF NOT EXISTS pp_orders_status_idx ON pp_orders(status, created_at)`,
      sql`CREATE TABLE IF NOT EXISTS pp_settings (id INTEGER PRIMARY KEY CHECK(id=1), meta INTEGER NOT NULL DEFAULT 1000)`,
      sql`INSERT INTO pp_settings (id) VALUES(1) ON CONFLICT DO NOTHING`,
      sql`CREATE TABLE IF NOT EXISTS pp_limits (key TEXT NOT NULL, bucket BIGINT NOT NULL, count INTEGER NOT NULL, PRIMARY KEY(key,bucket))`
    ]);
}
export async function limit(sql, key, max, seconds) {
  const bucket = Math.floor(Date.now() / (seconds * 1000));
  const [row] = await sql`INSERT INTO pp_limits (key,bucket,count) VALUES (${key},${bucket},1)
    ON CONFLICT(key,bucket) DO UPDATE SET count=pp_limits.count+1 RETURNING count`;
  if (row.count > max) throw new AppError(429, 'Muitas tentativas. Aguarde alguns minutos.');
}
