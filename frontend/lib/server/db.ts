import { Pool } from "pg";

declare global {
  // eslint-disable-next-line no-var
  var __ghostFrontendPgPool: Pool | undefined;
  // eslint-disable-next-line no-var
  var __ghostFrontendAuthSchemaPromise: Promise<void> | undefined;
}

function requireEnv(name: string) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function buildPool() {
  if (!global.__ghostFrontendPgPool) {
    global.__ghostFrontendPgPool = new Pool({
      connectionString: requireEnv("DATABASE_URL"),
      max: 4,
    });
  }

  return global.__ghostFrontendPgPool;
}

async function ensureAuthSchema(pool: Pool) {
  if (!global.__ghostFrontendAuthSchemaPromise) {
    global.__ghostFrontendAuthSchemaPromise = (async () => {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS operator_accounts (
          id UUID PRIMARY KEY,
          company_name TEXT NOT NULL,
          contact_name TEXT NOT NULL,
          email TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL,
          webauthn_user_id TEXT NOT NULL UNIQUE,
          otp_enabled BOOLEAN NOT NULL DEFAULT TRUE,
          created_at TIMESTAMPTZ NOT NULL,
          updated_at TIMESTAMPTZ NOT NULL,
          last_login_at TIMESTAMPTZ
        );

        CREATE INDEX IF NOT EXISTS operator_accounts_company_name_idx
        ON operator_accounts (company_name);

        CREATE TABLE IF NOT EXISTS operator_sessions (
          id UUID PRIMARY KEY,
          operator_account_id UUID NOT NULL REFERENCES operator_accounts(id) ON DELETE CASCADE,
          token_hash TEXT NOT NULL UNIQUE,
          expires_at TIMESTAMPTZ NOT NULL,
          created_at TIMESTAMPTZ NOT NULL,
          last_seen_at TIMESTAMPTZ NOT NULL
        );

        CREATE INDEX IF NOT EXISTS operator_sessions_account_idx
        ON operator_sessions (operator_account_id, expires_at DESC);

        CREATE TABLE IF NOT EXISTS operator_otp_codes (
          id UUID PRIMARY KEY,
          operator_account_id UUID NOT NULL REFERENCES operator_accounts(id) ON DELETE CASCADE,
          purpose TEXT NOT NULL,
          code_hash TEXT NOT NULL,
          expires_at TIMESTAMPTZ NOT NULL,
          consumed_at TIMESTAMPTZ,
          created_at TIMESTAMPTZ NOT NULL
        );

        CREATE INDEX IF NOT EXISTS operator_otp_codes_account_idx
        ON operator_otp_codes (operator_account_id, created_at DESC);

        CREATE TABLE IF NOT EXISTS operator_passkeys (
          id UUID PRIMARY KEY,
          operator_account_id UUID NOT NULL REFERENCES operator_accounts(id) ON DELETE CASCADE,
          credential_id TEXT NOT NULL UNIQUE,
          public_key TEXT NOT NULL,
          counter BIGINT NOT NULL,
          transports JSONB NOT NULL,
          device_type TEXT NOT NULL,
          backed_up BOOLEAN NOT NULL,
          label TEXT,
          created_at TIMESTAMPTZ NOT NULL,
          last_used_at TIMESTAMPTZ
        );

        CREATE INDEX IF NOT EXISTS operator_passkeys_account_idx
        ON operator_passkeys (operator_account_id, created_at DESC);

        CREATE TABLE IF NOT EXISTS operator_protocols (
          id UUID PRIMARY KEY,
          operator_account_id UUID NOT NULL REFERENCES operator_accounts(id) ON DELETE CASCADE,
          protocol_key TEXT NOT NULL,
          name TEXT NOT NULL,
          chain_id BIGINT NOT NULL,
          protocol_type TEXT,
          monitoring_authorized BOOLEAN NOT NULL DEFAULT TRUE,
          monitored_addresses JSONB NOT NULL DEFAULT '[]'::jsonb,
          contract_addresses JSONB NOT NULL DEFAULT '[]'::jsonb,
          security_contacts JSONB NOT NULL DEFAULT '[]'::jsonb,
          oracle_addresses JSONB NOT NULL DEFAULT '[]'::jsonb,
          dependencies JSONB NOT NULL DEFAULT '[]'::jsonb,
          upgrade_proxy_addresses JSONB NOT NULL DEFAULT '[]'::jsonb,
          upgrade_timelock_addresses JSONB NOT NULL DEFAULT '[]'::jsonb,
          billing_tier TEXT,
          created_at TIMESTAMPTZ NOT NULL,
          updated_at TIMESTAMPTZ NOT NULL,
          UNIQUE(operator_account_id, protocol_key)
        );

        CREATE INDEX IF NOT EXISTS operator_protocols_account_idx
        ON operator_protocols (operator_account_id, updated_at DESC);
      `);
    })().catch((error) => {
      global.__ghostFrontendAuthSchemaPromise = undefined;
      throw error;
    });
  }

  await global.__ghostFrontendAuthSchemaPromise;
}

export async function getPool() {
  const pool = buildPool();
  await ensureAuthSchema(pool);
  return pool;
}
