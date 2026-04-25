import crypto from "crypto";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { getPool } from "@/lib/server/db";

export type OperatorAccount = {
  id: string;
  company_name: string;
  contact_name: string;
  email: string;
  password_hash: string;
  webauthn_user_id: string;
  otp_enabled: boolean;
  created_at: string;
  updated_at: string;
  last_login_at: string | null;
};

export type OperatorPasskey = {
  id: string;
  operator_account_id: string;
  credential_id: string;
  public_key: string;
  counter: number;
  transports: string[];
  device_type: string;
  backed_up: boolean;
  label: string | null;
  created_at: string;
  last_used_at: string | null;
};

const SESSION_COOKIE_NAME = "ghost_session";
const SESSION_DURATION_MS = 1000 * 60 * 60 * 24 * 14;

type SessionOptions = {
  durationMs?: number;
};

export async function findAccountByEmail(email: string) {
  const pool = await getPool();
  const { rows } = await pool.query<OperatorAccount>(
    `SELECT *
     FROM operator_accounts
     WHERE email = $1`,
    [email.trim().toLowerCase()],
  );

  return rows[0] ?? null;
}

export async function findAccountById(accountId: string) {
  const pool = await getPool();
  const { rows } = await pool.query<OperatorAccount>(
    `SELECT *
     FROM operator_accounts
     WHERE id = $1`,
    [accountId],
  );

  return rows[0] ?? null;
}

export async function createOperatorAccount(input: {
  companyName: string;
  contactName: string;
  email: string;
  passwordHash: string;
}) {
  const pool = await getPool();
  const now = new Date().toISOString();
  const id = crypto.randomUUID();
  const webauthnUserId = crypto.randomUUID();

  const { rows } = await pool.query<OperatorAccount>(
    `INSERT INTO operator_accounts (
       id,
       company_name,
       contact_name,
       email,
       password_hash,
       webauthn_user_id,
       otp_enabled,
       created_at,
       updated_at
     ) VALUES ($1,$2,$3,$4,$5,$6,TRUE,$7,$7)
     RETURNING *`,
    [
      id,
      input.companyName.trim(),
      input.contactName.trim(),
      input.email.trim().toLowerCase(),
      input.passwordHash,
      webauthnUserId,
      now,
    ],
  );

  return rows[0];
}

export async function createSession(accountId: string, options: SessionOptions = {}) {
  const pool = await getPool();
  const rawToken = crypto.randomBytes(32).toString("hex");
  const tokenHash = hashToken(rawToken);
  const now = new Date();
  const expiresAt = new Date(
    now.getTime() + (options.durationMs ?? SESSION_DURATION_MS),
  );

  await pool.query(
    `INSERT INTO operator_sessions (
       id,
       operator_account_id,
       token_hash,
       expires_at,
       created_at,
       last_seen_at
     ) VALUES ($1,$2,$3,$4,$5,$5)`,
    [crypto.randomUUID(), accountId, tokenHash, expiresAt.toISOString(), now.toISOString()],
  );

  await pool.query(
    `UPDATE operator_accounts
     SET last_login_at = $2, updated_at = $2
     WHERE id = $1`,
    [accountId, now.toISOString()],
  );

  cookies().set(SESSION_COOKIE_NAME, rawToken, {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    expires: expiresAt,
    priority: "high",
  });
}

export async function clearSession() {
  const token = cookies().get(SESSION_COOKIE_NAME)?.value;
  if (token) {
    const pool = await getPool();
    await pool.query(`DELETE FROM operator_sessions WHERE token_hash = $1`, [
      hashToken(token),
    ]);
  }

  cookies().delete(SESSION_COOKIE_NAME);
}

export async function getOptionalSessionAccount() {
  const token = cookies().get(SESSION_COOKIE_NAME)?.value;
  if (!token) {
    return null;
  }

  const tokenHash = hashToken(token);
  const pool = await getPool();
  const { rows } = await pool.query<OperatorAccount>(
    `SELECT a.*
     FROM operator_sessions s
     JOIN operator_accounts a ON a.id = s.operator_account_id
     WHERE s.token_hash = $1
       AND s.expires_at > NOW()
     LIMIT 1`,
    [tokenHash],
  );

  const account = rows[0] ?? null;
  if (!account) {
    return null;
  }

  await pool.query(
    `UPDATE operator_sessions
     SET last_seen_at = NOW()
     WHERE token_hash = $1`,
    [tokenHash],
  );

  return account;
}

export async function requireSessionAccount() {
  const account = await getOptionalSessionAccount();
  if (!account) {
    redirect("/sign-in?next=/account");
  }

  return account;
}

export async function listPasskeysForAccount(accountId: string) {
  const pool = await getPool();
  const { rows } = await pool.query<OperatorPasskey>(
    `SELECT
       id,
       operator_account_id,
       credential_id,
       public_key,
       counter,
       transports,
       device_type,
       backed_up,
       label,
       created_at,
       last_used_at
     FROM operator_passkeys
     WHERE operator_account_id = $1
     ORDER BY created_at DESC`,
    [accountId],
  );

  return rows.map((row: OperatorPasskey) => ({
    ...row,
    transports: Array.isArray(row.transports) ? row.transports : [],
  }));
}

export async function countPasskeysForAccount(accountId: string) {
  const pool = await getPool();
  const { rows } = await pool.query<{ count: string }>(
    `SELECT COUNT(*)::text AS count
     FROM operator_passkeys
     WHERE operator_account_id = $1`,
    [accountId],
  );

  return Number.parseInt(rows[0]?.count ?? "0", 10);
}

export async function findPasskeyByCredentialId(credentialId: string) {
  const pool = await getPool();
  const { rows } = await pool.query<OperatorPasskey>(
    `SELECT
       id,
       operator_account_id,
       credential_id,
       public_key,
       counter,
       transports,
       device_type,
       backed_up,
       label,
       created_at,
       last_used_at
     FROM operator_passkeys
     WHERE credential_id = $1
     LIMIT 1`,
    [credentialId],
  );

  const row = rows[0] ?? null;
  return row
    ? {
        ...row,
        transports: Array.isArray(row.transports) ? row.transports : [],
      }
    : null;
}

export async function storePasskey(input: {
  accountId: string;
  credentialId: string;
  publicKey: string;
  counter: number;
  transports: string[];
  deviceType: string;
  backedUp: boolean;
  label?: string | null;
}) {
  const pool = await getPool();
  await pool.query(
    `INSERT INTO operator_passkeys (
       id,
       operator_account_id,
       credential_id,
       public_key,
       counter,
       transports,
       device_type,
       backed_up,
       label,
       created_at
     ) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,NOW())`,
    [
      crypto.randomUUID(),
      input.accountId,
      input.credentialId,
      input.publicKey,
      input.counter,
      JSON.stringify(input.transports ?? []),
      input.deviceType,
      input.backedUp,
      input.label ?? null,
    ],
  );
}

export async function updatePasskeyCounter(passkeyId: string, counter: number) {
  const pool = await getPool();
  await pool.query(
    `UPDATE operator_passkeys
     SET counter = $2, last_used_at = NOW()
     WHERE id = $1`,
    [passkeyId, counter],
  );
}

function hashToken(token: string) {
  return crypto.createHash("sha256").update(token).digest("hex");
}
