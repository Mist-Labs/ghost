import crypto from "crypto";
import nodemailer from "nodemailer";
import { getPool } from "@/lib/server/db";

const OTP_DURATION_MS = 1000 * 60 * 15;
const DEV_OTP_SECRET = crypto.randomBytes(32).toString("hex");

function getOtpSecret() {
  return process.env.SESSION_SECRET || process.env.GHOST_API_KEY || DEV_OTP_SECRET;
}

function getTransport() {
  const host = process.env.SMTP_SERVER;
  const port = Number(process.env.SMTP_PORT || "587");
  const user = process.env.SMTP_USERNAME;
  const pass = process.env.SMTP_PASSWORD;

  if (!host || !user || !pass) {
    throw new Error("SMTP configuration is incomplete for OTP delivery");
  }

  return nodemailer.createTransport({
    host,
    port,
    secure: port === 465,
    auth: {
      user,
      pass,
    },
  });
}

export async function issueLoginOtp(account: {
  id: string;
  email: string;
  company_name: string;
  contact_name: string;
}) {
  const pool = await getPool();
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = new Date(Date.now() + OTP_DURATION_MS).toISOString();
  const codeHash = hashOtp(account.id, code);

  await pool.query(
    `DELETE FROM operator_otp_codes
     WHERE purpose = 'login'
       AND (consumed_at IS NOT NULL OR expires_at <= NOW())`,
  );

  await pool.query(
    `DELETE FROM operator_otp_codes
     WHERE operator_account_id = $1
       AND purpose = 'login'
       AND consumed_at IS NULL`,
    [account.id],
  );

  await pool.query(
    `INSERT INTO operator_otp_codes (
       id,
       operator_account_id,
       purpose,
       code_hash,
       expires_at,
       created_at
     ) VALUES ($1,$2,'login',$3,$4,NOW())`,
    [crypto.randomUUID(), account.id, codeHash, expiresAt],
  );

  const transport = getTransport();
  const from = process.env.FROM_EMAIL || process.env.SMTP_USERNAME;

  await transport.sendMail({
    from,
    to: account.email,
    subject: "Your Ghost sign-in code",
    text: [
      `Hello ${account.contact_name},`,
      "",
      `Your Ghost sign-in code for ${account.company_name} is ${code}.`,
      "It expires in 15 minutes.",
      "",
      "If you did not request this code, you can ignore this email.",
    ].join("\n"),
  });
}

export async function consumeLoginOtp(accountId: string, code: string) {
  const pool = await getPool();
  const codeHash = hashOtp(accountId, code);

  await pool.query(
    `DELETE FROM operator_otp_codes
     WHERE purpose = 'login'
       AND consumed_at IS NULL
       AND expires_at <= NOW()`,
  );

  const { rows } = await pool.query<{ id: string }>(
    `SELECT id
     FROM operator_otp_codes
     WHERE operator_account_id = $1
       AND purpose = 'login'
       AND code_hash = $2
       AND consumed_at IS NULL
       AND expires_at > NOW()
     ORDER BY created_at DESC
     LIMIT 1`,
    [accountId, codeHash],
  );

  const record = rows[0] ?? null;
  if (!record) {
    return false;
  }

  await pool.query(
    `UPDATE operator_otp_codes
     SET consumed_at = NOW()
     WHERE id = $1`,
    [record.id],
  );

  return true;
}

function hashOtp(accountId: string, code: string) {
  return crypto
    .createHash("sha256")
    .update(`${getOtpSecret()}:${accountId}:${code}`)
    .digest("hex");
}
