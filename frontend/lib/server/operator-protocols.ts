import crypto from "crypto";
import type { ProtocolDefinition } from "@/lib/protocols";
import { getPool } from "@/lib/server/db";

type OperatorProtocolRow = {
  id: string;
  operator_account_id: string;
  protocol_key: string;
  name: string;
  chain_id: string | number;
  protocol_type: string | null;
  monitoring_authorized: boolean;
  monitored_addresses: unknown;
  contract_addresses: unknown;
  security_contacts: unknown;
  oracle_addresses: unknown;
  dependencies: unknown;
  upgrade_proxy_addresses: unknown;
  upgrade_timelock_addresses: unknown;
  billing_tier: string | null;
  created_at: string;
  updated_at: string;
};

export type OperatorProtocolInput = {
  name: string;
  protocolKey: string;
  chainId: number;
  tier?: string | null;
  protocolType?: string | null;
  monitoredAddresses: string[];
  securityContacts: string[];
  oracleAddresses?: string[];
  proxyAddresses?: string[];
  timelockAddresses?: string[];
};

const ADDRESS_PATTERN = /^0x[a-fA-F0-9]{40}$/;
const PROTOCOL_KEY_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

function normalizeStringArray(value: unknown) {
  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .map((entry) => (typeof entry === "string" ? entry.trim() : ""))
    .filter(Boolean);
}

function normalizeEmailArray(value: unknown) {
  return normalizeStringArray(value).map((entry) => entry.toLowerCase());
}

function normalizeDependencyArray(value: unknown) {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter(
    (entry): entry is { name: string; address: string; kind: string; critical?: boolean } =>
      Boolean(
        entry &&
          typeof entry === "object" &&
          typeof (entry as { name?: unknown }).name === "string" &&
          typeof (entry as { address?: unknown }).address === "string" &&
          typeof (entry as { kind?: unknown }).kind === "string",
      ),
  );
}

function rowToProtocol(row: OperatorProtocolRow): ProtocolDefinition {
  const monitoredAddresses = normalizeStringArray(row.monitored_addresses);
  const contractAddresses = normalizeStringArray(row.contract_addresses);
  const securityContacts = normalizeEmailArray(row.security_contacts);
  const oracleAddresses = normalizeStringArray(row.oracle_addresses);
  const proxyAddresses = normalizeStringArray(row.upgrade_proxy_addresses);
  const timelockAddresses = normalizeStringArray(row.upgrade_timelock_addresses);
  const dependencies = normalizeDependencyArray(row.dependencies);

  return {
    id: row.protocol_key,
    name: row.name,
    chain_id: Number(row.chain_id),
    protocol_type: row.protocol_type ?? undefined,
    monitoring_authorized: row.monitoring_authorized,
    monitored_addresses: monitoredAddresses,
    contract_addresses: contractAddresses.length ? contractAddresses : monitoredAddresses,
    security_contacts: securityContacts,
    oracle_addresses: oracleAddresses,
    dependencies,
    upgrade_monitor:
      proxyAddresses.length || timelockAddresses.length
        ? {
            proxy_addresses: proxyAddresses,
            timelock_addresses: timelockAddresses,
          }
        : undefined,
    billing: row.billing_tier
      ? {
          tier: row.billing_tier,
          active: true,
        }
      : undefined,
  };
}

function dedupe(values: string[]) {
  return [...new Set(values)];
}

function normalizeAddresses(values: string[]) {
  return dedupe(
    values
      .map((value) => value.trim())
      .filter(Boolean)
      .map((value) => value.toLowerCase()),
  );
}

function normalizeEmails(values: string[]) {
  return dedupe(
    values
      .map((value) => value.trim().toLowerCase())
      .filter(Boolean),
  );
}

export function validateOperatorProtocolInput(input: OperatorProtocolInput) {
  const name = input.name.trim();
  if (!name) {
    return "Protocol name is required.";
  }

  const protocolKey = input.protocolKey.trim().toLowerCase();
  if (!protocolKey) {
    return "Protocol key is required.";
  }

  if (!PROTOCOL_KEY_PATTERN.test(protocolKey)) {
    return "Protocol key must use lowercase letters, numbers, and hyphens only.";
  }

  if (!Number.isInteger(input.chainId) || input.chainId <= 0) {
    return "Chain ID must be a positive integer.";
  }

  const monitoredAddresses = normalizeAddresses(input.monitoredAddresses);
  if (!monitoredAddresses.length) {
    return "At least one watched address is required.";
  }

  if (monitoredAddresses.some((address) => !ADDRESS_PATTERN.test(address))) {
    return "Watched addresses must be valid 0x addresses.";
  }

  const securityContacts = normalizeEmails(input.securityContacts);
  if (!securityContacts.length) {
    return "At least one report email is required.";
  }

  if (securityContacts.some((email) => !email.includes("@"))) {
    return "Report emails must be valid email addresses.";
  }

  const oracleAddresses = normalizeAddresses(input.oracleAddresses ?? []);
  if (oracleAddresses.some((address) => !ADDRESS_PATTERN.test(address))) {
    return "Oracle addresses must be valid 0x addresses.";
  }

  const proxyAddresses = normalizeAddresses(input.proxyAddresses ?? []);
  if (proxyAddresses.some((address) => !ADDRESS_PATTERN.test(address))) {
    return "Proxy addresses must be valid 0x addresses.";
  }

  const timelockAddresses = normalizeAddresses(input.timelockAddresses ?? []);
  if (timelockAddresses.some((address) => !ADDRESS_PATTERN.test(address))) {
    return "Timelock addresses must be valid 0x addresses.";
  }

  return null;
}

function serializedInput(input: OperatorProtocolInput) {
  return {
    name: input.name.trim(),
    protocolKey: input.protocolKey.trim().toLowerCase(),
    chainId: input.chainId,
    protocolType: input.protocolType?.trim() || null,
    tier: input.tier?.trim() || null,
    monitoredAddresses: normalizeAddresses(input.monitoredAddresses),
    securityContacts: normalizeEmails(input.securityContacts),
    oracleAddresses: normalizeAddresses(input.oracleAddresses ?? []),
    proxyAddresses: normalizeAddresses(input.proxyAddresses ?? []),
    timelockAddresses: normalizeAddresses(input.timelockAddresses ?? []),
  };
}

export async function listOperatorProtocols(accountId: string) {
  const pool = await getPool();
  const { rows } = await pool.query<OperatorProtocolRow>(
    `SELECT *
     FROM operator_protocols
     WHERE operator_account_id = $1
     ORDER BY updated_at DESC, created_at DESC`,
    [accountId],
  );

  return rows.map(rowToProtocol);
}

export async function getOperatorProtocolByKey(
  accountId: string,
  protocolKey: string,
) {
  const pool = await getPool();
  const { rows } = await pool.query<OperatorProtocolRow>(
    `SELECT *
     FROM operator_protocols
     WHERE operator_account_id = $1
       AND protocol_key = $2
     LIMIT 1`,
    [accountId, protocolKey.trim().toLowerCase()],
  );

  return rows[0] ? rowToProtocol(rows[0]) : null;
}

export async function createOperatorProtocol(
  accountId: string,
  input: OperatorProtocolInput,
) {
  const pool = await getPool();
  const normalized = serializedInput(input);
  const now = new Date().toISOString();

  const { rows } = await pool.query<OperatorProtocolRow>(
    `INSERT INTO operator_protocols (
       id,
       operator_account_id,
       protocol_key,
       name,
       chain_id,
       protocol_type,
       monitored_addresses,
       contract_addresses,
       security_contacts,
       oracle_addresses,
       dependencies,
       upgrade_proxy_addresses,
       upgrade_timelock_addresses,
       billing_tier,
       created_at,
       updated_at
     ) VALUES (
       $1,$2,$3,$4,$5,$6,
       $7::jsonb,$7::jsonb,$8::jsonb,$9::jsonb,'[]'::jsonb,$10::jsonb,$11::jsonb,$12,$13,$13
     )
     RETURNING *`,
    [
      crypto.randomUUID(),
      accountId,
      normalized.protocolKey,
      normalized.name,
      normalized.chainId,
      normalized.protocolType,
      JSON.stringify(normalized.monitoredAddresses),
      JSON.stringify(normalized.securityContacts),
      JSON.stringify(normalized.oracleAddresses),
      JSON.stringify(normalized.proxyAddresses),
      JSON.stringify(normalized.timelockAddresses),
      normalized.tier,
      now,
    ],
  );

  return rowToProtocol(rows[0]);
}

export async function updateOperatorProtocol(
  accountId: string,
  protocolKey: string,
  input: OperatorProtocolInput,
) {
  const pool = await getPool();
  const normalized = serializedInput(input);
  const { rows } = await pool.query<OperatorProtocolRow>(
    `UPDATE operator_protocols
     SET protocol_key = $3,
         name = $4,
         chain_id = $5,
         protocol_type = $6,
         monitored_addresses = $7::jsonb,
         contract_addresses = $7::jsonb,
         security_contacts = $8::jsonb,
         oracle_addresses = $9::jsonb,
         upgrade_proxy_addresses = $10::jsonb,
         upgrade_timelock_addresses = $11::jsonb,
         billing_tier = $12,
         updated_at = NOW()
     WHERE operator_account_id = $1
       AND protocol_key = $2
     RETURNING *`,
    [
      accountId,
      protocolKey.trim().toLowerCase(),
      normalized.protocolKey,
      normalized.name,
      normalized.chainId,
      normalized.protocolType,
      JSON.stringify(normalized.monitoredAddresses),
      JSON.stringify(normalized.securityContacts),
      JSON.stringify(normalized.oracleAddresses),
      JSON.stringify(normalized.proxyAddresses),
      JSON.stringify(normalized.timelockAddresses),
      normalized.tier,
    ],
  );

  return rows[0] ? rowToProtocol(rows[0]) : null;
}

export async function deleteOperatorProtocol(
  accountId: string,
  protocolKey: string,
) {
  const pool = await getPool();
  const { rowCount } = await pool.query(
    `DELETE FROM operator_protocols
     WHERE operator_account_id = $1
       AND protocol_key = $2`,
    [accountId, protocolKey.trim().toLowerCase()],
  );

  return (rowCount ?? 0) > 0;
}
