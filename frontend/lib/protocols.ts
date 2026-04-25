import fs from "fs/promises";
import path from "path";

export type BillingDefinition = {
  tier?: string;
  billing_email?: string;
  active?: boolean;
};

export type ProtocolDefinition = {
  id: string;
  name: string;
  chain_id: number;
  protocol_type?: string;
  monitoring_authorized?: boolean;
  monitored_addresses?: string[];
  contract_addresses?: string[];
  security_contacts?: string[];
  oracle_addresses?: string[];
  dependencies?: Array<{
    name: string;
    address: string;
    kind: string;
    critical?: boolean;
  }>;
  upgrade_monitor?: {
    proxy_addresses?: string[];
    timelock_addresses?: string[];
  };
  billing?: BillingDefinition;
  simulation?: {
    token_whales?: Array<{ token: string; holder: string; decimals?: number }>;
    routers?: Array<{
      kind: string;
      address: string;
      quoter?: string;
      wrapped_native?: string;
      factory?: string;
    }>;
    flash_loan_providers?: Array<{
      kind: string;
      address: string;
      asset: string;
      liquidity_holder?: string;
    }>;
    market_paths?: Array<{
      label: string;
      router_kind: string;
      token_in: string;
      token_out: string;
      amount_in?: string;
      fee_tiers?: number[];
      stable_hops?: boolean[];
    }>;
  };
  invariants?: Array<{ name: string; severity?: string; kind?: string }>;
};

const defaultProtocolFiles = [
  "protocols.base-sepolia.example.json",
  "protocols.example.json",
];

async function readProtocolFile(fileName: string): Promise<ProtocolDefinition[]> {
  const candidatePaths = path.isAbsolute(fileName)
    ? [fileName]
    : [
        path.join(process.cwd(), fileName),
        path.join(path.resolve(process.cwd(), ".."), fileName),
      ];

  for (const candidatePath of candidatePaths) {
    try {
      const raw = await fs.readFile(candidatePath, "utf8");
      return JSON.parse(raw) as ProtocolDefinition[];
    } catch {
      // Try the next location.
    }
  }

  return [];
}

export async function loadProtocolsFromFiles(
  fileNames: string[] = defaultProtocolFiles,
): Promise<ProtocolDefinition[]> {
  const protocols = await Promise.all(
    fileNames.map((fileName) => readProtocolFile(fileName)),
  );

  return protocols.flat();
}

export async function loadActiveProtocols(): Promise<ProtocolDefinition[]> {
  const fileName =
    process.env.PROTOCOLS_FILE || "protocols.base-sepolia.example.json";
  return loadProtocolsFromFiles([fileName]);
}

export async function loadProtocolById(
  protocolId: string,
): Promise<ProtocolDefinition | null> {
  const protocols = await loadProtocolsFromFiles();
  return protocols.find((protocol) => protocol.id === protocolId) ?? null;
}
