import { JsonRpcProvider } from "ethers";
import { loadProtocolById, type ProtocolDefinition } from "@/lib/protocols";

export type AnalysisLogEvent = {
  type: "log";
  timestamp: string;
  level: "info" | "warn" | "success" | "error";
  message: string;
};

export type AnalysisSummaryEvent = {
  type: "summary";
  summary: {
    protocolId: string;
    protocolName: string;
    chainId: number;
    monitoredAddressCount: number;
    deployedAddressCount: number;
    dependencyCount: number;
    contactCount: number;
    coverage: string;
    latestBlock: string;
  };
};

export type AnalysisEvent = AnalysisLogEvent | AnalysisSummaryEvent;

function nowTag() {
  return new Date().toISOString().slice(11, 19);
}

function fullScanIntervalSecs() {
  const raw = Number.parseInt(process.env.FULL_SCAN_INTERVAL_SECS ?? "86400", 10);
  return Number.isFinite(raw) && raw > 0 ? raw : 86400;
}

function formatDuration(totalSeconds: number) {
  if (totalSeconds % 86400 === 0) {
    const days = totalSeconds / 86400;
    return days === 1 ? "24h" : `${days}d`;
  }

  if (totalSeconds % 3600 === 0) {
    return `${totalSeconds / 3600}h`;
  }

  if (totalSeconds % 60 === 0) {
    return `${totalSeconds / 60}m`;
  }

  return `${totalSeconds}s`;
}

function formatUtcTimestamp(date: Date) {
  return date.toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function runProtocolAnalysisForProtocol(
  protocol: ProtocolDefinition,
  onEvent: (event: AnalysisEvent) => Promise<void>,
) {
  const rpcUrl = process.env.ALCHEMY_HTTP_URL;
  if (!rpcUrl) {
    throw new Error("ALCHEMY_HTTP_URL is not configured");
  }

  const provider = new JsonRpcProvider(rpcUrl);

  await emit(onEvent, "info", `loaded protocol registry entry ${protocol.id} · ${protocol.name}`);

  const [network, latestBlock] = await Promise.all([
    provider.getNetwork(),
    provider.getBlockNumber(),
  ]);
  await emit(
    onEvent,
    Number(network.chainId) === protocol.chain_id ? "success" : "warn",
    `rpc chain ${Number(network.chainId)} · expected ${protocol.chain_id} · latest block ${latestBlock}`,
  );

  const proxyCount = protocol.upgrade_monitor?.proxy_addresses?.length ?? 0;
  const timelockCount = protocol.upgrade_monitor?.timelock_addresses?.length ?? 0;
  await emit(
    onEvent,
    proxyCount > 0 || timelockCount > 0 ? "success" : "warn",
    `upgrade watch armed ${proxyCount} proxies · ${timelockCount} timelocks`,
  );

  const monitoredAddresses = protocol.monitored_addresses ?? [];
  let deployedAddressCount = 0;
  for (const address of monitoredAddresses) {
    const code = await provider.getCode(address);
    const deployed = code !== "0x";
    if (deployed) {
      deployedAddressCount += 1;
    }

    await emit(
      onEvent,
      deployed ? "success" : "warn",
      `address ${address} ${deployed ? "has deployed bytecode" : "returned empty code"}`,
      300,
    );
  }

  const oracleCount = protocol.oracle_addresses?.length ?? 0;
  await emit(
    onEvent,
    oracleCount > 0 ? "success" : "warn",
    `oracle coverage ${oracleCount} configured price dependencies`,
  );

  const dependencyCount = protocol.dependencies?.length ?? 0;
  await emit(
    onEvent,
    dependencyCount > 0 ? "success" : "warn",
    `dependency graph loaded ${dependencyCount} linked addresses`,
  );

  const marketPaths = protocol.simulation?.market_paths?.length ?? 0;
  const flashProviders = protocol.simulation?.flash_loan_providers?.length ?? 0;
  await emit(
    onEvent,
    marketPaths > 0 || flashProviders > 0 ? "success" : "warn",
    `simulation profile ${marketPaths} market paths · ${flashProviders} flash providers`,
  );

  const coverage =
    monitoredAddresses.length > 0 &&
    deployedAddressCount === monitoredAddresses.length &&
    dependencyCount > 0
      ? "strong"
      : deployedAddressCount > 0
        ? "partial"
        : "weak";

  await emit(
    onEvent,
    coverage === "strong" ? "success" : coverage === "partial" ? "warn" : "error",
    `analysis complete · coverage ${coverage} · contacts ${protocol.security_contacts?.length ?? 0}`,
  );

  const nextScanAt = new Date(Date.now() + fullScanIntervalSecs() * 1000);
  await emit(
    onEvent,
    "info",
    `next scheduled security scan ${formatUtcTimestamp(nextScanAt)} · interval ${formatDuration(fullScanIntervalSecs())}`,
  );

  await onEvent({
    type: "summary",
    summary: {
      protocolId: protocol.id,
      protocolName: protocol.name,
      chainId: protocol.chain_id,
      monitoredAddressCount: monitoredAddresses.length,
      deployedAddressCount,
      dependencyCount,
      contactCount: protocol.security_contacts?.length ?? 0,
      coverage,
      latestBlock: latestBlock.toString(),
    },
  });
}

export async function runProtocolAnalysis(
  protocolId: string,
  onEvent: (event: AnalysisEvent) => Promise<void>,
) {
  const protocol = await loadProtocolById(protocolId);
  if (!protocol) {
    throw new Error("Protocol not found");
  }

  return runProtocolAnalysisForProtocol(protocol, onEvent);
}

async function emit(
  onEvent: (event: AnalysisEvent) => Promise<void>,
  level: AnalysisLogEvent["level"],
  message: string,
  delayMs = 450,
) {
  await onEvent({
    type: "log",
    timestamp: nowTag(),
    level,
    message,
  });

  await sleep(delayMs);
}
