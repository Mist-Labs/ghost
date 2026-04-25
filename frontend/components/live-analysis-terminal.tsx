"use client";

import { useEffect, useMemo, useState } from "react";
import { consumeNdjsonStream } from "@/lib/ndjson";
import type { ProtocolDefinition } from "@/lib/protocols";
import { truncateAddress } from "@/lib/utils";

type AnalysisLog = {
  type: "log";
  timestamp: string;
  level: "info" | "warn" | "success" | "error";
  message: string;
};

type AnalysisSummary = {
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

type AnalysisError = {
  type: "error";
  message: string;
};

type StreamEvent = AnalysisLog | AnalysisSummary | AnalysisError;

function levelColor(level: string) {
  switch (level) {
    case "success":
      return "text-signal";
    case "warn":
      return "text-amber-300";
    case "error":
      return "text-rose-400";
    default:
      return "text-cyan-300";
  }
}

export function LiveAnalysisTerminal({
  protocols,
  fallbackProtocols = [],
}: {
  protocols: ProtocolDefinition[];
  fallbackProtocols?: ProtocolDefinition[];
}) {
  const availableProtocols = useMemo(() => {
    const seen = new Set<string>();
    return [...protocols, ...fallbackProtocols].filter((protocol) => {
      if (seen.has(protocol.id)) {
        return false;
      }

      seen.add(protocol.id);
      return true;
    });
  }, [fallbackProtocols, protocols]);

  const [selectedProtocolId, setSelectedProtocolId] = useState(
    protocols[0]?.id ?? fallbackProtocols[0]?.id ?? "",
  );
  const [logs, setLogs] = useState<AnalysisLog[]>([]);
  const [summary, setSummary] = useState<AnalysisSummary["summary"] | null>(null);
  const [isOpen, setIsOpen] = useState(false);
  const [isPending, setIsPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const selectedProtocol = useMemo(
    () =>
      availableProtocols.find((protocol) => protocol.id === selectedProtocolId) ??
      null,
    [availableProtocols, selectedProtocolId],
  );

  const selectedProtocolIsFallback = useMemo(
    () =>
      fallbackProtocols.some((protocol) => protocol.id === selectedProtocolId) &&
      !protocols.some((protocol) => protocol.id === selectedProtocolId),
    [fallbackProtocols, protocols, selectedProtocolId],
  );

  useEffect(() => {
    if (!availableProtocols.length) {
      setSelectedProtocolId("");
      return;
    }

    if (!availableProtocols.some((protocol) => protocol.id === selectedProtocolId)) {
      setSelectedProtocolId(protocols[0]?.id ?? fallbackProtocols[0]?.id ?? "");
    }
  }, [availableProtocols, fallbackProtocols, protocols, selectedProtocolId]);

  async function runAnalysis() {
    if (!selectedProtocolId) {
      return;
    }

    setIsOpen(true);
    setIsPending(true);
    setError(null);
    setLogs([]);
    setSummary(null);

    try {
      const response = await fetch("/api/live-analysis", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ protocolId: selectedProtocolId }),
      });

      if (!response.ok) {
        const payload = await response.json().catch(() => null);
        throw new Error(payload?.error || "Analysis request failed");
      }

      await consumeNdjsonStream(response, (payload) => {
        const event = payload as StreamEvent;
        if (event.type === "log") {
          setLogs((current) => [...current, event]);
          return;
        }
        if (event.type === "summary") {
          setSummary(event.summary);
          return;
        }
        if (event.type === "error") {
          setError(event.message);
        }
      });
    } catch (analysisError) {
      setError(
        analysisError instanceof Error
          ? analysisError.message
          : "Analysis request failed",
      );
    } finally {
      setIsPending(false);
    }
  }

  return (
    <div className="grid gap-6 xl:grid-cols-[360px_minmax(0,1fr)]">
      <div className="panel p-6">
        <div className="mb-5">
          <p className="micro-label">Account Console</p>
          <h2 className="mt-3 font-display text-3xl font-semibold tracking-[-0.035em]">
            Run live protocol analysis
          </h2>
          <p className="mt-3 text-sm leading-7 text-text-2">
            This console inspects the currently registered protocol over the
            active RPC, verifies deployment coverage, and reports monitor
            readiness against real chain state.
          </p>
        </div>

        <label className="micro-label">Selected protocol</label>
        <select
          value={selectedProtocolId}
          onChange={(event) => setSelectedProtocolId(event.target.value)}
          disabled={!availableProtocols.length}
          className="mt-2 w-full rounded-xl border border-white/10 bg-raised px-4 py-3 text-sm text-text-1 outline-none transition focus:border-signal/50"
        >
          {availableProtocols.length ? (
            <>
              {protocols.length ? (
                <optgroup label="Account protocols">
                  {protocols.map((protocol) => (
                    <option key={protocol.id} value={protocol.id}>
                      {protocol.name}
                    </option>
                  ))}
                </optgroup>
              ) : null}
              {fallbackProtocols.length ? (
                <optgroup label="Demo protocols">
                  {fallbackProtocols.map((protocol) => (
                    <option key={protocol.id} value={protocol.id}>
                      {protocol.name}
                    </option>
                  ))}
                </optgroup>
              ) : null}
            </>
          ) : (
            <option value="">No protocols registered</option>
          )}
        </select>

        {selectedProtocol ? (
          <div className="mt-5 space-y-4">
            <div className="grid grid-cols-2 gap-2">
              <div className="product-card p-3">
                <p className="micro-label">Tier</p>
                <p className="mt-1.5 text-sm font-medium leading-6 text-text-1">
                  {selectedProtocol.billing?.tier ?? "unassigned"}
                </p>
              </div>
              <div className="product-card p-3">
                <p className="micro-label">
                  {selectedProtocolIsFallback ? "Profile source" : "Report emails"}
                </p>
                <p className="mt-1.5 text-sm font-medium leading-6 text-text-1">
                  {selectedProtocolIsFallback
                    ? "Shared demo registry"
                    : selectedProtocol.security_contacts?.length ?? 0}
                </p>
              </div>
            </div>

            <div className="product-card space-y-3 p-4">
              <p className="micro-label">Watched addresses</p>
              <div className="space-y-2 font-mono text-xs text-text-2">
                {(selectedProtocol.monitored_addresses ?? []).map((address) => (
                  <div
                    key={address}
                    className="flex items-center justify-between gap-3 rounded-lg border border-white/5 bg-black/30 px-3 py-2"
                  >
                    <span>{truncateAddress(address)}</span>
                    <span className="text-[10px] uppercase tracking-[0.16em] text-text-3">
                      watched
                    </span>
                  </div>
                ))}
              </div>
            </div>

            <button
              onClick={runAnalysis}
              disabled={isPending || !selectedProtocolId}
              className="inline-flex w-full items-center justify-center rounded-xl bg-signal px-4 py-3 font-display text-sm font-semibold uppercase tracking-[0.12em] text-black shadow-signal transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-70"
            >
              {isPending ? "Running analysis..." : "Run analysis in terminal"}
            </button>
          </div>
        ) : null}
      </div>

      <div className="terminal-shell min-h-[620px]">
        <div className="terminal-bar">
          <div className="flex items-center gap-2">
            <span className="terminal-dot bg-[#ff5f57]" />
            <span className="terminal-dot bg-[#febc2e]" />
            <span className="terminal-dot bg-[#28c840]" />
          </div>
          <div className="flex-1 text-center font-mono text-[11px] tracking-[0.08em] text-white/35">
            integrated live analysis console
          </div>
          <div className="font-mono text-[10px] uppercase tracking-[0.16em] text-signal">
            {isPending ? "analyzing" : isOpen ? "ready" : "idle"}
          </div>
        </div>

        <div className="relative min-h-[576px] overflow-hidden bg-black px-5 py-5 font-mono text-[12px] leading-7 md:px-6">
          <div className="scan-overlay pointer-events-none absolute inset-0" />

          <div className="relative z-10 space-y-2">
            {!isOpen ? (
              <>
                <div className="text-text-3">
                  $ ghost analyze --protocol {selectedProtocol?.id ?? "<none>"}
                </div>
                <div className="text-text-3">
                  {availableProtocols.length
                    ? "Waiting for operator command. Select a protocol and run live analysis."
                    : "Register a protocol above to unlock live analysis from this account."}
                </div>
              </>
            ) : null}

            {error ? <div className="text-rose-400">{error}</div> : null}

            {logs.length ? (
              <>
                <div className="text-text-3">
                  $ ghost analyze --protocol {selectedProtocol?.id}
                </div>
                {logs.map((log) => (
                  <div key={`${log.timestamp}-${log.message}`} className="flex gap-3">
                    <span className="w-16 shrink-0 text-[10px] text-text-3">
                      {log.timestamp}
                    </span>
                    <span className={levelColor(log.level)}>{log.message}</span>
                  </div>
                ))}
              </>
            ) : null}

            {summary ? (
              <div className="mt-6 rounded-xl border border-signal/20 bg-signal/[0.07] p-4">
                <div className="flex flex-wrap gap-6 text-[11px] uppercase tracking-[0.18em] text-text-3">
                  <span>coverage {summary.coverage}</span>
                  <span>addresses {summary.deployedAddressCount}/{summary.monitoredAddressCount}</span>
                  <span>dependencies {summary.dependencyCount}</span>
                  <span>latest block {summary.latestBlock}</span>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      </div>
    </div>
  );
}
