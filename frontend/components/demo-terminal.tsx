"use client";

import { useState } from "react";
import { consumeNdjsonStream } from "@/lib/ndjson";

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

const toneMap: Record<string, string> = {
  info: "text-cyan-300",
  warn: "text-amber-300",
  error: "text-rose-400",
  success: "text-signal",
};

export function DemoTerminal({
  protocolId,
  protocolName,
}: {
  protocolId?: string;
  protocolName?: string;
}) {
  const [logs, setLogs] = useState<AnalysisLog[]>([]);
  const [summary, setSummary] = useState<AnalysisSummary["summary"] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isRunning, setIsRunning] = useState(false);

  async function runDemo() {
    setLogs([]);
    setSummary(null);
    setError(null);
    setIsRunning(true);

    try {
      const response = await fetch("/api/demo-analysis", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ protocolId }),
      });

      if (!response.ok) {
        const payload = await response.json().catch(() => null);
        throw new Error(payload?.error || "Unable to run demo.");
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
    } catch (demoError) {
      setError(
        demoError instanceof Error ? demoError.message : "Unable to run demo.",
      );
    } finally {
      setIsRunning(false);
    }
  }

  return (
    <div className="terminal-shell relative">
      <div className="terminal-bar">
        <div className="flex items-center gap-2">
          <span className="terminal-dot bg-[#ff5f57]" />
          <span className="terminal-dot bg-[#febc2e]" />
          <span className="terminal-dot bg-[#28c840]" />
        </div>
        <div className="flex-1 text-center font-mono text-[11px] tracking-[0.08em] text-white/35">
          ghost demo terminal · preset protocol test set
        </div>
        <button
          onClick={runDemo}
          disabled={isRunning || !protocolId}
          className="rounded-full border border-signal/25 bg-signal/[0.08] px-4 py-1.5 font-mono text-[10px] uppercase tracking-[0.16em] text-signal transition hover:border-signal/45 disabled:cursor-not-allowed disabled:opacity-70"
        >
          {isRunning ? "Running..." : "Run demo"}
        </button>
      </div>
      <div className="relative overflow-hidden bg-black px-5 py-5 font-mono text-[12px] leading-7 md:px-6">
        <div className="scan-overlay pointer-events-none absolute inset-0" />
        <div className="pointer-events-none absolute inset-x-0 top-0 h-32 animate-scan bg-[linear-gradient(180deg,rgba(0,230,118,0.08),transparent)]" />

        <div className="relative z-10 space-y-4">
          <div className="rounded-2xl border border-white/10 bg-white/[0.02] px-4 py-3">
            <div className="micro-label">Preset protocol</div>
            <div className="mt-2 text-sm text-text-1">
              {protocolName ?? "No demo protocol configured"}
            </div>
            <div className="mt-1 text-xs text-text-3">{protocolId ?? "unavailable"}</div>
          </div>

          <div className="text-text-3">
            $ ghost demo --protocol {protocolId ?? "<none>"} --mode proactive-scan
          </div>

          {!logs.length && !isRunning && !error ? (
            <div className="text-text-3">
              Click <span className="text-text-1">Run demo</span> to execute the
              preset protocol checks in real time.
            </div>
          ) : null}

          {logs.map((entry) => (
            <div key={`${entry.timestamp}-${entry.message}`} className="flex gap-3">
              <span className="w-16 shrink-0 text-[10px] text-text-3">
                {entry.timestamp}
              </span>
              <span className={toneMap[entry.level]}>{entry.message}</span>
            </div>
          ))}

          {error ? <div className="text-rose-400">{error}</div> : null}

          {summary ? (
            <div className="rounded-2xl border border-signal/20 bg-signal/[0.06] px-4 py-3">
              <div className="flex flex-wrap gap-4 text-[11px] uppercase tracking-[0.16em] text-text-3">
                <span>coverage {summary.coverage}</span>
                <span>addresses {summary.deployedAddressCount}/{summary.monitoredAddressCount}</span>
                <span>dependencies {summary.dependencyCount}</span>
                <span>block {summary.latestBlock}</span>
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
