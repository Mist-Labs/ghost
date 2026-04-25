"use client";

import { useState } from "react";
import { LiveAnalysisTerminal } from "@/components/live-analysis-terminal";
import { ProtocolAccountTable } from "@/components/protocol-account-table";
import type { ProtocolDefinition } from "@/lib/protocols";

type ProtocolFormState = {
  name: string;
  protocolKey: string;
  chainId: string;
  tier: string;
  monitoredAddresses: string;
  securityContacts: string;
  oracleAddresses: string;
  proxyAddresses: string;
  timelockAddresses: string;
};

const emptyForm = (defaultChainId: number): ProtocolFormState => ({
  name: "",
  protocolKey: "",
  chainId: String(defaultChainId),
  tier: "",
  monitoredAddresses: "",
  securityContacts: "",
  oracleAddresses: "",
  proxyAddresses: "",
  timelockAddresses: "",
});

function listToText(values: string[] | undefined) {
  return (values ?? []).join("\n");
}

function splitEntries(value: string) {
  return value
    .split(/[\n,]/g)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function protocolToForm(protocol: ProtocolDefinition): ProtocolFormState {
  return {
    name: protocol.name,
    protocolKey: protocol.id,
    chainId: String(protocol.chain_id),
    tier: protocol.billing?.tier ?? "",
    monitoredAddresses: listToText(protocol.monitored_addresses),
    securityContacts: listToText(protocol.security_contacts),
    oracleAddresses: listToText(protocol.oracle_addresses),
    proxyAddresses: listToText(protocol.upgrade_monitor?.proxy_addresses),
    timelockAddresses: listToText(protocol.upgrade_monitor?.timelock_addresses),
  };
}

function buildPayload(form: ProtocolFormState) {
  return {
    name: form.name.trim(),
    protocolKey: form.protocolKey.trim().toLowerCase(),
    chainId: Number.parseInt(form.chainId, 10),
    tier: form.tier || null,
    monitoredAddresses: splitEntries(form.monitoredAddresses),
    securityContacts: splitEntries(form.securityContacts),
    oracleAddresses: splitEntries(form.oracleAddresses),
    proxyAddresses: splitEntries(form.proxyAddresses),
    timelockAddresses: splitEntries(form.timelockAddresses),
  };
}

export function OperatorProtocolWorkspace({
  initialProtocols,
  fallbackProtocols = [],
  defaultChainId,
}: {
  initialProtocols: ProtocolDefinition[];
  fallbackProtocols?: ProtocolDefinition[];
  defaultChainId: number;
}) {
  const [protocols, setProtocols] = useState(initialProtocols);
  const [form, setForm] = useState<ProtocolFormState>(emptyForm(defaultChainId));
  const [editingProtocolKey, setEditingProtocolKey] = useState<string | null>(null);
  const [editorOpen, setEditorOpen] = useState(initialProtocols.length === 0);
  const [isSaving, setIsSaving] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  function updateField<K extends keyof ProtocolFormState>(
    key: K,
    value: ProtocolFormState[K],
  ) {
    setForm((current) => ({ ...current, [key]: value }));
  }

  function resetForm() {
    setForm(emptyForm(defaultChainId));
    setEditingProtocolKey(null);
    setError(null);
  }

  function closeEditor() {
    resetForm();
    if (protocols.length > 0) {
      setEditorOpen(false);
    }
  }

  function startCreate() {
    resetForm();
    setNotice(null);
    setEditorOpen(true);
  }

  function startEdit(protocol: ProtocolDefinition) {
    setForm(protocolToForm(protocol));
    setEditingProtocolKey(protocol.id);
    setError(null);
    setNotice(null);
    setEditorOpen(true);
  }

  async function saveProtocol() {
    setIsSaving(true);
    setError(null);
    setNotice(null);

    try {
      const payload = buildPayload(form);
      const response = await fetch(
        editingProtocolKey
          ? `/api/account/protocols/${editingProtocolKey}`
          : "/api/account/protocols",
        {
          method: editingProtocolKey ? "PATCH" : "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        },
      );

      const result = await response.json().catch(() => null);
      if (!response.ok) {
        throw new Error(result?.error || "Unable to save protocol.");
      }

      const saved = result.protocol as ProtocolDefinition;
      setProtocols((current) => {
        const others = current.filter((protocol) => protocol.id !== editingProtocolKey);
        return [saved, ...others];
      });

      setNotice(editingProtocolKey ? "Protocol updated." : "Protocol added.");
      setForm(emptyForm(defaultChainId));
      setEditingProtocolKey(null);
      setEditorOpen(false);
    } catch (saveError) {
      setError(
        saveError instanceof Error ? saveError.message : "Unable to save protocol.",
      );
    } finally {
      setIsSaving(false);
    }
  }

  async function deleteProtocol(protocol: ProtocolDefinition) {
    const confirmed = window.confirm(
      `Delete ${protocol.name}? This removes its watched addresses from this account.`,
    );
    if (!confirmed) {
      return;
    }

    setError(null);
    setNotice(null);

    try {
      const response = await fetch(`/api/account/protocols/${protocol.id}`, {
        method: "DELETE",
      });
      const result = await response.json().catch(() => null);
      if (!response.ok) {
        throw new Error(result?.error || "Unable to delete protocol.");
      }

      setProtocols((current) => current.filter((entry) => entry.id !== protocol.id));
      if (editingProtocolKey === protocol.id) {
        resetForm();
      }
      if (protocols.length <= 1) {
        setEditorOpen(true);
      }
      setNotice("Protocol deleted.");
    } catch (deleteError) {
      setError(
        deleteError instanceof Error
          ? deleteError.message
          : "Unable to delete protocol.",
      );
    }
  }

  return (
    <div className="space-y-6">
      <div className="panel p-7">
        <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
          <div>
            <p className="micro-label">Protocol registry</p>
            <h2 className="mt-3 font-display text-2xl font-semibold tracking-[-0.03em] text-text-1">
              Register and update monitored protocols
            </h2>
            <p className="mt-3 max-w-3xl text-sm leading-7 text-text-2">
              Add watched contract addresses, report emails, and key monitoring
              inputs so Ghost can scan the right protocol surface from this
              account.
            </p>
            <div className="mt-4 flex flex-wrap gap-2 font-mono text-[10px] uppercase tracking-[0.16em]">
              <span className="rounded-full border border-white/10 px-3 py-1 text-text-2">
                {protocols.length} registered
              </span>
              <span className="rounded-full border border-white/10 px-3 py-1 text-text-2">
                {editorOpen ? editingProtocolKey ? "editing protocol" : "adding protocol" : "registry ready"}
              </span>
            </div>
          </div>
          <div className="flex flex-wrap gap-3">
            <button
              type="button"
              onClick={startCreate}
              className="rounded-full border border-signal/25 bg-signal/[0.08] px-5 py-3 font-mono text-xs uppercase tracking-[0.16em] text-signal transition hover:border-signal/45"
            >
              Add protocol
            </button>
            {editorOpen && protocols.length > 0 ? (
              <button
                type="button"
                onClick={closeEditor}
                className="rounded-full border border-white/10 px-5 py-3 font-mono text-xs uppercase tracking-[0.16em] text-text-2 transition hover:border-white/20 hover:text-text-1"
              >
                Close panel
              </button>
            ) : null}
          </div>
        </div>

        {editorOpen ? (
          <div className="mt-8 rounded-[28px] border border-white/10 bg-[#0b1013] p-6">
            <div className="flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
              <div>
                <p className="micro-label">
                  {editingProtocolKey ? "Update protocol" : "New protocol"}
                </p>
                <h3 className="mt-2 font-display text-xl font-semibold tracking-[-0.03em] text-text-1">
                  {editingProtocolKey ? "Update monitored protocol details" : "Register monitored protocol"}
                </h3>
              </div>
              <p className="max-w-xl text-sm leading-6 text-text-2">
                Save the addresses and contacts Ghost should monitor from this account.
              </p>
            </div>

            <div className="mt-8 grid gap-4 md:grid-cols-2">
              <div>
                <label className="micro-label">Protocol name</label>
                <input
                  value={form.name}
                  onChange={(event) => updateField("name", event.target.value)}
                  className="mt-2 w-full rounded-2xl border border-white/10 bg-[#0b1013] px-4 py-3 text-sm text-text-1 outline-none transition focus:border-signal/40"
                  placeholder="Aave Base"
                />
              </div>
              <div>
                <label className="micro-label">Protocol key</label>
                <input
                  value={form.protocolKey}
                  onChange={(event) => updateField("protocolKey", event.target.value)}
                  className="mt-2 w-full rounded-2xl border border-white/10 bg-[#0b1013] px-4 py-3 text-sm text-text-1 outline-none transition focus:border-signal/40"
                  placeholder="aave-base"
                />
              </div>
              <div>
                <label className="micro-label">Chain ID</label>
                <input
                  value={form.chainId}
                  onChange={(event) => updateField("chainId", event.target.value)}
                  inputMode="numeric"
                  className="mt-2 w-full rounded-2xl border border-white/10 bg-[#0b1013] px-4 py-3 text-sm text-text-1 outline-none transition focus:border-signal/40"
                  placeholder={String(defaultChainId)}
                />
              </div>
              <div>
                <label className="micro-label">Tier</label>
                <select
                  value={form.tier}
                  onChange={(event) => updateField("tier", event.target.value)}
                  className="mt-2 w-full rounded-2xl border border-white/10 bg-[#0b1013] px-4 py-3 text-sm text-text-1 outline-none transition focus:border-signal/40"
                >
                  <option value="">Unassigned</option>
                  <option value="sentinel">Sentinel</option>
                  <option value="guardian">Guardian</option>
                  <option value="fortress">Fortress</option>
                </select>
              </div>
              <div>
                <label className="micro-label">Watched addresses</label>
                <textarea
                  value={form.monitoredAddresses}
                  onChange={(event) => updateField("monitoredAddresses", event.target.value)}
                  rows={5}
                  className="mt-2 w-full rounded-2xl border border-white/10 bg-[#0b1013] px-4 py-3 text-sm text-text-1 outline-none transition focus:border-signal/40"
                  placeholder={"0x...\n0x..."}
                />
              </div>
              <div>
                <label className="micro-label">Report emails</label>
                <textarea
                  value={form.securityContacts}
                  onChange={(event) => updateField("securityContacts", event.target.value)}
                  rows={5}
                  className="mt-2 w-full rounded-2xl border border-white/10 bg-[#0b1013] px-4 py-3 text-sm text-text-1 outline-none transition focus:border-signal/40"
                  placeholder={"security@protocol.xyz\nops@protocol.xyz"}
                />
              </div>
              <div>
                <label className="micro-label">Oracle addresses</label>
                <textarea
                  value={form.oracleAddresses}
                  onChange={(event) => updateField("oracleAddresses", event.target.value)}
                  rows={4}
                  className="mt-2 w-full rounded-2xl border border-white/10 bg-[#0b1013] px-4 py-3 text-sm text-text-1 outline-none transition focus:border-signal/40"
                  placeholder={"0x...\n0x..."}
                />
              </div>
              <div>
                <label className="micro-label">Proxy addresses</label>
                <textarea
                  value={form.proxyAddresses}
                  onChange={(event) => updateField("proxyAddresses", event.target.value)}
                  rows={4}
                  className="mt-2 w-full rounded-2xl border border-white/10 bg-[#0b1013] px-4 py-3 text-sm text-text-1 outline-none transition focus:border-signal/40"
                  placeholder={"0x...\n0x..."}
                />
              </div>
              <div className="md:col-span-2">
                <label className="micro-label">Timelock addresses</label>
                <textarea
                  value={form.timelockAddresses}
                  onChange={(event) => updateField("timelockAddresses", event.target.value)}
                  rows={3}
                  className="mt-2 w-full rounded-2xl border border-white/10 bg-[#0b1013] px-4 py-3 text-sm text-text-1 outline-none transition focus:border-signal/40"
                  placeholder={"0x...\n0x..."}
                />
              </div>
            </div>

            <div className="mt-6 flex flex-wrap gap-3">
              <button
                type="button"
                onClick={saveProtocol}
                disabled={isSaving}
                className="rounded-full bg-signal px-5 py-3 font-display text-sm font-semibold uppercase tracking-[0.12em] text-black shadow-signal transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-70"
              >
                {isSaving ? "Saving..." : editingProtocolKey ? "Save changes" : "Register protocol"}
              </button>
              <button
                type="button"
                onClick={closeEditor}
                className="rounded-full border border-white/10 px-5 py-3 font-mono text-xs uppercase tracking-[0.16em] text-text-2 transition hover:border-white/20 hover:text-text-1"
              >
                {editingProtocolKey ? "Cancel edit" : protocols.length > 0 ? "Close panel" : "Clear form"}
              </button>
            </div>
          </div>
        ) : (
          <div className="mt-8 rounded-[28px] border border-white/10 bg-[#0b1013] px-5 py-4 text-sm leading-7 text-text-2">
            Ghost will keep using the protocols already registered on this account. Open the panel again whenever you need to add another protocol or revise monitored addresses.
          </div>
        )}

        {notice ? (
          <div className="mt-4 rounded-2xl border border-signal/30 bg-signal/[0.08] px-4 py-3 text-sm text-signal">
            {notice}
          </div>
        ) : null}

        {error ? (
          <div className="mt-4 rounded-2xl border border-rose-500/20 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
            {error}
          </div>
        ) : null}
      </div>

      <ProtocolAccountTable
        protocols={protocols}
        onEdit={startEdit}
        onDelete={deleteProtocol}
      />

      <LiveAnalysisTerminal
        protocols={protocols}
        fallbackProtocols={fallbackProtocols}
      />
    </div>
  );
}
