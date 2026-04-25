"use client";

import type { ProtocolDefinition } from "@/lib/protocols";
import { truncateAddress } from "@/lib/utils";

export function ProtocolAccountTable({
  protocols,
  onEdit,
  onDelete,
}: {
  protocols: ProtocolDefinition[];
  onEdit?: (protocol: ProtocolDefinition) => void;
  onDelete?: (protocol: ProtocolDefinition) => void;
}) {
  return (
    <div className="panel overflow-hidden">
      <div className="border-b border-white/5 px-6 py-4">
        <p className="micro-label">Registered protocols</p>
        <h2 className="mt-2 font-display text-2xl font-semibold tracking-[-0.03em]">
          Account inventory
        </h2>
      </div>

      {protocols.length === 0 ? (
        <div className="px-6 py-10 text-sm leading-7 text-text-2">
          No protocols have been registered yet. Use the registry panel above
          to add your first monitored protocol and start managing watched
          addresses from this account.
        </div>
      ) : (
      <div className="overflow-x-auto">
        <table className="min-w-full text-left">
          <thead className="border-b border-white/5 bg-white/[0.02]">
            <tr className="font-mono text-[10px] uppercase tracking-[0.18em] text-text-3">
              <th className="px-6 py-4">Protocol</th>
              <th className="px-6 py-4">Tier</th>
              <th className="px-6 py-4">Watched</th>
              <th className="px-6 py-4">Contacts</th>
              <th className="px-6 py-4">Coverage</th>
              {onEdit || onDelete ? <th className="px-6 py-4">Actions</th> : null}
            </tr>
          </thead>
          <tbody>
            {protocols.map((protocol) => (
              <tr key={protocol.id} className="border-b border-white/5">
                <td className="px-6 py-4">
                  <div className="font-medium text-text-1">{protocol.name}</div>
                  <div className="mt-1 font-mono text-xs text-text-3">
                    {protocol.id}
                  </div>
                </td>
                <td className="px-6 py-4 text-sm text-text-2">
                  {protocol.billing?.tier ?? "unassigned"}
                </td>
                <td className="px-6 py-4 text-sm text-text-2">
                  <div className="space-y-1 font-mono text-xs">
                    {(protocol.monitored_addresses ?? []).slice(0, 2).map((address) => (
                      <div key={address}>{truncateAddress(address)}</div>
                    ))}
                    {(protocol.monitored_addresses?.length ?? 0) > 2 ? (
                      <div className="text-text-3">
                        +{(protocol.monitored_addresses?.length ?? 0) - 2} more
                      </div>
                    ) : null}
                  </div>
                </td>
                <td className="px-6 py-4 text-sm text-text-2">
                  {(protocol.security_contacts ?? []).length}
                </td>
                <td className="px-6 py-4">
                  <div className="flex flex-wrap gap-2 font-mono text-[10px] uppercase tracking-[0.16em]">
                    <span className="rounded-full border border-signal/20 bg-signal/[0.08] px-3 py-1 text-signal">
                      proactive
                    </span>
                    {protocol.upgrade_monitor?.proxy_addresses?.length ? (
                      <span className="rounded-full border border-white/10 px-3 py-1 text-text-2">
                        upgrades
                      </span>
                    ) : null}
                    {protocol.dependencies?.length ? (
                      <span className="rounded-full border border-white/10 px-3 py-1 text-text-2">
                        dependencies
                      </span>
                    ) : null}
                  </div>
                </td>
                {onEdit || onDelete ? (
                  <td className="px-6 py-4">
                    <div className="flex gap-3">
                      {onEdit ? (
                        <button
                          type="button"
                          onClick={() => onEdit(protocol)}
                          className="font-mono text-[10px] uppercase tracking-[0.16em] text-signal transition hover:brightness-110"
                        >
                          Edit
                        </button>
                      ) : null}
                      {onDelete ? (
                        <button
                          type="button"
                          onClick={() => onDelete(protocol)}
                          className="font-mono text-[10px] uppercase tracking-[0.16em] text-rose-300 transition hover:text-rose-200"
                        >
                          Delete
                        </button>
                      ) : null}
                    </div>
                  </td>
                ) : null}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      )}
    </div>
  );
}
