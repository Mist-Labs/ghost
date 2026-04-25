import { SiteChrome } from "@/components/site-chrome";
import { loadProtocolsFromFiles } from "@/lib/protocols";
import { getOptionalSessionAccount } from "@/lib/server/auth";
import { truncateAddress } from "@/lib/utils";

export default async function ProtocolsPage() {
  const protocols = await loadProtocolsFromFiles();
  const signedIn = Boolean(await getOptionalSessionAccount());
  const totalWatched = protocols.reduce(
    (count, protocol) => count + (protocol.monitored_addresses?.length ?? 0),
    0,
  );
  const totalDependencies = protocols.reduce(
    (count, protocol) => count + (protocol.dependencies?.length ?? 0),
    0,
  );

  return (
    <SiteChrome accent="registry loaded" signedIn={signedIn}>
      <main className="shell py-16 md:py-20">
        <div className="page-hero">
          <span className="eyebrow eyebrow-centered">Protocols</span>
          <h1 className="section-title mt-6">
            Protocol registry coverage with proactive monitors and response
            depth.
          </h1>
          <p className="section-copy mx-auto mt-6">
            Registry entries define the addresses, dependencies, contacts, and
            simulation context Ghost uses to stay ahead of exploit paths.
          </p>
        </div>

        <div className="mt-14 grid gap-4 md:grid-cols-3">
          <div className="stat-card">
            <p className="micro-label">Protocols</p>
            <p className="mt-3 font-display text-4xl font-semibold text-text-1">
              {protocols.length}
            </p>
          </div>
          <div className="stat-card">
            <p className="micro-label">Watched addresses</p>
            <p className="mt-3 font-display text-4xl font-semibold text-text-1">
              {totalWatched}
            </p>
          </div>
          <div className="stat-card">
            <p className="micro-label">Dependencies tracked</p>
            <p className="mt-3 font-display text-4xl font-semibold text-text-1">
              {totalDependencies}
            </p>
          </div>
        </div>

        <div className="mt-14 grid gap-5 xl:grid-cols-2">
          {protocols.map((protocol) => (
            <div key={protocol.id} className="panel p-7">
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div>
                  <p className="micro-label">{protocol.protocol_type ?? "protocol"}</p>
                  <h2 className="mt-3 font-display text-3xl font-semibold tracking-[-0.04em]">
                    {protocol.name}
                  </h2>
                  <p className="mt-2 font-mono text-xs text-text-3">{protocol.id}</p>
                </div>
                <div className="rounded-full border border-signal/25 bg-signal/[0.08] px-4 py-2 font-mono text-[11px] uppercase tracking-[0.16em] text-signal">
                  chain {protocol.chain_id}
                </div>
              </div>

              <div className="mt-6 grid gap-4 md:grid-cols-2">
                <div className="product-card p-4">
                  <p className="micro-label">Watched addresses</p>
                  <p className="mt-2 text-2xl font-semibold text-text-1">
                    {protocol.monitored_addresses?.length ?? 0}
                  </p>
                </div>
                <div className="product-card p-4">
                  <p className="micro-label">Security contacts</p>
                  <p className="mt-2 text-2xl font-semibold text-text-1">
                    {protocol.security_contacts?.length ?? 0}
                  </p>
                </div>
              </div>

              <div className="mt-6">
                <p className="micro-label">Addresses</p>
                <div className="mt-3 flex flex-wrap gap-2">
                  {(protocol.monitored_addresses ?? []).map((address) => (
                    <span
                      key={address}
                      className="rounded-full border border-white/10 px-3 py-2 font-mono text-xs text-text-2"
                    >
                      {truncateAddress(address)}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      </main>
    </SiteChrome>
  );
}
