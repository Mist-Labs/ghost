import { SiteChrome } from "@/components/site-chrome";
import { getOptionalSessionAccount } from "@/lib/server/auth";
import { docSections } from "@/lib/site";

export default async function DocsPage() {
  const signedIn = Boolean(await getOptionalSessionAccount());
  return (
    <SiteChrome accent="docs online" signedIn={signedIn}>
      <main className="shell py-16 md:py-20">
        <div className="page-hero">
          <span className="eyebrow eyebrow-centered">Docs</span>
          <h1 className="section-title mt-6">
            Operational docs for protocol onboarding, monitoring, and response.
          </h1>
          <p className="section-copy mx-auto mt-6">
            This docs view mirrors the product architecture: protocol config,
            proactive scanning, incident response, and operator workflows.
          </p>
        </div>

        <div className="mt-14 grid gap-5 lg:grid-cols-[320px_1fr]">
          <div className="panel p-7">
            <p className="micro-label">Guide index</p>
            <div className="mt-5 space-y-4">
              {docSections.map((section) => (
                <div key={section.title}>
                  <p className="font-display text-xl font-semibold tracking-[-0.03em]">
                    {section.title}
                  </p>
                  <ul className="mt-3 space-y-2 text-sm leading-7 text-text-2">
                    {section.items.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </div>

          <div className="panel p-7">
            <p className="micro-label">Quickstart</p>
            <div className="mt-6 space-y-6">
              <div>
                <h2 className="subsection-title">Base Sepolia demo boot</h2>
                <p className="mt-3 text-sm leading-7 text-text-2">
                  Point your environment at Base Sepolia, keep the dedicated
                  Sepolia protocol file selected, and start the Ghost service
                  with the Kimi signature extractor configured.
                </p>
              </div>

              <div className="rounded-2xl border border-white/10 bg-black/60 p-5 font-mono text-xs leading-7 text-text-2">
                DATABASE_URL=postgresql://...{"\n"}
                ALCHEMY_HTTP_URL=https://base-sepolia.g.alchemy.com/v2/...{"\n"}
                ALCHEMY_WS_URL=wss://base-sepolia.g.alchemy.com/v2/...{"\n"}
                CHAIN_ID=84532{"\n"}
                PROTOCOLS_FILE=protocols.base-sepolia.example.json{"\n"}
                KIMI_API_KEY=...{"\n"}
                BASESCAN_API_KEY=...
              </div>
            </div>
          </div>
        </div>
      </main>
    </SiteChrome>
  );
}
