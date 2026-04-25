import { SiteChrome } from "@/components/site-chrome";
import { getOptionalSessionAccount } from "@/lib/server/auth";

const phases = [
  {
    title: "Registry + readiness",
    copy: "Protocols register watched addresses, security contacts, dependency context, and optional simulation profiles. Ghost validates the profile before trusting protocol-specific probes.",
  },
  {
    title: "Proactive sweep",
    copy: "Verified-source AST analysis, upgrade monitoring, oracle checks, dependency checks, and invariant sweeps run continuously against registered protocols.",
  },
  {
    title: "Live anomaly detection",
    copy: "The mempool and post-confirmation path score exploit signals, confirm drain behavior on forks, and collapse noisy inputs into a single confidence tier.",
  },
  {
    title: "Response orchestration",
    copy: "Once confidence crosses the right threshold, Ghost starts attacker profiling, fund tracking, legal exports, disclosure workflows, and optional bounty recovery tooling.",
  },
];

export default async function HowItWorksPage() {
  const signedIn = Boolean(await getOptionalSessionAccount());
  return (
    <SiteChrome accent="workflow map active" signedIn={signedIn}>
      <main className="shell py-16 md:py-20">
        <div className="page-hero">
          <span className="eyebrow eyebrow-centered">How it works</span>
          <h1 className="section-title mt-6">
            Ghost operates like a protocol command loop, not a static dashboard.
          </h1>
          <p className="section-copy mx-auto mt-6">
            The system cycles through registry validation, proactive analysis,
            live signal detection, simulation-backed confirmation, and
            evidence-rich response routing. Each phase is designed to add
            confidence instead of noise.
          </p>
        </div>

        <div className="mt-14 grid gap-5 lg:grid-cols-[0.8fr_1.2fr]">
          <div className="panel p-7">
            <p className="micro-label">Response doctrine</p>
            <p className="mt-4 text-sm leading-7 text-text-2">
              Prevent what you can, confirm what you cannot prevent, and never
              escalate without preserving evidence quality. That principle
              drives every page and every operator action in Ghost.
            </p>
          </div>

          <div className="space-y-5">
            {phases.map((phase, index) => (
              <div key={phase.title} className="panel grid gap-6 p-7 md:grid-cols-[88px_1fr]">
                <div>
                  <div className="inline-flex h-12 w-12 items-center justify-center rounded-full border border-signal/20 bg-signal/[0.08] font-display text-lg font-bold text-signal">
                    {String(index + 1).padStart(2, "0")}
                  </div>
                </div>
                <div>
                  <h2 className="subsection-title">{phase.title}</h2>
                  <p className="mt-3 text-sm leading-7 text-text-2">
                    {phase.copy}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </main>
    </SiteChrome>
  );
}
