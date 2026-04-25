import Link from "next/link";
import { DemoTerminal } from "@/components/demo-terminal";
import { SiteChrome } from "@/components/site-chrome";
import { loadActiveProtocols } from "@/lib/protocols";
import { getOptionalSessionAccount } from "@/lib/server/auth";

const platformCards = [
  {
    title: "Verified-source analysis",
    copy: "Compiler-pinned source analysis, proxy resolution, and deterministic checks against production contract surfaces.",
  },
  {
    title: "Upgrade and oracle monitoring",
    copy: "Ghost watches implementation drift, timelock queues, same-block oracle use, stale feeds, and single-source dependency risk.",
  },
  {
    title: "Exploit-path confirmation",
    copy: "Simulation-backed checks distinguish weak signals from reproducible exploit paths before an operator has to make a decision.",
  },
  {
    title: "Evidence and operator control",
    copy: "Human approval stays on irreversible actions while Ghost assembles disclosures, legal exports, and tracking evidence automatically.",
  },
];

const workflowCards = [
  {
    title: "Threat intelligence",
    copy: "Ghost ingests confirmed exploit intelligence, extracts structured signatures, and re-scans monitored protocols against current chain state.",
  },
  {
    title: "Contract surveillance",
    copy: "Verified source, proxy implementations, timelocks, oracle paths, and dependency exposure are monitored continuously instead of only after a loss.",
  },
  {
    title: "Exploit confirmation",
    copy: "Simulation, invariant checks, and protocol-aware probes separate weak signals from reproducible exploit paths.",
  },
  {
    title: "Response artifacts",
    copy: "Once confidence is high enough, Ghost packages findings, tracking evidence, disclosures, and legal exports without leaving the operator blind.",
  },
];

export default async function HomePage() {
  const protocols = await loadActiveProtocols();
  const demoProtocol = protocols[0] ?? null;
  const account = await getOptionalSessionAccount();
  const signedIn = Boolean(account);

  return (
    <SiteChrome accent="proactive monitoring live" signedIn={signedIn}>
      <main>
        <section className="shell pb-14 pt-16 lg:pb-20 lg:pt-24">
          <div className="page-hero">
            <span className="eyebrow eyebrow-centered">
              proactive protocol security
            </span>
            <h1 className="section-title mt-6">
              Proactively detect and block exploit paths before execution.
            </h1>
            <p className="section-copy mx-auto mt-6">
              Ghost gives protocol teams continuous verified-source analysis,
              live upgrade and oracle monitoring, exploit confirmation, and
              evidence-grade response from one operator surface.
            </p>

            <div className="mt-10 flex flex-wrap justify-center gap-4">
              <Link
                href={signedIn ? "/account" : "/sign-up"}
                className="rounded-full bg-signal px-6 py-3 font-display text-sm font-semibold uppercase tracking-[0.12em] text-black shadow-signal transition hover:brightness-110"
              >
                {signedIn ? "Run Analysis" : "Sign up"}
              </Link>
              <Link
                href="/how-it-works"
                className="rounded-full border border-white/15 px-6 py-3 font-mono text-xs uppercase tracking-[0.16em] text-text-2 transition hover:border-white/25 hover:text-text-1"
              >
                How it works
              </Link>
            </div>
          </div>

          <div className="mt-14 grid gap-4 md:grid-cols-4">
            <div className="stat-card">
              <p className="micro-label">Reaction window</p>
              <p className="mt-3 font-display text-4xl font-semibold text-text-1">
                &lt;90s
              </p>
              <p className="mt-2 text-sm leading-6 text-text-2">
                From confirmed exploit path to disclosure and legal exports.
              </p>
            </div>
            <div className="stat-card">
              <p className="micro-label">Coverage loop</p>
              <p className="mt-3 font-display text-4xl font-semibold text-text-1">
                24/7
              </p>
              <p className="mt-2 text-sm leading-6 text-text-2">
                Scheduled scans, trigger-based rescans, and live anomaly watch.
              </p>
            </div>
            <div className="stat-card">
              <p className="micro-label">Core monitors</p>
              <p className="mt-3 font-display text-4xl font-semibold text-text-1">
                4
              </p>
              <p className="mt-2 text-sm leading-6 text-text-2">
                Upgrades, oracles, dependencies, and invariants.
              </p>
            </div>
            <div className="stat-card">
              <p className="micro-label">Approval model</p>
              <p className="mt-3 font-display text-4xl font-semibold text-text-1">
                Manual
              </p>
              <p className="mt-2 text-sm leading-6 text-text-2">
                Irreversible response actions remain operator-approved.
              </p>
            </div>
          </div>

          <div className="mt-12">
            <DemoTerminal
              protocolId={demoProtocol?.id}
              protocolName={demoProtocol?.name}
            />
          </div>
        </section>

        <section className="shell py-10 lg:py-14">
          <div className="page-hero">
            <span className="eyebrow eyebrow-centered">platform coverage</span>
            <h2 className="subsection-title mt-5">
              Built to prevent incidents first, then respond with evidence when
              prevention is no longer enough.
            </h2>
          </div>

          <div className="mt-12 grid gap-5 lg:grid-cols-2">
            {platformCards.map((card) => (
              <div key={card.title} className="product-card">
                <p className="micro-label">{card.title}</p>
                <p className="mt-4 text-sm leading-7 text-text-2">
                  {card.copy}
                </p>
              </div>
            ))}
          </div>
        </section>

        <section className="shell py-8 pb-20">
          <div className="grid gap-5 lg:grid-cols-[1.1fr_0.9fr]">
            <div className="panel p-7">
              <p className="micro-label">Operational model</p>
              <h2 className="subsection-title mt-4">
                One loop for monitoring, confirmation, and operator-approved
                action.
              </h2>
              <div className="mt-8 grid gap-4 sm:grid-cols-2">
                {workflowCards.map((card) => (
                  <div
                    key={card.title}
                    className="rounded-2xl border border-white/10 bg-raised/60 p-5"
                  >
                    <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-signal">
                      {card.title}
                    </p>
                    <p className="mt-3 text-sm leading-7 text-text-2">
                      {card.copy}
                    </p>
                  </div>
                ))}
              </div>
            </div>

            <div className="panel p-7">
              <p className="micro-label">Operator guarantees</p>
              <ul className="mt-6 space-y-4 text-sm leading-7 text-text-2">
                <li>
                  Findings carry simulation and corpus provenance through to
                  disclosures and legal exports.
                </li>
                <li>
                  Ghost does not move funds or trigger irreversible actions
                  without explicit human approval.
                </li>
                <li>
                  The landing terminal is a demo surface. The account console
                  runs real analysis against your configured protocol registry.
                </li>
              </ul>
              <div className="mt-8 flex flex-wrap gap-3">
                {signedIn ? (
                  <Link
                    href="/account"
                    className="rounded-full border border-signal/25 bg-signal/[0.08] px-5 py-3 font-mono text-xs uppercase tracking-[0.16em] text-signal transition hover:border-signal/45"
                  >
                    Run Analysis
                  </Link>
                ) : (
                  <Link
                    href="/sign-up"
                    className="rounded-full border border-signal/25 bg-signal/[0.08] px-5 py-3 font-mono text-xs uppercase tracking-[0.16em] text-signal transition hover:border-signal/45"
                  >
                    Create operator account
                  </Link>
                )}
                <Link
                  href="/docs"
                  className="rounded-full border border-white/10 px-5 py-3 font-mono text-xs uppercase tracking-[0.16em] text-text-2 transition hover:border-white/20 hover:text-text-1"
                >
                  Read operator docs
                </Link>
              </div>
            </div>
          </div>
        </section>
      </main>
    </SiteChrome>
  );
}
