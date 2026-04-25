import { SiteChrome } from "@/components/site-chrome";
import { getOptionalSessionAccount } from "@/lib/server/auth";
import { pricingTiers } from "@/lib/site";

export default async function PricingPage() {
  const signedIn = Boolean(await getOptionalSessionAccount());
  return (
    <SiteChrome accent="commercial overview" signedIn={signedIn}>
      <main className="shell py-16 md:py-20">
        <div className="page-hero">
          <span className="eyebrow eyebrow-centered">Pricing</span>
          <h1 className="section-title mt-6">
            Retainer pricing aligned to protocol TVL and response depth.
          </h1>
          <p className="section-copy mx-auto mt-6">
            Ghost is sold as continuous protocol coverage. The operating model
            in the implementation guide tiers retainers by TVL and incident
            responsibility, and this page now mirrors that structure.
          </p>
        </div>

        <div className="mt-14 grid gap-5 lg:grid-cols-3">
          {pricingTiers.map((tier) => (
            <div
              key={tier.name}
              className={`panel flex flex-col p-7 ${tier.featured ? "border-signal/25 bg-signal/[0.04]" : ""}`}
            >
              <p className="micro-label">{tier.name}</p>
              <p className="mt-3 font-mono text-[11px] uppercase tracking-[0.18em] text-text-3">
                {tier.tvl}
              </p>
              <div className="mt-6 flex items-end gap-2">
                <span className="font-display text-5xl font-semibold tracking-[-0.04em]">
                  {tier.price}
                </span>
                <span className="pb-2 text-sm text-text-2">{tier.cadence}</span>
              </div>
              <p className="mt-4 text-sm leading-7 text-text-2">{tier.description}</p>
              <ul className="mt-6 space-y-3 text-sm leading-7 text-text-2">
                {tier.features.map((feature) => (
                  <li key={feature} className="flex gap-3">
                    <span className="mt-2 h-1.5 w-1.5 rounded-full bg-signal" />
                    <span>{feature}</span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </main>
    </SiteChrome>
  );
}
