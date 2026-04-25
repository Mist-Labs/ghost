export const navItems = [
  { href: "/", label: "Overview" },
  { href: "/protocols", label: "Protocols" },
  { href: "/docs", label: "Docs" },
  { href: "/pricing", label: "Pricing" },
];

export const pricingTiers = [
  {
    name: "Sentinel",
    tvl: "< $50M TVL",
    price: "$2,500",
    cadence: "/mo",
    description:
      "Detection and attacker profiling for protocols that need continuous watch without the full recovery pipeline.",
    features: [
      "24/7 proactive scans",
      "Detection and anomaly scoring",
      "Attacker profiling",
      "Operator alerts and artifact capture",
    ],
  },
  {
    name: "Guardian",
    tvl: "$50M–$500M TVL",
    price: "$7,500",
    cadence: "/mo",
    description:
      "Full Ghost response pipeline for protocols that need live confirmation, attribution, and legal-ready incident handling.",
    featured: true,
    features: [
      "Everything in Sentinel",
      "Full response pipeline",
      "CEX surveillance",
      "Legal package generation",
    ],
  },
  {
    name: "Fortress",
    tvl: "$500M+ TVL",
    price: "$25,000",
    cadence: "/mo",
    description:
      "Managed coverage for large protocols that need custom integrations, faster response guarantees, and dedicated operational support.",
    features: [
      "Everything in Guardian",
      "Dedicated incident manager",
      "Custom ABI integration",
      "<30s response SLA",
    ],
  },
];

export const docSections = [
  {
    title: "Getting Started",
    items: [
      "Environment configuration for Base / Base Sepolia",
      "Protocol registry and simulation profiles",
      "Corpus loading, validation, and hot reload",
    ],
  },
  {
    title: "Response Engine",
    items: [
      "Anomaly scoring and confidence tiers",
      "Fund tracking and attribution snapshots",
      "Legal package and filing export workflow",
    ],
  },
  {
    title: "Proactive Security",
    items: [
      "Verified-source AST analysis",
      "Upgrade, oracle, dependency, and invariant monitoring",
      "Live protocol analysis console",
    ],
  },
];
