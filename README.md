# Ghost

**Detects, prevents, and responds to DeFi hacks.**

Ghost is an autonomous security agent for DeFi protocols. It runs two parallel loops — a reactive incident response pipeline that activates within 60 seconds of an exploit landing, and a proactive contract scanner that hunts for vulnerabilities before attackers find them. Built in Rust on Base.

---

## What Ghost Does

### Reactive Path — Exploit Response
When an exploit lands, Ghost activates automatically:

1. **Detects** the attack transaction in the mempool using a 12-signal anomaly scorer
2. **Confirms** via three parallel on-chain checks — reserve drain simulation, ABI intent classification, and economic invariant verification — eliminating false positives before escalating
3. **Profiles** the attacker — wallet funding history, behavioral fingerprinting, RPC geolocation
4. **Tracks** stolen funds in real time across wallet hops, bridges, and mixer entries
5. **Deploys** a decaying on-chain bounty contract to the attacker's address with a structured settlement offer
6. **Monitors** 300+ CEX hot wallets and auto-drafts freeze requests the moment stolen funds appear
7. **Generates** a court-ready legal package with full chain of custody, wallet attribution, and pre-filled FBI IC3 and Europol EC3 complaint templates
8. **Notifies** the Security Alliance (SEAL) and the protocol team

All escalation actions — bounty deployment, SEAL notification, legal package dispatch — sit behind a 60-second operator confirmation gate. No funds are moved autonomously.

### Proactive Path — Vulnerability Scanning
Ghost continuously monitors every authorized protocol for vulnerabilities before attackers find them:

- **Hack feed ingestion** — polls Rekt News and DeFiLlama every 15 minutes for new exploit reports
- **Signature extraction** — derives reusable vulnerability signatures from each report using structured AI output
- **Contract scanning** — deterministic AST analysis via `solc --standard-json` against Sourcify-verified source, with Beacon/UUPS/transparent proxy resolution
- **Simulation confirmation** — fork-based exploitability probes using real Base mainnet liquidity (Aerodrome, Uniswap v3, Balancer v2, Aave V3)
- **Hybrid oracle monitoring** — same-block price update/use detection, single-source dependency flagging, TWAP window enforcement
- **Upgrade monitoring** — tracks queued TimelockController actions and proposed implementations before execution
- **Dependency monitoring** — verifies bridge, router, and oracle addresses against approved codehash baselines
- **Responsible disclosure** — private notification to the protocol's security contacts with 90-day resolution SLA

### AST Rule Pack (Phase 1 — Solidity)
Ghost ships nine deterministic rules covering the highest-historical-loss vulnerability classes:

| Rule | Description |
|---|---|
| `unprotected_upgrade` | `upgradeTo` reachable without access control |
| `unprotected_initializer` | `initialize()` missing `initializer` modifier |
| `delegatecall_on_user_input` | `delegatecall` target derived from user-controlled input |
| `tx_origin_auth` | `tx.origin` used for access control |
| `public_selfdestruct` | `selfdestruct` reachable without owner guard |
| `unchecked_low_level_call` | `.call()` return value not checked |
| `unchecked_arithmetic_block` | Arithmetic inside `unchecked {}` without bounds validation |
| `critical_access_control_missing` | State-changing functions with no modifier or role check |
| `reentrancy_window` | External call before state update (medium confidence) |

Oracle timing is intentionally excluded from AST-only detection and handled in the hybrid monitor path for lower false positive rates.

---

## Architecture

```
                     ┌──────────────────────────────┐
                     │      PostgreSQL + API         │
                     └──────────────┬───────────────┘
                                    │
          ┌─────────────────────────┼─────────────────────────┐
          ▼                         ▼                         ▼
 Mempool Listener          Hack Intel Feed            Artifact Store
          │                         │                         │
          ▼                         ▼                         ▼
  Detection Engine        Signature Extractor        Filesystem / 0G
          │                         │
          ▼                         ▼
     Orchestrator          Base Contract Scanner
          │                         │
          └──────────────► Notifications / Disclosure
```

Ghost runs two concurrent loops:
- **Reactive**: mempool listener → anomaly scoring → confirmation pipeline → incident persistence → artifact storage → operator notification
- **Proactive**: hack intel ingestion → signature extraction → authorized protocol scanning → responsible disclosure

---

## Tech Stack

- **Language**: Rust 1.75+ (Tokio async runtime)
- **Chain**: Base sepolia (chain ID 84532)
- **Database**: PostgreSQL 15+ via Diesel ORM
- **Detection**: Alchemy/Base WebSocket RPC, Flashbots RPC
- **Simulation**: Tenderly fork simulation, Foundry Anvil for local testing
- **Source verification**: Sourcify (primary), BaseScan (fallback)
- **Compiler**: `solc --standard-json` pinned to deployment version
- **Tracing**: Nansen, Arkham Intelligence, Metasleuth
- **Geolocation**: bloXroute BDN first-seen node, MaxMind GeoIP
- **Legal output**: Headless Chrome PDF generation
- **Storage**: 0G decentralized storage for tamper-proof evidence
- **Execution**: KeeperHub for reliable on-chain bounty deployment
- **Monitoring hook**: Uniswap v4 GhostHook on Base pools

---

## Smart Contracts

| Contract | Description |
|---|---|
| `GhostRegistry.sol` | On-chain registry of authorized monitoring protocols. Admin role syncs automatically via Ghost's operator wallet. |
| `GhostBounty.sol` | Per-incident escrow with 5%/day decay. World ID verification gates post-claim disclosure tier. |
| `GhostHook.sol` | Uniswap v4 hook providing pool-level swap anomaly detection via `beforeSwap`/`afterSwap` callbacks. |

---

## Confidence Tier System

Ghost never escalates on a single signal. All three confirmation layers must be evaluated before any action:

| Tier | Conditions | Actions |
|---|---|---|
| None | Sanctioned exit function or score < 2 | Ignore |
| Low | Anomaly score ≥ 2 only | Log only |
| Medium | Drain confirmed + suspicious ABI | Track funds, profile attacker, alert operator |
| High | Economic invariant violated | All above + prepare escalation assets |
| Critical | Invariant + unknown selector + score ≥ 4 | All above + auto-confirm after 60s |

---

## Getting Started

### Prerequisites
- Rust 1.75+
- PostgreSQL 15+
- Base HTTP and WebSocket RPC (Alchemy recommended)
- Foundry (for contract deployment and local fork testing)
- Node.js 18+ (for 0G artifact publishing)

### Installation

```bash
git clone https://github.com/your-org/ghost
cd ghost
cp .env.example .env
# Configure your .env — see Environment Variables below
diesel migration run
cargo build --release
```

### Running Ghost

```bash
# Production (Base mainnet)
RUST_LOG=ghost=info cargo run --release

# Local fork (Anvil)
anvil --fork-url $ALCHEMY_HTTP_URL \
      --fork-block-number $SIMULATION_FORK_BLOCK_NUMBER \
      --block-time 2
RUST_LOG=ghost=debug cargo run --release -- --rpc ws://localhost:8545

# Validate CEX corpus
cargo run -- validate-cex-corpus ./cex_wallets.json
```

### Demo Flow

The included `protocols.example.json` ships a runnable Aave V3 Base demo profile with sepolia deployed addresses, a funded whale holder, Aerodrome and Uniswap v3 routes, and a pinned fork block for reproducible simulation.

```bash
# 1. Start a pinned Base fork
anvil --fork-url $ALCHEMY_HTTP_URL \
      --fork-block-number $SIMULATION_FORK_BLOCK_NUMBER

# 2. Copy the example profile
cp protocols.example.json protocols.json

# 3. Run Ghost against the local fork
RUST_LOG=ghost=info cargo run --release -- --rpc ws://localhost:8545

# 4. Simulate a test exploit
cargo run --bin simulate_exploit -- --protocol aave --amount 1000000
```

Ghost will detect the exploit, build the attacker profile, track funds, deploy the bounty contract, and write `legal-package.pdf` — end to end in under two minutes.

---

## Environment Variables

```env
# Chain
CHAIN_NAME=base_sepolia
CHAIN_ID=84532
ALCHEMY_HTTP_URL=https://base-sepolia.g.alchemy.com/v2/YOUR_KEY
ALCHEMY_WS_URL=wss://base-sepolia.g.alchemy.com/v2/YOUR_KEY
EXPLORER_API_URL=https://api.basescan.org/api
BASESCAN_API_KEY=your_key

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/ghost

# Detection
MIN_ALERT_SCORE=2

# Simulation
SIMULATION_FORK_BLOCK_NUMBER=29000000   # pinned for reproducible demo

# Operator
OPERATOR_EMAIL=security@yourprotocol.com
GHOST_API_KEY=change_me
HTTP_BIND=127.0.0.1:8080

# Notifications
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password
FROM_EMAIL=ghost@example.com

# Proactive scanning
HACK_FEED_POLL_INTERVAL_SECS=900
FULL_SCAN_INTERVAL_SECS=86400
DISCLOSURE_FIRST_RESPONSE_SLA_HOURS=24
DISCLOSURE_RESOLUTION_SLA_DAYS=90
OPENAI_API_KEY=your_key

# Attribution
CEX_WALLETS_FILE=./cex_wallets.json
BLOXROUTE_AUTH=your_bloxroute_auth_header
MAXMIND_DB_PATH=/path/to/GeoLite2-City.mmdb

# Bounty deployment
BOUNTY_PRIVATE_KEY=your_key
BOUNTY_SOLC_BINARY=solc
BOUNTY_CONTRACT_PATH=contracts/GhostBounty.sol

# Billing (disabled by default)
ACTIVATE_FEE=false
STRIPE_SECRET_KEY=your_key
```

---

## Protocol Registry

Ghost only scans contracts belonging to protocols with `monitoring_authorized: true` in `protocols.json`. This is a hard requirement — Ghost does not scan arbitrary contracts.

Minimal protocol entry:

```json
{
  "id": "your-protocol",
  "name": "Your Protocol",
  "chain_id": 8453,
  "protocol_type": "amm",
  "monitoring_authorized": true,
  "contract_addresses": ["0x..."],
  "security_contacts": ["security@yourprotocol.com"],
  "oracle_monitor": {
    "require_sequencer_uptime_feed": true,
    "minimum_sources": 2,
    "feeds": []
  },
  "invariants": []
}
```

See `protocols.example.json` for the full Aave V3 Base demo profile with simulation configuration.

---

## Security Boundaries

Ghost is a read-and-report system. Two controlled write actions exist:

- **Bounty contract deployment** — requires explicit `--deploy-bounty` flag or operator confirmation
- **Freeze request emails** — drafted automatically, sent only after operator approval via the dashboard

No funds are moved autonomously. No attacker identity data is published without operator authorization. All evidence is packaged for law enforcement handoff only.

---

## Business Model

Three revenue streams, all gated behind `ACTIVATE_FEE=false` until you're ready:

| Model | Structure |
|---|---|
| **Protocol Retainer** | $2,500–$25,000/month based on TVL tier (Sentinel / Guardian / Fortress) |
| **Recovery Success Fee** | 10% of funds recovered via bounty, CEX freeze, or law enforcement |
| **Threat Intelligence Feed** | $1,500–$5,000/month per subscriber — anonymized incident data API |

---

## Deploying Contracts

```bash
# Deploy all three contracts to Base
forge script script/Deploy.s.sol \
  --rpc-url $ALCHEMY_HTTP_URL \
  --private-key $DEPLOYER_PRIVATE_KEY \
  --broadcast \
  --verify \
  --etherscan-api-key $BASESCAN_API_KEY

# Verify individually
forge verify-contract <address> src/GhostRegistry.sol:GhostRegistry \
  --chain base \
  --etherscan-api-key $BASESCAN_API_KEY
```

---

## API Endpoints

Ghost exposes an operator API on `HTTP_BIND`:

```
GET  /health                          # health check
GET  /ready                           # readiness check
GET  /incidents                       # list all incidents
GET  /incidents/:id                   # incident detail
GET  /incidents/:id/artifacts         # legal package and evidence artifacts
GET  /proactive/disclosures           # list vulnerability disclosures
POST /proactive/disclosures/:id/acknowledge  # acknowledge a disclosure
POST /admin/reload-cex-corpus         # hot-reload CEX wallet corpus
POST /admin/reload-bridge-corpus      # hot-reload bridge corpus
POST /admin/reload-mixer-corpus       # hot-reload mixer corpus
GET  /admin/attribution-overview      # corpus health and coverage stats
POST /admin/sync-attribution-feeds    # trigger remote corpus sync
```

All endpoints require `Authorization: Bearer $GHOST_API_KEY`.

---

## Built By

**Mist Labs** — Kigali, Rwanda

Okoli Arinze — Co-founder & Lead Engineer
Rust · Solidity · Cairo · ZK Proofs · DeFi Security
[github.com/OkoliEvans](https://github.com/OkoliEvans)

---

## License

MIT