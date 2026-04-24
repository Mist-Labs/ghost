# Ghost — Frontend Design Specification
### Autonomous Exploit Response System · Complete Product Design Document

---

## 0. Design Philosophy & Aesthetic Direction

Ghost is not a dashboard. It is a **command center** — the thing that runs at 3 AM when a $40M protocol is bleeding out in real time. The design must reflect that. Every visual decision derives from a single principle:

> **Surgical precision under pressure.**

The aesthetic is **Cold Intelligence** — drawn from military operations interfaces, financial terminal software (Bloomberg, Refinitiv), and air traffic control systems. Not "hacker aesthetic." Not Web3 crypto glam. A tool that serious professionals trust with serious money.

**Mood references:**
- Bloomberg Terminal: density, information hierarchy, zero ornamentation
- Palantir Gotham: operational intelligence, graph-centric data, institutional weight
- Figma's dark mode: refined surfaces, quiet micro-interactions
- The Interface from "Margin Call": urgency without hysteria

**The single thing users will remember:** The **confidence tier pulse** — a slow, breathing glow around the entire viewport that shifts from neutral gray → amber → red as an incident escalates. The whole screen becomes the alert.

---

## 1. Design Tokens

### 1.1 Color System

All colors defined as CSS custom properties. The palette is near-monochromatic with a single acid-green signal color. No gradients unless purposeful.

```css
:root {
  /* ── Backgrounds ─────────────────────────────────────── */
  --bg-void:        #080909;   /* True base — viewport background */
  --bg-surface:     #0D0F10;   /* Card / panel surfaces */
  --bg-raised:      #131618;   /* Elevated elements, modals */
  --bg-hover:       #1A1E21;   /* Hover states */
  --bg-selected:    #1F2428;   /* Selected / active states */

  /* ── Borders ─────────────────────────────────────────── */
  --border-dim:     rgba(255, 255, 255, 0.05);
  --border-default: rgba(255, 255, 255, 0.09);
  --border-strong:  rgba(255, 255, 255, 0.16);

  /* ── Text ────────────────────────────────────────────── */
  --text-primary:   #E6EBF0;   /* Headings, key data */
  --text-secondary: #8B96A1;   /* Supporting text, labels */
  --text-tertiary:  #4E5A63;   /* Muted, timestamps, metadata */
  --text-inverse:   #080909;   /* Text on light surfaces */

  /* ── Signal — Primary accent ─────────────────────────── */
  --signal:         #00E676;   /* Acid green — the only warm color */
  --signal-dim:     rgba(0, 230, 118, 0.12);
  --signal-glow:    0 0 24px rgba(0, 230, 118, 0.25);

  /* ── Confidence Tiers ────────────────────────────────── */
  --tier-none:      #2A3038;   /* Neutral — no flag */
  --tier-low:       #1E3A2F;   /* Low confidence */
  --tier-low-fg:    #52C788;
  --tier-medium:    #3A2F10;   /* Medium — tracking starts */
  --tier-medium-fg: #F0A500;
  --tier-high:      #3A1A10;   /* High — legal prep starts */
  --tier-high-fg:   #FF6B35;
  --tier-critical:  #2E0A0A;   /* Critical — full mobilization */
  --tier-critical-fg: #FF2442;
  --tier-critical-glow: 0 0 32px rgba(255, 36, 66, 0.3);

  /* ── Semantic ────────────────────────────────────────── */
  --success:        #00C853;
  --warning:        #FFB300;
  --danger:         #FF2442;
  --info:           #2196F3;

  /* ── Data Visualization ──────────────────────────────── */
  --chart-1:        #00E676;
  --chart-2:        #FF6B35;
  --chart-3:        #2196F3;
  --chart-4:        #9C27B0;
  --chart-5:        #FFB300;
}
```

### 1.2 Typography

**Rationale:** Two typefaces only. Headlines use **Syne** (variable, heavy weights) — architectural, condensed, industrial without being aggressive. Body and UI text use **Geist** — the most precise neutral grotesque built for dense UI. All wallet addresses, hashes, and numeric data use **Geist Mono** — monospace is non-negotiable for on-chain data.

```css
/* Import */
@import url('https://fonts.googleapis.com/css2?family=Syne:wght@400..800&display=swap');
/* Geist loaded via Vercel CDN or self-hosted */

:root {
  --font-display:  'Syne', sans-serif;       /* Headings, hero text, nav labels */
  --font-body:     'Geist', sans-serif;      /* Body copy, UI labels, descriptions */
  --font-mono:     'Geist Mono', monospace;  /* All addresses, hashes, code, data */
}
```

**Type Scale (8pt grid):**

| Token | Size | Weight | Line Height | Use |
|---|---|---|---|---|
| `--text-hero` | 72px | 800 | 0.92 | Landing page hero only |
| `--text-display` | 48px | 700 | 1.0 | Page titles |
| `--text-headline` | 32px | 700 | 1.1 | Section headings |
| `--text-title` | 20px | 600 | 1.2 | Card titles, panel headers |
| `--text-body-lg` | 16px | 400 | 1.5 | Longform, descriptions |
| `--text-body` | 14px | 400 | 1.5 | General UI copy |
| `--text-label` | 12px | 500 | 1.4 | Labels, metadata (UPPERCASE + tracking: 0.08em) |
| `--text-caption` | 11px | 400 | 1.4 | Timestamps, secondary data |
| `--text-mono` | 13px | 400 | 1.6 | Addresses, hashes |
| `--text-mono-sm` | 11px | 400 | 1.5 | Truncated hashes, inline data |

**Typography rules:**
- Labels (12px) always uppercase with `letter-spacing: 0.08em`
- Wallet addresses always truncated: `0x7f3a...c901` with monospace
- Numbers showing loss amounts use `--danger` color
- Numbers showing recovered amounts use `--success` color
- Block heights and timestamps always `--text-mono`

### 1.3 Spacing

8pt base grid throughout.

```
4px  — xs  (tight inline gaps)
8px  — sm  (between related elements)
12px — md  (default padding)
16px — lg  (card padding, section spacing)
24px — xl  (component separation)
32px — 2xl (section separation)
48px — 3xl (major layout gaps)
64px — 4xl (hero whitespace)
```

### 1.4 Border Radius

Ghost uses minimal rounding. Curved corners signal approachability; Ghost signals precision.

```
2px  — tags, badges, inline elements
4px  — inputs, small components
6px  — cards, panels (default)
8px  — modals, drawers
0px  — table rows, full-bleed elements
```

### 1.5 Elevation & Shadow

No box-shadow for depth. Borders create separation. Glow used only for critical states.

```css
--shadow-card:     0 1px 0 var(--border-dim), 0 0 0 1px var(--border-dim);
--shadow-modal:    0 24px 64px rgba(0, 0, 0, 0.6), 0 0 0 1px var(--border-default);
--shadow-dropdown: 0 8px 24px rgba(0, 0, 0, 0.4), 0 0 0 1px var(--border-default);
```

### 1.6 Motion

```css
:root {
  --ease-snap:   cubic-bezier(0.16, 1, 0.3, 1);   /* Snappy UI transitions */
  --ease-slide:  cubic-bezier(0.4, 0, 0.2, 1);    /* Slides, drawers */
  --ease-bounce: cubic-bezier(0.34, 1.56, 0.64, 1); /* Badges, counters */

  --dur-instant:  80ms;
  --dur-fast:     160ms;
  --dur-normal:   240ms;
  --dur-slow:     400ms;
  --dur-breath:   3000ms;  /* Confidence tier glow pulse */
}
```

Motion principles:
- Functional motion only — nothing animates without a reason
- All live-updating data (wallet balances, fund movements) uses a **subtle green flash** on value change (150ms background pulse from `--signal-dim` to transparent)
- The confidence tier viewport glow is the only persistent animation in the product
- Page transitions: content fades out (100ms) and the next fades in (200ms) with 50ms delay — no sliding pages

---

## 2. Layout Architecture

### 2.1 Grid

Three-column shell layout for the dashboard application:

```
┌──────────┬──────────────────────────────────┬───────────────┐
│          │                                  │               │
│  Sidebar │          Main Content            │  Context Rail │
│   240px  │            fluid                 │    320px      │
│          │                                  │               │
└──────────┴──────────────────────────────────┴───────────────┘
```

- **Sidebar (240px fixed):** Primary navigation, system status, active incident indicator
- **Main content (fluid):** Primary workspace — varies per page
- **Context rail (320px fixed):** Contextual panel — incident detail, attacker profile, action queue. Collapses on secondary pages.

Content within main area uses a **12-column grid at 24px gutter**.

### 2.2 Sidebar Anatomy

```
┌─────────────────────────┐
│  ◈  GHOST               │  ← Wordmark (Syne 700, --signal green)
│  v2.1.0   ● LIVE        │  ← Version + live indicator (pulsing dot)
├─────────────────────────┤
│                         │
│  ● ACTIVE INCIDENT      │  ← Flashes when incident active (--danger)
│  $4.2M · 00:14:32       │  ← Amount + elapsed time counter
│                         │
├─────────────────────────┤
│  MONITOR                │
│  ○ Overview             │
│  ○ Live Feed            │
│  ○ Incidents            │
├─────────────────────────┤
│  RESPOND                │
│  ○ Attacker Intel       │
│  ○ Fund Tracker         │
│  ○ Freeze Requests      │
│  ○ Bounty Contracts     │
├─────────────────────────┤
│  REPORT                 │
│  ○ Legal Packages       │
│  ○ Community Alerts     │
├─────────────────────────┤
│  SYSTEM                 │
│  ○ Configuration        │
│  ○ Protocol Registry    │
├─────────────────────────┤
│                         │
│  ◎  [Protocol Avatar]   │  ← Connected protocol
│  Euler Finance          │
│  3 monitors active      │
│                         │
└─────────────────────────┘
```

**Sidebar rules:**
- Nav labels: 12px uppercase, `--font-body`, `letter-spacing: 0.08em`
- Section dividers: 1px `--border-dim` with section label in `--text-tertiary`
- Active nav item: `--signal` left border (2px), `--bg-hover` background
- Icons: 16px, custom-designed geometric shapes (not Heroicons/Lucide defaults — these look generic)
- Active incident block: `--tier-critical` background, red border-left (2px), value in `--danger`

### 2.3 Top Bar (Main Content)

Fixed 56px bar above main content area only (not spanning sidebar):

```
┌─────────────────────────────────────────────────────────┐
│  Fund Tracker                  [Search]  [Filter]  [+]  │
│  ─────────────────────────────────────────────────────  │
│  INC-2024-0312 · Euler Finance · 14 mins ago            │
└─────────────────────────────────────────────────────────┘
```

Page title in `--font-display`, 20px, 600. Breadcrumb in `--text-tertiary`, 12px.

---

## 3. Pages

---

### Page 1: Marketing / Landing Page

**Purpose:** Convert DeFi protocols, security firms, and insurance underwriters. One scroll. One CTA.

**Layout:** Full-width. No sidebar. Centered content at max-width 1200px.

#### Section 1 — Hero

```
┌──────────────────────────────────────────────────────────────────┐
│                                                                  │
│                   ◈  G H O S T                                  │
│                                                                  │
│      AUTONOMOUS EXPLOIT RESPONSE.                                │
│      FROM DETECTION TO LEGAL IN                                  │
│      UNDER 2 MINUTES.                                            │
│                                                                  │
│  [  REQUEST ACCESS  ]          [ Watch Demo ]                    │
│                                                                  │
│  ──────────────────────────────────────────────────────         │
│  $2.1B recovered window missed in 2023  ·  0 automated systems  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

**Hero type:** "AUTONOMOUS EXPLOIT RESPONSE." at 72px Syne 800, uppercase, tight leading (0.92). Line breaks intentional — reads like a terminal command.

**Background:** Subtle noise texture (`filter: contrast(145%) brightness(100%)` on SVG feTurbulence). A faint grid pattern (1px lines at 64px intervals, `opacity: 0.03`) that suggests a coordinate system.

**Animated element:** Below the headline, a live-simulated transaction stream — a 3-column monospace feed of fake transaction hashes scrolling upward at 60fps, fading out at top and bottom. Suggests real-time monitoring without being distracting. Color: `--text-tertiary`. One entry per ~800ms flashes briefly in `--signal` before fading — simulating a flagged transaction.

**CTA buttons:**
- Primary: `--signal` background, `--text-inverse` text, 0 radius (sharp corners — intentional)
- Secondary: transparent, `--border-default` border, `--text-secondary` text

#### Section 2 — The Problem (Three stats)

Three full-width columns. No cards. Just numbers.

```
    $4.2B              3–18 hrs           < 2%
  lost in DeFi    average response     recovery
  exploits 2023   time (manual)         rate
```

Numbers: 64px Syne 700, `--text-primary`
Labels: 13px, `--text-tertiary`, uppercase

Thin horizontal rule above and below the row.

#### Section 3 — What Ghost Does

Left: vertical numbered sequence with short label + one-sentence description per capability  
Right: Static screenshot of the Ghost dashboard (real UI, not an illustration)

Seven capabilities listed. Active number indicator (01–07) in `--signal` green. Hovering a capability highlights its corresponding zone in the dashboard screenshot.

#### Section 4 — Confidence Tier Explainer

Visual: The five confidence tiers rendered as a horizontal spectrum bar — `none → low → medium → high → critical` — with what Ghost does at each tier listed beneath each segment. This is the single most important UX concept in the product.

Tier bar:
- Full-width
- Each segment: 20% width, background from `--tier-*`, label in `--tier-*-fg`
- Below each: 2–3 bullet actions that unlock at that tier

#### Section 5 — The 30-Day MVP Timeline

Horizontal timeline (desktop) / vertical (mobile). 8 milestones. Each milestone: date, label, description. Currently-completed milestones shown with `--signal` dot. The MVP end state is shown as a terminal block — white text on black showing Ghost's final output.

#### Section 6 — Who It's For

Four cards. Each: icon (geometric, not emoji), title, one-sentence description. Grid: 2×2.

Cards: `--bg-surface`, `--border-default` border, 6px radius. On hover: `--border-strong` border, `--bg-raised` background. No shadows.

#### Section 7 — Footer

Three columns: logo + tagline left, links center, legal right. Full-width separator line. Background: `--bg-void`.

---

### Page 2: Dashboard Overview

**The primary screen.** This is what operators see the moment they log in.

#### Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  GHOST OVERVIEW          [Apr 21 2026]   [All Protocols ▾]      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌──────────┐  │
│  │ ACTIVE      │ │ FUNDS AT    │ │ BOUNTIES    │ │FREEZE    │  │
│  │ INCIDENTS   │ │ RISK        │ │ DEPLOYED    │ │REQUESTS  │  │
│  │     1       │ │  $4.2M      │ │     3       │ │    2     │  │
│  │ ● CRITICAL  │ │  +$847k     │ │ ○ pending   │ │ sent     │  │
│  └─────────────┘ └─────────────┘ └─────────────┘ └──────────┘  │
│                                                                  │
│  ┌─────────────────────────────────────┐ ┌───────────────────┐  │
│  │ LIVE ANOMALY FEED                   │ │ INCIDENT QUEUE    │  │
│  │                                     │ │                   │  │
│  │ [Scrolling transaction feed]        │ │ 1 CRITICAL        │  │
│  │ Each row: score, hash, protocol,    │ │ 0 HIGH            │  │
│  │ time, action                        │ │ 2 MEDIUM          │  │
│  │                                     │ │ 5 LOW             │  │
│  │                                     │ │                   │  │
│  └─────────────────────────────────────┘ └───────────────────┘  │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ ANOMALY SCORE HISTORY — Last 24 Hours                   │    │
│  │  [Area chart, --signal green fill, timestamps on x]     │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

#### Stat Cards (top row)

4 cards, equal width, `--bg-surface`, 6px radius, 16px padding.

Structure per card:
```
LABEL (12px uppercase --text-tertiary)
VALUE (32px Syne 700 --text-primary)
SUBTEXT (12px --text-secondary)
```

Active Incidents card: When `>0`, the value pulses in `--danger`. A small animated indicator dot breathes slowly.

#### Live Anomaly Feed

Full-height scrollable table. Updates in real time. Rows:

```
SCORE  HASH            PROTOCOL        SIGNALS     TIME    STATUS
  7    0x7f3a…c901     Euler Finance   FL+OC+DG    0:04    ⚠ CONFIRM
  3    0xb291…44fe     Aave v3         FL+GAS      0:07    ● WATCH
  1    0xc044…8810     Uniswap v3      GAS         0:11    — CLEAR
```

- `SCORE ≥ 5`: row background `--tier-high`, score in `--tier-high-fg`
- `SCORE ≥ 2`: row background `--tier-medium`, score in `--tier-medium-fg`
- `SCORE = 1`: default row, `--text-tertiary` for score
- Signal codes are inline tags: `FL` (flash loan), `OC` (oracle correlation), `DG` (drain-from-governance), `GAS` (gas anomaly) — each a small pill badge

New rows slide in from the bottom. Removed rows slide out at top with 160ms ease.

#### Incident Queue (right column)

Compact list. Each entry:
```
● [PROTOCOL AVATAR]  Protocol Name
  INC-2024-0312 · $4.2M · 14m ago
  ████████████ CRITICAL
```

Tier color stripe on left. Click → opens Incident Detail page.

---

### Page 3: Incident Detail

**Context:** An active or historical incident. This is Ghost's most information-dense page.

#### Three-pane layout

```
┌─────────────┬───────────────────────────┬─────────────────────┐
│             │                           │                     │
│  INCIDENT   │    TIMELINE & EVIDENCE    │   ACTION QUEUE      │
│  SUMMARY    │                           │                     │
│             │                           │                     │
│  INC-2024   │   [Vertical timeline of   │  [Pending actions   │
│  -0312      │    all events: detection, │   requiring human   │
│             │    confirmations, fund    │   approval]         │
│  Euler      │    movements, responses]  │                     │
│  Finance    │                           │  ○ Send freeze rq   │
│             │                           │  ○ Deploy bounty    │
│  $4.2M      │                           │  ○ Notify SEAL      │
│  CRITICAL   │                           │                     │
│             │                           │  [60s gate timer    │
│  14:32      │                           │   visible here]     │
│  elapsed    │                           │                     │
└─────────────┴───────────────────────────┴─────────────────────┘
```

#### Incident Summary Panel (left, 280px)

```
INC-2024-0312

PROTOCOL
Euler Finance

STATUS
● CRITICAL

FUNDS AT RISK
$4,217,440

ELAPSED
00:14:32

CONFIDENCE
████████░░ 82%

ATTACKER
0x7f3a…c901
→ View Profile

PHASE
3 of 6 — Fund Tracking

SIGNALS TRIGGERED
7 of 12
FL · OC · DG · WA · GAS · TT · RP
```

Phase progress bar: horizontal, 6 segments filled up to current phase. Each segment: a dot connected by line. Active phase pulses.

#### Timeline Panel (center, fluid)

Vertical timeline. Each event is a row:

```
00:00:00  ● EXPLOIT DETECTED
          Flash loan initiated from 0x7f3a...c901
          Score: 7/12 signals → CRITICAL tier triggered

00:00:04  ● CONFIRMATION: RESERVE DRAIN
          USDC reserve: $8.2M → $4.0M (-51.2%)
          Simulation confirmed via eth_call fork

00:00:06  ● CONFIRMATION: ECONOMIC INVARIANT VIOLATED
          Input: 1,000 USDC → Output: 4,217 USDC
          Actual/Expected ratio: 4.217x (threshold: 1.05x)

00:00:09  ● ATTACKER PROFILE GENERATED
          Estimated jurisdiction: Eastern Europe
          Skill tier: Advanced
          Funding: Binance CEX withdrawal → 0x4c2a...81de

00:00:14  ● FUND MOVEMENT #1
          0x7f3a...c901 → 0xa91b...33cc
          Amount: 4,217,440 USDC via direct transfer

00:00:22  ● FUND MOVEMENT #2
          0xa91b...33cc → 0xBridge (Stargate)
          Amount: 4,217,440 USDC → Arbitrum
          [ View on Arbiscan → ]

00:11:18  ● CEX DEPOSIT DETECTED
          Funds entered Binance hot wallet 0x3c...9a
          Freeze request drafted — awaiting approval
          [  REVIEW FREEZE REQUEST →  ]

[pending] ○ Bounty contract deployment — awaiting approval
[pending] ○ Legal package generation — in queue
```

Timeline events: left border colored by event type. Detection = `--danger`. Confirmation = `--warning`. Fund movement = `--info`. Response action = `--signal`.

Pending events: dashed border, `--text-secondary`.

Action items within the timeline are interactive inline cards, not separate flows.

#### Action Queue Panel (right, 320px)

Three sections: **Pending Approval**, **In Progress**, **Completed**.

Each pending action is a card:
```
┌───────────────────────────────────┐
│  FREEZE REQUEST                   │
│  Binance · 0x3c9a...              │
│  $4,217,440 USDC                  │
│                                   │
│  FinCEN + MiCA Article 17 cited   │
│  Draft ready — review before send │
│                                   │
│  [  REVIEW DRAFT  ]               │
│  ○ 60-second approval gate        │
└───────────────────────────────────┘
```

**60-second approval gate:** A circular timer rendered beneath high-stakes action buttons. Ring empties over 60s. Operator must actively confirm — no accidental sends.

---

### Page 4: Attacker Intelligence

**Purpose:** Structured attacker profile, built automatically by Ghost.

#### Layout

Left third: Profile summary card  
Right two-thirds: Tabbed detail view

#### Profile Summary Card

```
┌──────────────────────────────────┐
│  ATTACKER PROFILE                │
│  INC-2024-0312                   │
│                                  │
│  WALLET                          │
│  0x7f3a...c901                   │
│  [ Copy ]  [ Etherscan → ]       │
│                                  │
│  FIRST SEEN                      │
│  Apr 14, 2026 · 3 days prior     │
│                                  │
│  FUNDING SOURCE                  │
│  Binance CEX withdrawal          │
│  0x4c2a...81de                   │
│                                  │
│  ESTIMATED JURISDICTION          │
│  Eastern Europe                  │
│  Confidence: Medium              │
│                                  │
│  SKILL TIER                      │
│  ████████░░ Advanced             │
│                                  │
│  PRIOR FLAGS                     │
│  1 prior flagged interaction     │
│  Uniswap v2 · Mar 2026           │
│                                  │
│  LAW ENFORCEMENT READY           │
│  [ Export Profile PDF → ]        │
│                                  │
└──────────────────────────────────┘
```

#### Tabbed Detail View

Tabs: **Funding Trace** · **Behavioral Signals** · **Transaction History** · **Gas Patterns**

**Funding Trace tab:**

A horizontal wallet chain diagram:

```
[Binance]  →  [0x4c2a...81de]  →  [0x7f3a...c901]  →  EXPLOIT
   CEX           Bridge              Attacker
 Withdrawal       (3d ago)          Wallet
 (7d ago)
```

Each node: a small rectangular card. Edge: arrow with label (amount, time, method). Active node (attacker wallet) highlighted with `--signal` border.

**Behavioral Signals tab:**

Table of behavioral signals detected:

| Signal | Value | Significance |
|---|---|---|
| Test transactions | 3 prior probing txs | High — deliberate preparation |
| Execution time (UTC) | 03:47 UTC | Medium — low-traffic window |
| Gas strategy | Dynamic, above base | High — MEV awareness |
| First-seen RPC node | Frankfurt, DE | Medium — VPN likely |
| Time between fund receipt and exploit | 3 days | High — typical staging pattern |

**Gas Patterns tab:**  
Small sparkline chart: gas used per transaction over time. Annotated with event markers (wallet created, first test tx, exploit).

---

### Page 5: Fund Tracker

**The real-time map of where stolen funds are.**

#### Layout

Full-width graph view + right sidebar for wallet detail.

```
┌──────────────────────────────────────────────────┬────────────┐
│                                                  │            │
│           FUND MOVEMENT GRAPH                    │  WALLET    │
│                                                  │  DETAIL    │
│  [Force-directed graph: wallets as nodes,        │            │
│   transfers as edges, amount encoded in          │  [Selected │
│   edge thickness, chain encoded in node color]  │   node     │
│                                                  │   info]    │
│                                                  │            │
├──────────────────────────────────────────────────┤            │
│  CHAIN FILTER: [ETH] [ARB] [BASE] [BSC] [SOL]   │            │
│  SHOW: Wallets ✓  Bridges ✓  CEX Deposits ✓     │            │
└──────────────────────────────────────────────────┴────────────┘
```

#### Fund Movement Graph

Built with D3.js force-directed layout.

**Node types and visual encoding:**

| Node Type | Shape | Color |
|---|---|---|
| Attacker wallet | Circle, 24px | `--danger` |
| Intermediate wallet | Circle, 16px | `--text-secondary` |
| Bridge contract | Diamond, 20px | `--chart-3` (blue) |
| CEX hot wallet | Hexagon, 22px | `--warning` |
| Mixer | Triangle, 18px | `--tier-critical-fg` |
| Unknown contract | Square, 14px | `--text-tertiary` |

**Edge encoding:**
- Width: proportional to USD value (1px = $100k)
- Color: fades from source node color to target
- Animated: a moving dot travels along each edge (direction = fund flow)
- Confirmed edges: solid; suspected edges: dashed

**Interaction:**
- Click node → opens wallet detail in right sidebar
- Hover node → tooltip with address, total received, total sent, chain
- Scroll → zoom
- Drag → pan
- Double-click node → expand its connections

**Chain color-coding for node border:**
- Ethereum: `#627EEA`
- Arbitrum: `#28A0F0`
- Base: `#0052FF`
- BSC: `#F3BA2F`
- Solana: `#9945FF`

#### Wallet Detail Sidebar (320px)

Activated on node click:

```
WALLET DETAIL

0x7f3a...c901
[ Copy ]  [ Explorer → ]

CHAIN        Ethereum
TYPE         EOA
BALANCE      4,217,440 USDC

TOTAL IN     $4,217,440
TOTAL OUT    $4,217,440

INBOUND TRANSACTIONS
→ 0x4c2a...81de   $4.2M   14m ago

OUTBOUND TRANSACTIONS
← 0xa91b...33cc   $4.2M   13m ago

STATUS
● TRACKED — moved to Arbitrum
```

---

### Page 6: Legal Package

**Purpose:** Produce a court-ready document bundle in one click.**

#### Layout

Two-pane: document list left, preview right.

```
┌──────────────────────┬──────────────────────────────────────┐
│  LEGAL PACKAGE       │                                      │
│  INC-2024-0312       │     DOCUMENT PREVIEW                 │
│                      │                                      │
│  ✓ Chain of Custody  │  [Rendered PDF preview in iframe]    │
│  ✓ Wallet Graph      │                                      │
│  ✓ Exchange Deposits │                                      │
│  ✓ Jurisdiction Note │                                      │
│  ✓ FBI IC3 Template  │                                      │
│  ✓ Europol EC3 Form  │                                      │
│                      │                                      │
│  [ EXPORT BUNDLE ]   │                                      │
│  [ SHARE WITH COUNSEL]                                      │
└──────────────────────┴──────────────────────────────────────┘
```

Each document in the list: status badge (`GENERATED` / `PENDING` / `REQUIRES INPUT`), name, page count.

Export button produces a password-protected ZIP. Share with Counsel generates a time-limited signed URL.

---

### Page 7: Live Demo / Simulation

**Purpose:** A fully self-contained, scripted simulation of Ghost responding to a real exploit — runnable by anyone, including judges, investors, and protocol evaluators, with no live credentials required. This page exists both inside the app (accessible from the sidebar) and as a standalone public URL for sharing.

**Design principle:** The demo must feel like watching a real incident unfold, not a slideshow. Everything happens in real time with realistic delays. The operator can intervene at approval gates exactly as they would in a real incident.

---

#### Layout

Full-screen takeover. Sidebar collapses to icon-only during demo mode. A persistent demo banner replaces the top bar.

```
┌──────────────────────────────────────────────────────────────────────┐
│  ◈ DEMO MODE  ·  Simulating: Euler Finance Exploit · Apr 14 2023     │
│  [  ▶ RUNNING  ]  Elapsed: 00:01:47   [  ‖ Pause  ]  [  ↺ Reset  ]  │
└──────────────────────────────────────────────────────────────────────┘
```

Below the banner, the full Incident Detail page renders live — the same three-pane layout (Summary / Timeline / Action Queue) — but driven entirely by the simulation engine.

---

#### Demo Selection Screen (pre-launch)

Before the simulation starts, a full-screen modal lets the operator choose which exploit to simulate:

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│   ◈  GHOST SIMULATION                                               │
│   Select an exploit scenario to simulate                            │
│                                                                     │
│   ┌──────────────────────┐  ┌──────────────────────┐               │
│   │  EULER FINANCE       │  │  RONIN BRIDGE        │               │
│   │  Apr 14 2023         │  │  Mar 29 2022         │               │
│   │  $197M · Flash loan  │  │  $625M · Validator   │               │
│   │  ● Canonical case    │  │  ○ Cross-chain       │               │
│   └──────────────────────┘  └──────────────────────┘               │
│                                                                     │
│   ┌──────────────────────┐  ┌──────────────────────┐               │
│   │  CURVE FINANCE       │  │  CUSTOM SCENARIO     │               │
│   │  Jul 30 2023         │  │  Define your own     │               │
│   │  $62M · Reentrancy   │  │  protocol + amount   │               │
│   │  ○ Reentrancy path   │  │  ○ Advanced          │               │
│   └──────────────────────┘  └──────────────────────┘               │
│                                                                     │
│   SIMULATION SPEED                                                  │
│   ○ Real-time (events at actual intervals — most realistic)         │
│   ● Accelerated 10× (recommended for demos)                         │
│   ○ Instant (skip to final state — for reviewing output)            │
│                                                                     │
│   [  LAUNCH SIMULATION  ]                                           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

Cards: `--bg-surface`, `--border-default`. Selected card: `--signal` border (2px), `--bg-raised` background. "Canonical case" badge on Euler — that's the MVP demo scenario.

---

#### Simulation Timeline (center pane)

The core of the demo. Events appear one by one with realistic timing. Each event animates in from the bottom — slides up 8px + fades in over 200ms. No event renders instantly; there's always a visible processing delay to sell the "machine working" feel.

**Scripted event sequence (Euler Finance scenario, 10× speed):**

```
T+0:00   ● ANOMALY DETECTED
         Transaction 0x47f3...881c scored 7/12 signals
         FL · OC · DG · WA · GAS · TT · RP
         Confidence: NONE → initiating confirmation pipeline...

         [Spinning indicator — 1.2s pause]

T+0:04   ● CONFIRMATION 1/3: RESERVE DRAIN SIMULATION
         Running eth_call fork via Tenderly...
         USDC reserve: $197,000,000 → $0 (-100%)
         ✓ Confirmed

T+0:06   ● CONFIRMATION 2/3: ABI INTENT CHECK
         Called function: donateToReserves() — sanctioned exit function
         ✓ Confirmed

T+0:08   ● CONFIRMATION 3/3: ECONOMIC INVARIANT CHECK
         Input: 1,000 USDC
         Expected output: ≤1,050 USDC
         Actual output: 8,877,507 USDC
         Ratio: 8,877× (threshold: 1.05×)
         ✓ Confirmed — invariant violated

         [Brief pause — tier escalation moment]

T+0:10   ████ CONFIDENCE TIER: CRITICAL
         [Viewport glow activates — slow red pulse begins]
         All response modules engaged

T+0:12   ● ATTACKER PROFILE GENERATED
         Funding: Binance withdrawal → 0x4c2a...81de (7 days prior)
         Skill tier: Advanced
         Estimated jurisdiction: Eastern Europe
         Test transactions: 3 prior probing txs confirmed
         First-seen RPC node: Frankfurt, DE

T+0:18   ● FUND MOVEMENT #1 DETECTED
         0xb13d...881c → 0x00000...Euler (donation exploit)
         197,740,000 DAI extracted

T+0:24   ● FUND MOVEMENT #2 DETECTED
         0xb13d...881c → Uniswap V3 (DAI → WETH swap)
         197,740,000 DAI → 85,811 WETH

T+0:31   ● BRIDGE EXIT DETECTED
         0xb13d...881c → Stargate Bridge → Arbitrum
         85,811 WETH departing Ethereum mainnet

T+0:44   ● CEX DEPOSIT DETECTED ← [HIGHLIGHT — this is the key moment]
         Funds entered Binance hot wallet 0x3f5c...9a2b
         Freeze window: OPEN
         Freeze request drafted automatically

         ┌─────────────────────────────────────┐
         │  ⚠ ACTION REQUIRED                  │
         │  Freeze request ready for Binance.  │
         │  Review and send within 4 hours.    │
         │  [ REVIEW FREEZE REQUEST → ]        │
         └─────────────────────────────────────┘

T+0:51   ● BOUNTY CONTRACT READY
         Offer: Return 90%, keep $19.7M as bounty
         Decay: 5% per 24h
         Deploy to 0xb13d...881c?
         [ DEPLOY BOUNTY CONTRACT → ]

T+0:58   ● LEGAL PACKAGE GENERATED
         6 documents · 34 pages
         FBI IC3 template · Europol EC3 form
         Jurisdiction: Eastern Europe (Medium confidence)
         [ VIEW LEGAL PACKAGE → ]

T+1:02   ● SEAL NOTIFIED
         Structured incident report dispatched
         Message sent to: SEAL Slack channel, Rekt News

T+1:09   ● ALERT EMAIL SENT
         Notified 3 recipients at CRITICAL tier
         evans@mistlabs.io · security@protocol.xyz · counsel@lawfirm.com

T+1:14   ● SIMULATION COMPLETE
         Total elapsed: 1 min 14 sec
         End-to-end response time: 74 seconds
         [  VIEW FULL REPORT  ]  [  RESET  ]  [  SHARE THIS DEMO  ]
```

At `SIMULATION COMPLETE`, a summary card slides up from the bottom of the screen:

```
┌─────────────────────────────────────────────────────────────────┐
│  GHOST RESPONSE SUMMARY                                         │
│  Euler Finance · INC-SIM-EULER-001                              │
│                                                                 │
│  Detection to legal package:    74 seconds                      │
│  Detection to freeze request:   44 seconds                      │
│  Wallet hops tracked:           3                               │
│  CEX deposit detected:          ✓ Binance                       │
│  False positives on $500k bridge: 0                             │
│                                                                 │
│  Manual equivalent:  Approx. 2–3 hours (industry average)      │
│  Ghost:              74 seconds                                 │
│                                                                 │
│  [  VIEW LEGAL PACKAGE  ]  [  SHARE DEMO LINK  ]  [  RESET  ]  │
└─────────────────────────────────────────────────────────────────┘
```

---

#### Interactive Approval Gates During Demo

At `T+0:44` (freeze request) and `T+0:51` (bounty contract), the simulation **pauses and waits for the operator** to interact with the approval gate — exactly as it would in a real incident. The demo does not auto-proceed past these gates.

This is intentional. It lets the demo runner walk a judge through the approval flow hands-on. The judge can click "Review Draft," read the freeze request, and hit Confirm themselves. They feel the product, they don't just watch it.

If no interaction occurs within 30 seconds, a subtle prompt appears: "Waiting for operator approval — click to proceed." The demo never auto-approves.

---

#### False Positive Proof (built into demo)

At `T+0:38`, while the attacker's funds are moving, a second transaction appears in the Live Feed simultaneously:

```
T+0:38   ◎ LARGE TRANSFER — CLEARED
         0xWhale...44ab transferred $500,000 USDC via Hop Bridge
         Score: 1/12 — GAS anomaly only
         ABI intent: bridge() — sanctioned exit function → CLEARED
         No confirmation pipeline triggered
```

This row appears in the feed at `--text-tertiary` opacity, tagged `✓ CLEAR`. It proves Ghost doesn't false-positive on large legitimate transfers — directly addressing the 30-day MVP requirement. Point it out explicitly during the presentation.

---

#### Shareable Demo URL

The "Share Demo Link" button generates a public URL:

```
ghost.security/demo?scenario=euler&speed=10x&token=abc123
```

- No login required to view
- Runs the same scripted simulation
- Approval gates still require interaction (judges can try it themselves after the presentation)
- Link expires in 7 days
- View count shown to the protocol: "Viewed 14 times"

This URL is the leave-behind after the pitch.

---

### Page 8: Configuration

**Purpose:** Define monitored protocols, detection thresholds, notification targets, and approval gates.

#### Sections

**Monitored Protocols:**

Table: Protocol name, contract addresses (comma-separated), start block, monitoring status (active/paused). Add/remove rows inline.

**Detection Thresholds:**

Form with range sliders and numeric inputs:

```
Minimum anomaly score to flag          [ ─────●──── ]  2
Minimum anomaly score for MEDIUM tier  [ ──────●─── ]  4
Minimum anomaly score for HIGH tier    [ ────────●── ]  6
Economic invariant violation threshold [ ───●─────── ]  5%
Reserve drain minimum percentage       [ ────●────── ]  20%
```

**Notification Targets:**

Webhook URL, SEAL API key, Rekt submission token. Masked inputs. Test button next to each.

**Alert Email Recipients:**

Operators add email addresses that receive incident alerts. Emails are sent at configurable confidence tiers — not every flagged transaction, only escalations that matter.

```
ALERT EMAIL RECIPIENTS
─────────────────────────────────────────────────────────────

  NAME                  EMAIL                     NOTIFY AT      STATUS
  ─────────────────────────────────────────────────────────────
  Evans O.              evans@mistlabs.io         HIGH+          ● Active
  Security Team         security@protocol.xyz     MEDIUM+        ● Active
  Legal Counsel         counsel@lawfirm.com       CRITICAL only  ● Active
  Backup SOC            soc@protocol.xyz          HIGH+          ○ Paused

  [ + ADD RECIPIENT ]
  ─────────────────────────────────────────────────────────────
  Test emails will be sent from: alerts@ghost.security
```

**Add Recipient drawer** (slides in from right, 400px):

```
ADD ALERT RECIPIENT
───────────────────────────────────────

Name
[ Evans O.                            ]

Email Address
[ evans@mistlabs.io                   ]

Notify at confidence tier
  ○ LOW and above
  ○ MEDIUM and above
  ● HIGH and above
  ○ CRITICAL only

Alert types
  ✓ Exploit detected
  ✓ Confidence tier escalation
  ✓ Fund movement (CEX deposit)
  ✓ Approval action required
  ○ Bounty contract response
  ○ Daily digest (no active incident)

[ SAVE RECIPIENT ]    [ Cancel ]
───────────────────────────────────────
```

Email row interactions:
- Hover row → shows **Edit** and **Remove** inline actions (right-aligned, `--text-tertiary`, appear on hover only)
- **Paused** recipients are visually dimmed (60% opacity). Toggling paused/active requires no confirmation — it's reversible.
- **Remove** opens a single-line inline confirmation within the row: "Remove evans@mistlabs.io? [Confirm] [Cancel]" — no modal for a non-destructive action like this
- **Test** button (accessible via the Edit drawer) sends a sample MEDIUM-tier incident email immediately

Email content spec (what each alert email contains):

```
Subject: [GHOST ALERT] CRITICAL — Euler Finance exploit detected · $4.2M at risk

Body:
  Incident:   INC-2024-0312
  Protocol:   Euler Finance
  Tier:       CRITICAL
  Amount:     $4,217,440 USDC
  Time:       Apr 21 2026 · 03:47 UTC
  Attacker:   0x7f3a...c901

  Status:     Fund tracking active — 2 hops detected
              CEX deposit pending confirmation

  Actions required:
  → Freeze request drafted — awaiting approval
  → Bounty contract ready — awaiting approval

  [ OPEN INCIDENT IN GHOST → ]

  ─────────────────────────────
  Sent by Ghost · Mist Labs
  Manage alert preferences →
  Unsubscribe this address →
```

Email is plain-text first, HTML fallback. No images, no tracking pixels. The "OPEN INCIDENT IN GHOST" link is a signed time-limited URL (24h expiry) that deep-links directly to the incident detail page — no login friction for on-call responders who may be opening this from their phone at 3 AM.

**Unsubscribe handling:** Each email footer contains a one-click unsubscribe link. Clicking it pauses that recipient in the Ghost UI (does not delete the entry). The operator sees a banner in the Recipients table: "security@protocol.xyz unsubscribed via email link. [Re-enable]"

**Approval Gate Settings:**

Toggle: Require human approval for bounce deployment (default: ON)  
Toggle: Require human approval for freeze requests (default: ON)  
Toggle: Auto-notify SEAL at HIGH confidence (default: ON)  
Input: Approval gate timeout (default: 60s, range: 30–300s)

Warning banner when both human approval toggles are OFF: "Ghost will act autonomously. Review your liability posture before disabling approvals."

---

## 4. Components

### 4.1 Confidence Tier Badge

```
┌─────────────────────┐
│  ● CRITICAL         │
└─────────────────────┘
```

Pill badge. 6 variants (none/low/medium/high/critical + loading).

```css
.tier-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 3px 10px;
  border-radius: 2px;
  font: 500 11px/1 var(--font-body);
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.tier-badge--critical {
  background: var(--tier-critical);
  color: var(--tier-critical-fg);
  box-shadow: var(--tier-critical-glow);
}

.tier-badge__dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: currentColor;
  animation: pulse 2s ease-in-out infinite;
}
```

### 4.2 Hash Display

All wallet addresses and transaction hashes rendered as:

```
0x7f3a...c901
```

Component: `<HashDisplay hash="0x7f3a4b..." chars={4} />`

- Font: `--font-mono`, 12–13px
- Color: `--text-secondary` by default; `--signal` when actively involved in current incident
- Click: copies full hash to clipboard, shows 1.5s "Copied" confirmation
- Hover: shows full hash in tooltip (positioned above to avoid obscuring table rows)
- Optional chain indicator dot (colored by chain) prepended

### 4.3 Signal Tag

Inline pill for anomaly signal codes:

```
[FL] [OC] [DG] [GAS]
```

```css
.signal-tag {
  display: inline-flex;
  align-items: center;
  height: 18px;
  padding: 0 6px;
  border-radius: 2px;
  background: rgba(255,255,255,0.06);
  border: 1px solid var(--border-default);
  font: 500 10px/1 var(--font-mono);
  color: var(--text-secondary);
  letter-spacing: 0.04em;
}
```

Full signal code legend always accessible via `?` icon in the feed header.

### 4.4 Live Update Row

Table rows that receive live data updates:

When a value changes: background flashes from `--signal-dim` to transparent over 150ms. Never animates if the value is the same.

```css
@keyframes liveFlash {
  0%   { background: var(--signal-dim); }
  100% { background: transparent; }
}

.row--updated {
  animation: liveFlash 150ms var(--ease-snap) forwards;
}
```

### 4.5 Approval Gate Button

The single most critical UI component in the product. Used for freeze requests, bounty deployment, SEAL notifications.

```
┌────────────────────────────────────────────┐
│  SEND FREEZE REQUEST TO BINANCE            │
│                                            │
│  Review the draft before proceeding.       │
│  This action cannot be undone.             │
│                                            │
│  ╭────────────────────────────────────╮   │
│  │  [  CONFIRM SEND  ]                │   │
│  │       ○○○○○○○○○○○○○ 47s            │   │
│  ╰────────────────────────────────────╯   │
│                                            │
│  [ Cancel ]                                │
└────────────────────────────────────────────┘
```

The timer ring is an SVG circle with `stroke-dasharray` animation. Operator must click Confirm before the timer expires. If it expires without action, the gate resets (does not auto-fire).

The confirm button is only clickable (not disabled) after the operator has **scrolled through the full draft** — tracked via scroll position in the preview.

### 4.6 Alert Recipients Table

The `<AlertRecipients />` component used on the Configuration page.

**States:**

| State | Treatment |
|---|---|
| Active row | Default — name in `--text-primary`, email in `--text-secondary` |
| Paused row | 60% opacity, status dot `--text-tertiary` |
| Unsubscribed row | Amber left border (2px), `--warning` status dot, small "Unsubscribed via email" label |
| Hover row | `--bg-hover` background, Edit + Remove buttons appear |
| Empty state | "No recipients added. Ghost will log all alerts but not send emails." |

**Tier selector in the Add/Edit drawer:**

Four options rendered as a segmented control (not a dropdown — tier selection is a primary decision that benefits from all options being visible):

```
[ LOW+ ]  [ MEDIUM+ ]  [ HIGH+ ]  [ CRITICAL ]
```

Selected option: `--bg-selected` background, `--signal` bottom border (2px). Unselected: `--bg-surface`.

**Alert type checkboxes:**

Standard checkbox group. Checkboxes use a custom style:
```css
.checkbox {
  width: 14px;
  height: 14px;
  border: 1px solid var(--border-strong);
  border-radius: 2px;
  background: var(--bg-surface);
}

.checkbox:checked {
  background: var(--signal);
  border-color: var(--signal);
}
```

Checkmark: an SVG `✓` in `--text-inverse` at 10px.

**Send test email flow:**

1. Operator clicks "Send Test Email" in the Edit drawer
2. Button enters loading state (spinner, label: "Sending…")
3. On success: button turns green for 2s ("Sent ✓"), then resets
4. On failure: button turns red ("Failed — check address"), inline error below input

### 4.7 Viewport Confidence Glow

The signature Ghost effect. A box-shadow on the document body that pulses in the color of the current active incident's confidence tier.

```css
body {
  transition: box-shadow var(--dur-breath) ease-in-out;
}

body.tier--critical {
  box-shadow: inset 0 0 80px rgba(255, 36, 66, 0.08),
              inset 0 0 200px rgba(255, 36, 66, 0.04);
  animation: criticalBreath var(--dur-breath) ease-in-out infinite alternate;
}

@keyframes criticalBreath {
  from { box-shadow: inset 0 0 80px rgba(255, 36, 66, 0.06); }
  to   { box-shadow: inset 0 0 80px rgba(255, 36, 66, 0.14); }
}
```

Only active when an incident is open. Clears to neutral when no active incident.

### 4.7 Transaction Feed Row

The atomic unit of the live anomaly feed:

```
[ SCORE ] [ HASH ] [ PROTOCOL ] [ SIGNALS ] [ TIME ] [ STATUS ] [ ⋯ ]
    7      0x7f3a…    Euler       FL OC DG    0:04s    ⚠ CONFIRM
```

Row height: 40px. Monospace for hash and score. Standard body for the rest.

Status column values:
- `⚠ CONFIRM` — awaiting operator confirmation (`--warning`)
- `● ACTIVE` — confirmed, Ghost responding (`--danger`)
- `◎ WATCH` — below threshold, monitoring (`--text-secondary`)
- `✓ CLEAR` — confirmed false positive (`--text-tertiary`)
- `✓ RESOLVED` — incident closed (`--success`)

### 4.8 Protocol Avatar

16px or 24px circle with protocol's favicon/logo. Falls back to a geometric hash-based placeholder (consistent color and shape generated from the contract address). Never shows broken image states.

### 4.9 Chain Badge

Tiny inline badge indicating which blockchain:

```
[ETH]  [ARB]  [BASE]  [BSC]  [SOL]
```

Color-coded to chain palette (see Fund Tracker node colors). 10px monospace, 2px radius.

### 4.10 Empty State

When no incidents are active:

```
         ◈

    ALL CLEAR

Ghost is monitoring 3 protocols.
No anomalies in the last 24 hours.

[ View Configuration ]
```

The Ghost icon `◈` in `--signal` green. Everything else in `--text-tertiary`. No illustration, no mascot, no clipart.

---

## 5. Data Visualization Specifications

### 5.1 Anomaly Score History Chart

Type: Area chart  
Library: Recharts (React) or D3 (vanilla)

```
x-axis: 24-hour timeline, labeled every 4 hours (00:00, 04:00, etc.)
y-axis: Score 0–12, labeled at 0, 4, 8, 12
Area fill: --signal, opacity 0.15 → 0
Line stroke: --signal, 1.5px
Dots: only shown on hover
Threshold lines:
  y=2: dashed, --tier-low-fg, labeled "MEDIUM TRIGGER"
  y=5: dashed, --tier-high-fg, labeled "HIGH TRIGGER"
Incident markers: vertical dashed line at exploit time, --danger
```

Tooltip on hover: time, score, signals active. Monospace font for all values.

### 5.2 Fund Flow Sankey (in Legal Package)

Shows total funds: protocol reserve → attacker wallet → intermediate wallets → destinations.

```
Protocol Reserve ████████████████████ $4.2M
                 ↘
Attacker Wallet  ████████████████████ $4.2M
                 ↘
Intermediate     ████████████████████ $4.2M
                 ↘
Binance Deposit  ████████████████████ $4.2M
```

Left labels in `--text-secondary`. Bar fill in `--chart-1` to `--chart-5`. Node widths proportional to amount.

### 5.3 Confidence Timeline

Small horizontal timeline shown in the Incident Summary panel:

```
NONE → LOW → [MEDIUM] → HIGH → CRITICAL
 ○──────○──────●
              ▲
          current
```

Circle + line. Reached tiers: `--signal` fill. Unreached: `--border-default`. Current: pulsing dot.

---

## 6. Responsive Behavior

Ghost is a professional ops tool, not a consumer app. Mobile is not the primary surface, but a tablet view (1024px) must be functional.

### Breakpoints

| Name | Width | Changes |
|---|---|---|
| Desktop | ≥1280px | Full three-column layout |
| Laptop | 1024–1279px | Context rail collapses to drawer |
| Tablet | 768–1023px | Sidebar collapses to icon-only (48px); context rail becomes bottom drawer |
| Mobile | <768px | Sidebar becomes bottom tab bar; single-column; Fund graph replaced with list |

### Priority at reduced widths

1. Active incident status always visible
2. Approval gate always full-width and accessible
3. Fund tracker graph degrades to wallet movement list
4. Timeline always accessible
5. Legal package export always accessible

---

## 7. Accessibility

### Keyboard Navigation

- Tab order follows visual order left-to-right, top-to-bottom
- All interactive elements reachable by keyboard
- Approval gate requires explicit keyboard confirmation (Enter key after focusing button, not accidental)
- Live feed updates announced via `aria-live="polite"` region
- Critical tier incidents announced via `aria-live="assertive"`

### Color Independence

All confidence tiers communicated with:
1. Color (background + foreground)
2. Icon/symbol (●, ⚠, ○, ✓)
3. Text label (CRITICAL, HIGH, etc.)

No information conveyed by color alone.

### Contrast Ratios

- `--text-primary` on `--bg-surface`: 12.4:1 ✓
- `--text-secondary` on `--bg-surface`: 5.8:1 ✓
- `--signal` on `--bg-void`: 8.7:1 ✓
- `--tier-critical-fg` on `--tier-critical`: 6.2:1 ✓

### Focus Styles

```css
:focus-visible {
  outline: 2px solid var(--signal);
  outline-offset: 2px;
  border-radius: 2px;
}
```

---

## 8. Iconography

No icon libraries. Ghost uses a minimal set of custom geometric icons:

| Name | Description | Usage |
|---|---|---|
| `◈` | Rotated diamond — Ghost mark | Logo, empty states |
| `●` | Filled circle | Active/live status |
| `○` | Empty circle | Inactive/pending status |
| `⊕` | Circle plus | Add, expand |
| `⊗` | Circle cross | Remove, dismiss |
| `↗` | Diagonal arrow | External link |
| `→` | Right arrow | Navigation, next |
| `⋯` | Ellipsis | More actions |
| `▾` | Down caret | Dropdown |

All icons are inline SVG, 16×16 viewport, `currentColor` fill. No icon font. No PNG/JPG icons.

For chain logos (ETH, ARB, etc.) and exchange logos (Binance, Coinbase) — official brand SVGs only, never approximate.

---

## 9. Microcopy & Tone

Ghost's interface copy must match the product's identity: precise, serious, no marketing fluff.

**Rules:**
- Action labels are verbs: "Send Freeze Request" not "Freeze Request"
- Error states name the exact failure: "RPC connection lost: alchemy.com" not "Connection error"
- Confirmation dialogs state the consequence: "This will send an email to Binance Compliance. You cannot unsend it." not "Are you sure?"
- Empty states tell the operator what Ghost is doing: "Monitoring 3 protocols. No anomalies detected." not "Nothing here yet 👀"
- No emoji in operational UI
- All timestamps in ISO-style: "Apr 21 2026 · 03:47 UTC" not "14 minutes ago" (except in feed relative time where freshness matters)
- Dollar amounts: always with 2 decimal places minimum, comma-separated, prefixed with `$`
- Blockchain addresses: always truncated to first 4 and last 4 characters in display; full hash in tooltip and copy

**Forbidden words in UI:**
- "Amazing", "Powerful", "Revolutionary" — this is a professional tool
- "Oops" or emoji for errors — this is an incident response system
- "Soon", "Coming soon" — either it works or it's not in the UI

---

## 10. Component States Reference

Every interactive component in Ghost must implement all these states:

| State | Visual Treatment |
|---|---|
| Default | Base design |
| Hover | `--bg-hover` background OR `--border-strong` border |
| Focus | `--signal` outline, 2px, offset 2px |
| Active/Pressed | 5% darker than hover |
| Selected | `--signal` left border (2px), `--bg-selected` background |
| Disabled | 40% opacity, `cursor: not-allowed` |
| Loading | Skeleton shimmer (animated gradient) OR spinner (16px circle, `--text-tertiary`) |
| Error | `--danger` border, error message below in `--danger` 12px |
| Success | `--success` border for 1.5s then returns to default |
| Live/Updating | Green flash (see §4.4) |

---

## 11. File & Asset Structure

```
ghost-frontend/
├── app/
│   ├── layout.tsx              ← Root layout, sidebar, top bar
│   ├── page.tsx                ← Dashboard overview
│   ├── incidents/
│   │   ├── page.tsx            ← Incident list
│   │   └── [id]/page.tsx       ← Incident detail
│   ├── attacker/[id]/page.tsx  ← Attacker profile
│   ├── tracker/[id]/page.tsx   ← Fund tracker
│   ├── legal/[id]/page.tsx     ← Legal package
│   ├── freeze/page.tsx         ← Freeze request management
│   ├── bounty/page.tsx         ← Bounty contracts
│   └── config/page.tsx         ← Configuration
├── components/
│   ├── ui/                     ← Design system primitives
│   │   ├── Badge.tsx           ← Confidence tier badge + general badges
│   │   ├── HashDisplay.tsx     ← Address/hash truncation + copy
│   │   ├── SignalTag.tsx        ← Anomaly signal pill
│   │   ├── ChainBadge.tsx      ← Chain indicator
│   │   ├── Button.tsx          ← All button variants
│   │   ├── Input.tsx           ← Form inputs
│   │   ├── Table.tsx           ← Base table primitives
│   │   └── Tooltip.tsx         ← Hover tooltips
│   ├── demo/
│   │   ├── page.tsx                ← Demo selection screen
│   │   └── [scenario]/page.tsx     ← Live simulation view
│   ├── demo/
│   │   ├── ScenarioSelector.tsx    ← Pre-launch modal with scenario cards
│   │   ├── SimulationEngine.tsx    ← Scripted event sequencer
│   │   ├── SimulationBanner.tsx    ← Top bar with play/pause/reset controls
│   │   ├── SimulationSummary.tsx   ← End-state summary card
│   │   └── scenarios/
│   │       ├── euler.ts            ← Euler Finance event script
│   │       ├── ronin.ts            ← Ronin Bridge event script
│   │       └── curve.ts            ← Curve Finance event script
│   ├── config/
│   │   ├── AlertRecipients.tsx     ← Email recipient table + add/edit drawer
│   │   ├── RecipientDrawer.tsx     ← Slide-in form for add/edit
│   │   └── TierSelector.tsx        ← Segmented control for notification tier
│   ├── layout/
│   │   ├── Sidebar.tsx
│   │   ├── TopBar.tsx
│   │   └── ContextRail.tsx
│   ├── incident/
│   │   ├── IncidentSummary.tsx
│   │   ├── IncidentTimeline.tsx
│   │   ├── ActionQueue.tsx
│   │   └── ApprovalGate.tsx
│   ├── feed/
│   │   ├── LiveFeed.tsx
│   │   └── FeedRow.tsx
│   ├── tracker/
│   │   ├── FundGraph.tsx       ← D3 force graph
│   │   └── WalletDetail.tsx
│   ├── attacker/
│   │   ├── ProfileCard.tsx
│   │   └── FundingTrace.tsx
│   └── charts/
│       ├── AnomalyChart.tsx
│       └── FundSankey.tsx
├── styles/
│   ├── tokens.css              ← All CSS custom properties (§1)
│   ├── typography.css          ← Font imports, type scale
│   ├── reset.css
│   └── globals.css
├── lib/
│   ├── rpc.ts                  ← WebSocket RPC connection
│   ├── scoring.ts              ← Anomaly score display logic
│   └── format.ts               ← Currency, address, timestamp formatters
└── public/
    └── fonts/                  ← Self-hosted Geist + Geist Mono
```

---

## 12. Design Decisions Log

| Decision | Rationale |
|---|---|
| No gradient backgrounds | Ghost is a forensic tool. Gradients signal consumer product. |
| Acid green (`#00E676`) as sole accent | Maximum legibility on dark. Associated with terminals and data — appropriate for a security product. Avoids the generic blue of SaaS and the purple of DeFi. |
| Syne for display | Heavy, architectural, but not aggressive. Legible at large sizes. Distinctive without being tryhard. |
| No rounded cards (2–6px max) | Sharp edges reinforce precision. High-stakes tooling should not feel approachable. |
| Viewport glow as confidence indicator | The most peripheral vision-friendly alert. You feel the severity before you read it. |
| Hash truncation always 4+4 | Balance between recognizability and space. 4+4 allows visual distinction between addresses without requiring full display. |
| No color-only encoding | Security tool used under pressure. Operators may be using a bad monitor or be colorblind. |
| 60-second approval gate with scroll requirement | The two most dangerous things in incident response: not acting fast enough, and acting without reading. The gate forces both speed and attention simultaneously. |
| Email over Telegram for alerts | Telegram bot setup introduces an external dependency and an OAuth flow that's a barrier during incident setup. Email works with zero integration — every responder already has it, it's reachable on mobile, and the signed deep-link URL gets the operator into the incident in one tap. |
| Per-recipient tier thresholds | Not everyone on the list needs every alert. Legal counsel doesn't need LOW-tier anomaly pings. The on-call engineer does. Per-recipient thresholds prevent alert fatigue without reducing coverage. |
| Unsubscribe pauses, doesn't delete | If a recipient unsubscribes via email footer during an incident (e.g. wrong address, accidental), the operator needs to see that it happened and be able to re-enable it. Silent deletion would create invisible coverage gaps. |

---

*Ghost Design System v1.0 — Mist Labs*  
*All dimensions in px unless noted. 8pt grid throughout.*
