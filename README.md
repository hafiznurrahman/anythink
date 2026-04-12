# 🔍 CSPT Hunter

**Automated Client-Side Path Traversal vulnerability scanner for HackerOne Bug Bounty Programs**

---

## 📋 Table of Contents
- [Installation](#installation)
- [Usage](#usage)
- [Hunting Flow](#hunting-flow)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [Payloads](#payloads)
- [Impact Chains](#impact-chains)

---

## 🛠️ Installation

```bash
# Clone / download project
cd cspt-hunter

# Install dependencies
npm install

# Install Playwright browser
npx playwright install chromium
```

---

## 🚀 Usage

### Demo Mode (no API key needed)
```bash
npm start -- --demo
```

### Live Mode (HackerOne API)
```bash
export H1_API_TOKEN="your_hackerone_api_token"
npm start
```

### With Playwright dynamic testing
```bash
npm start -- --demo --playwright
```

### Start web dashboard
```bash
npm run server
# → open http://localhost:3337
```

### Options
```
--demo          Use demo targets (no H1 API required)
--playwright    Enable dynamic Playwright testing (slower, more accurate)
--max=N         Max programs to scan (default: 5)
```

---

## 🗺️ Hunting Flow

```
Phase 1: HackerOne Scope Scraping
  └─ Scrape BBP programs via GraphQL API / public endpoint
  └─ Extract in-scope URLs (eligible_for_bounty = true)
  └─ Resolve wildcard *.domain.com → subdomain enumeration
  └─ Crawl each base URL for dynamic endpoints

Phase 2: JS Static Analysis
  └─ Download all <script src="..."> from each page
  └─ Apply 15+ regex patterns for fetch/XHR/axios sinks
  └─ Trace source of URL variable (URLSearchParams, location.pathname, etc.)
  └─ Calculate confidence (high/medium/low) based on controllability
  └─ Filter false positives (test files, hardcoded URLs, etc.)

Phase 3: Playwright Dynamic Testing (--playwright flag)
  └─ Launch headless Chromium
  └─ Inject monitoring script (hook fetch + XHR + sendBeacon)
  └─ Inject traversal payloads into all parameters
  └─ Intercept all network requests
  └─ Detect path traversal in outgoing request URLs
  └─ Screenshot evidence if found

Phase 4: Impact Assessment
  └─ Map triggered endpoints to impact chains
  └─ CSRF: POST/DELETE/PUT state-changing endpoints
  └─ XSS: Response contains HTML rendered in DOM
  └─ InfoDisclosure: 200 OK with sensitive data indicators
  └─ AccountTakeover: Auth/token/session endpoints
  └─ SSRF: Internal IP ranges in triggered URL

Phase 5: Report Generation
  └─ Per-program Markdown report (./reports/*.md)
  └─ Aggregate JSON (./reports/all-results.json)
  └─ Local HTML dashboard (http://localhost:3337)
```

---

## 📁 Architecture

```
cspt-hunter/
├── src/
│   ├── types.ts              # TypeScript interfaces
│   ├── config.ts             # Payloads, patterns, sinks
│   ├── scraper.ts            # Phase 1: H1 scraper + crawler
│   ├── analyzer.ts           # Phase 2: JS static analysis
│   ├── playwright-analyzer.ts # Phase 3: Dynamic testing
│   ├── impact.ts             # Phase 4: Impact chaining
│   ├── reporter.ts           # Phase 5: Markdown generator
│   ├── server.ts             # Web dashboard Express server
│   └── index.ts              # Main orchestrator
├── reports/
│   ├── *.md                  # Per-program reports
│   ├── all-results.json      # Aggregate data for dashboard
│   └── screenshots/          # Playwright screenshots
└── package.json
```

---

## ⚙️ Configuration

Edit `src/config.ts` to customize:

```typescript
export const DEFAULT_CONFIG = {
  maxConcurrency: 3,        // Concurrent requests
  requestTimeout: 15000,    // 15 seconds
  headless: true,           // Playwright headless mode
  payloads: [...],          // Traversal payloads
  patterns: [...],          // JS sink regex patterns
  sensitiveEndpoints: [...] // Target endpoint patterns
}
```

---

## 💣 Payloads Used

| Category | Examples |
|----------|---------|
| Basic | `../`, `../../`, `../../../` |
| URL Encoded | `..%2f`, `%2e%2e%2f`, `..%252f` |
| Unicode | `..%c0%af`, `..%ef%bc%8f`, `..%u002f` |
| Filter Bypass | `..;/`, `....//`, `..\/`, `..%09/` |
| Null Byte | `../%00`, `../%00.json` |
| Targeted | `../../admin`, `../../../internal/config` |

---

## 💥 Impact Chains

| Chain | Severity | Trigger |
|-------|----------|---------|
| Account Takeover | CRITICAL | Auth/token/session endpoint reached |
| XSS | HIGH | Response contains HTML rendered in DOM |
| CSRF | HIGH | State-changing endpoint (POST/DELETE/PUT) |
| Info Disclosure | MEDIUM | Sensitive data in 200 OK response |
| SSRF | HIGH | Internal IP range in triggered URL |

---

## 📊 Web Dashboard

After scanning, run:
```bash
npm run server
```

Features:
- **Dashboard**: Stats, severity chart, impact chains, recent findings
- **All Findings**: Filter by severity / chain / search
- **Programs**: Per-program summary
- **MD Reports**: Rendered Markdown reports per program

---

## ⚠️ Legal Disclaimer

This tool is intended for **authorized security research only**.
Only use against programs you have **explicit permission** to test.
Always follow HackerOne's responsible disclosure guidelines.

---

*Built for Bug Hunters by Bug Hunters* 🐛
