# Feature Intel 🔍

Competitive intelligence system that detects unreleased features, hidden products, and upcoming launches across 68+ publicly traded tech companies. Monitors signals that companies **can't hide** — FCC filings, trademark registrations, job postings, JS feature flags, SDK updates, DNS records, arXiv papers, and more.

Alerts sent to Discord via webhook.

## 22 Detection Monitors

| # | Monitor | What It Catches | Signal |
|---|---------|----------------|--------|
| 1 | **JS Bundle Scanner** | Feature flags, A/B tests, hidden UI in web app JavaScript | Upcoming features |
| 2 | **Documentation Diffing** | API doc changes, new models, deprecations | New capabilities |
| 3 | **Sitemap Monitor** | New pages added to sitemaps before public linking | Pre-launch products |
| 4 | **GitHub Releases/PRs** | Open-source releases and feature PRs | Version drops |
| 5 | **iOS App Store** | Version changes + release notes (batch API) | Feature rollouts |
| 6 | **Google Play Store** | Android app updates and changelogs | Feature rollouts |
| 7 | **Chrome Flags** | New experimental flags in Chromium source | Browser features |
| 8 | **Subdomain Discovery** | DNS probing for new subdomains (beta.x.com, labs.x.com) | New products |
| 9 | **Page Change Monitor** | Blogs, changelogs, newsrooms, tech press | Announcements |
| 10 | **FCC Equipment Auth** | New hardware device filings (phones, headsets, etc.) | Hardware launches |
| 11 | **USPTO Trademarks** | New product name registrations months before launch | Product names |
| 12 | **SSL Certificate Transparency** | New HTTPS certs = new services being provisioned | New services |
| 13 | **robots.txt Changes** | Pages blocked from crawlers before launch | Hidden pages |
| 14 | **SEC 8-K Filings** | Material event disclosures (acquisitions, partnerships) | Corporate events |
| 15 | **npm Package Updates** | SDK version bumps leak API features | API changes |
| 16 | **PyPI Package Updates** | Python SDK changes reveal backend capabilities | API changes |
| 17 | **Job Postings** | Hiring for unannounced products (Greenhouse/Lever APIs) | Product direction |
| 18 | **Status Pages** | New internal service names appearing | Upcoming services |
| 19 | **DNS TXT/CNAME Records** | DNS record changes via Google DoH API | Infrastructure |
| 20 | **arXiv Papers** | Research papers from company labs before product ships | R&D direction |
| 21 | **GraphQL Introspection** | New types/mutations/fields in exposed GraphQL APIs | API features |
| 22 | **CDN Asset Discovery** | New images, logos, videos uploaded before pages link them | Product reveals |

## Coverage

**68 tickers monitored:** AAPL, ABNB, ADBE, AI, AMD, AMZN, APP, ARM, AVGO, CFLT, COIN, CRM, CRWD, CSCO, DASH, DBX, DDOG, DOCN, DOCU, DUOL, ESTC, FTNT, GOOGL, GTLB, HCP, HOOD, HUBS, INTC, INTU, IONQ, MDB, META, MSFT, MU, NET, NFLX, NOW, NVDA, OKTA, ORCL, PANW, PATH, PINS, PLTR, PYPL, QCOM, RBLX, RDDT, RGTI, RIVN, ROKU, S, SHOP, SNAP, SNOW, SOUN, SPOT, TEAM, TOST, TSLA, TTD, TWLO, U, UBER, WDAY, XYZ, ZM, ZS

**Plus private companies:** OpenAI, Anthropic, xAI, Perplexity, Stripe, Figma, Notion, Discord, Databricks, Scale AI

**452+ config entries** across all monitors.

## Setup

```bash
pip install -r requirements.txt
```

## Environment Variables

```env
DISCORD_WEBHOOK_URLS=https://discord.com/api/webhooks/...   # Optional, comma-separated additional webhooks
GITHUB_TOKEN=ghp_...                                         # Recommended for 32 repos (rate limits)
CHECK_INTERVAL_MINUTES=30                                    # Scan interval (default 30)
DB_PATH=feature_intel.db                                     # SQLite state database
```

## Usage

```bash
# Run once (baseline + detect)
python feature_intel.py --once

# Run continuously (every 30 min)
python feature_intel.py

# Custom interval
python feature_intel.py --interval 45

# Custom config
python feature_intel.py --config my_config.json
```

## How It Works

1. **First run** stores baselines (hashes) for all monitored targets
2. **Subsequent runs** compare current state against baselines
3. **Changes detected** → Discord alerts with details
4. All state in SQLite — survives restarts
5. Each monitor is independent and error-isolated
6. Progress logging: `[1/22] Running: JS Bundles` → `done in 2.3s`

## Configuration

`config.json` is auto-created on first run with defaults. Edit to add/remove targets.

Many monitors also have hardcoded defaults in the script (FCC grantee codes, SEC CIKs, USPTO owners, npm/PyPI packages, job posting targets, arXiv queries) that run automatically without config entries.

### Adding Targets

```jsonc
// JS Bundle target
{"name": "NewApp (TICK)", "url": "https://app.example.com", "keywords": ["beta", "unreleased"]}

// Doc monitor
{"name": "Company API", "urls": ["https://docs.example.com/changelog"], "keywords": ["new", "model"]}

// GitHub repo
{"name": "Project", "repo": "owner/repo", "watch": ["releases", "prs"], "keywords": ["agent"]}

// iOS app
{"name": "App Name (TICK)", "app_id": "1234567890"}

// Status page
{"name": "Company", "ticker": "TICK", "url": "https://status.example.com/"}
```

## Deploy to Railway

```bash
railway init
railway up
railway variables set GITHUB_TOKEN=ghp_...
railway variables set CHECK_INTERVAL_MINUTES=30
```

## Performance

- Full scan: ~2-4 minutes (452+ targets)
- App Store: batch API (61 apps in 1 call)
- Per-request timeout: 15s
- Per-monitor timing logged
- 30-minute default interval = well within rate limits
