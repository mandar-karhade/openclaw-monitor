# ClawMon

Exposure monitor for OpenClaw instances. Scans IP ranges for services running on port 18789, fingerprints them, enriches with geolocation data, and serves a live dashboard.

## What it does

1. **Port scanning** - Async TCP scan across target CIDR ranges at configurable concurrency (default 500)
2. **Fingerprinting** - HTTP probes to identify OpenClaw instances by title and server header
3. **Geolocation enrichment** - Resolves IP to country, city, provider, and lat/lon via ip-api.com
4. **Dashboard** - FastAPI web app with a live map, provider/country breakdowns, and a searchable instance table
5. **Auto-refresh** - Dashboard polls `/api/stats` every 10 seconds for live updates

## Project structure

```
scripts/
  scan.py          # CLI scanner
  probe.py         # Manual probe utility
src/clawmon/
  main.py          # FastAPI app
  config.py        # Settings (env vars)
  db.py            # SQLite via aiosqlite
  models.py        # Pydantic models
  scanner/
    port_scanner.py   # Async TCP port scanner
    fingerprinter.py  # HTTP fingerprinting
    censys_client.py  # Censys API (optional)
    enricher.py       # ip-api.com geolocation
templates/
  dashboard.html   # Jinja2 template (Leaflet map, Chart.js)
static/
  style.css
```

## Requirements

- Python 3.11+
- No paid APIs required (Censys free tier is optional)

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Copy `.env.example` to `.env` and fill in any optional values:

```bash
cp .env.example .env
```

## Scanning

```bash
# Scan specific CIDR ranges
python scripts/scan.py --targets 10.0.0.0/24 192.168.0.0/16

# Scan from a file (one CIDR per line)
python scripts/scan.py --targets-file targets.txt

# Use Censys free tier for discovery
python scripts/scan.py --censys

# Re-validate existing instances
python scripts/scan.py --revalidate

# Fresh scan (ignore saved subnet progress)
python scripts/scan.py --fresh --targets-file targets.txt
```

Instances are saved to `clawmon.db` as they're found. The dashboard updates in real time during scans.

## Dashboard

```bash
uvicorn clawmon.main:app --port 8000
```

Open `http://localhost:8000`. The dashboard shows:
- Leaflet map with circle markers (red = unsecured, green = secured)
- Exposed instance count
- Bar charts by provider and country
- Searchable, paginated instance table

### API

- `GET /` - Dashboard HTML
- `GET /api/stats` - JSON snapshot of all dashboard data
- `GET /api/enrich` - Trigger geolocation enrichment for unenriched IPs

## Docker deployment

```bash
docker compose up -d --build
```

The compose file runs two services:
- `dashboard` - FastAPI app on port 8000
- `tunnel` - Cloudflare Tunnel sidecar (set `CLOUDFLARE_TUNNEL_TOKEN` in `.env`)

The SQLite database is bind-mounted from `./clawmon.db` into the container at `/data/clawmon.db`.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `DB_PATH` | `clawmon.db` | Path to SQLite database |
| `CENSYS_API_ID` | | Censys free tier API ID |
| `CENSYS_API_SECRET` | | Censys free tier API secret |
| `SCAN_CONCURRENCY` | `500` | Max concurrent TCP connections |
| `SCAN_TIMEOUT` | `3` | TCP connect timeout in seconds |
| `SCAN_RATE_LIMIT` | `2` | HTTP fingerprint requests per second |
| `CLOUDFLARE_TUNNEL_TOKEN` | | Cloudflare Tunnel token for Docker deployment |

## Responsible disclosure

All IPs are masked in the dashboard (last octet replaced with `xxx`). The scanner is intended for security research to measure OpenClaw exposure, not for exploitation.
