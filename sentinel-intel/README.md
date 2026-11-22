# Sentinel Intel — Ariam Vertical Slice

Threat Intelligence and MITRE ATT&CK enrichment service for the Sentinel platform.

## Included
- Parallel indicator enrichment for IPs, domains, URLs and file hashes.
- VirusTotal, AbuseIPDB and GeoIP adapters with timeouts, retries, redacted errors and deterministic demo fallback.
- SQLite cache with TTL, provider quota guard and stale-cache fallback.
- MITRE ATT&CK technique catalog, alert-to-technique mapping, coverage analysis and Navigator layer export.
- Indicator store with deduplication, freshness, expiry and JSON/CSV export.
- Evidence bundle contract consumed by agent, severity engine and dashboard.
- FastAPI REST API plus a lightweight dashboard at `/dashboard`.
- Dockerfile, Compose service, tests and integration contract.

## Run locally
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn intel_service.main:app --app-dir src --host 0.0.0.0 --port 8000
```
Open `http://localhost:8000/dashboard`.

## Demo
```bash
curl -X POST http://localhost:8000/api/v1/enrich   -H 'content-type: application/json'   -d '{"indicators":[{"type":"ip","value":"185.220.101.1"}],"correlation_id":"demo-001"}'
```

## Real providers
Set `VT_API_KEY`, `ABUSEIPDB_API_KEY`, and optionally `GEOIP_ENDPOINT` in `.env`. Without keys the service remains runnable using clearly marked `demo` provider results; no fabricated result is presented as a live lookup.

## Tests
`pytest -q`
