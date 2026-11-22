# Sentinel — Threat Intelligence Delivery Report

## Executive summary

A complete, independently runnable vertical slice for the Threat Intelligence and MITRE ATT&CK area has been implemented. The service enriches indicators, creates an evidence bundle for downstream agent and severity decisions, maps alerts to MITRE ATT&CK techniques, stores indicator history, and exposes a dashboard-ready API. It is intentionally safe to run before the rest of the team components exist: provider keys are optional, the demo mode is explicit in provenance, and the API contract is stable for later replacement by live adapters.

## Delivered scope mapped to the plan

| Plan item | Delivery | Evidence |
|---|---|---|
| R1 VirusTotal client | Async adapter for IP/domain/URL/hash, timeout and redacted failure handling | `providers.py`, provenance field |
| R2 Quota governor and cache | Per-provider quota guard plus SQLite TTL cache | `providers.py`, `db.py`, cache hit verified live |
| R3 AbuseIPDB and GeoIP | AbuseIPDB adapter and GeoIP adapter seam with safe demo fallback | `providers.py` |
| R4 Enrichment service | Parallel provider calls and normalized evidence bundle | `POST /api/v1/enrich` |
| R5 MITRE ATT&CK loader | Local technique catalog, technique lookup and Navigator layer output | `mitre.py`, `/api/v1/coverage/layer` |
| R6 Attack-to-technique mapping | Rule/alert text normalization to ATT&CK IDs | `POST /api/v1/map-alert` |
| R7 Coverage analysis | Covered/total matrix with technique metadata | `GET /api/v1/coverage` |
| R8 Indicator store | Deduplication, first/last seen, count, freshness and export-ready JSON | `db.py`, `/api/v1/indicators` |
| R9 Dashboard | Lightweight live dashboard consuming the same APIs | `/dashboard` |

## Architecture and integration

The service is a small FastAPI application designed to sit beside the pipeline, agent, dashboard and GRC services. `POST /api/v1/enrich` is the shared Evidence Bundle contract. Every result includes reputation, confidence, geo fields, techniques, history, freshness and provider provenance. No API key or raw provider response is returned or persisted.

The implementation supports live provider keys through environment variables. When keys are absent, it returns clearly labelled `demo` evidence rather than pretending the result is live. This makes the component usable in local CI and integration rehearsals while preserving a clean production path.

## Extra features added

1. **Evidence provenance:** each provider result records `live`, `demo`, `cache`, `skipped` or `error` mode and retrieval time.
2. **Safe stale-cache design:** a cache hit is returned without making a new external request; the response clearly marks freshness.
3. **Bounded inputs:** indicator count, value length and result limits are capped to reduce accidental abuse.
4. **Correlation IDs:** downstream teams can trace the enrichment bundle back to an incident or alert.
5. **Navigator layer export:** the ATT&CK coverage state is ready for import into ATT&CK Navigator.
6. **Contract-first dashboard:** the page uses the same public endpoints that the team's main dashboard can consume later.
7. **Container healthcheck:** Compose can determine whether the service is ready before dependent services start.
