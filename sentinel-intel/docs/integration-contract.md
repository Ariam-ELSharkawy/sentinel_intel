# Ariam Integration Contract

## Evidence bundle
`POST /api/v1/enrich` accepts `{indicators, correlation_id, requested_by}`. Each indicator is `{type: ip|domain|url|hash, value}`.

Response shape:
```json
{
  "correlation_id":"...",
  "generated_at":"ISO-8601",
  "items":[{
    "indicator":{"type":"ip","value":"..."},
    "reputation":{"score":0,"malicious":false,"confidence":0.0,"sources":[]},
    "geo":{"country":null,"asn":null,"organization":null},
    "techniques":[],
    "history":[],
    "freshness":{"cached":false,"expires_at":"..."},
    "provenance":[{"provider":"...","mode":"live|demo|cache","retrieved_at":"..."}],
    "errors":[]
  }]
}
```

The agent may use `reputation.score`, `reputation.confidence`, `techniques`, and `history` as evidence. It must not treat demo mode as live certainty. Severity can use the score and confidence, while the dashboard can use `/api/v1/coverage` and `/api/v1/indicators`.

## Mapping contract
Alerts can send `attack_type`, `rule_id`, `source`, or `techniques`. `POST /api/v1/map-alert` returns normalized ATT&CK technique IDs and names.

## Safety
- No provider secret is returned.
- Raw provider response bodies are not persisted.
- Values are normalized and bounded; indicator values are never executed.
- Quota and timeout failures produce evidence errors and may fall back to unexpired cache.
