# Security and Operations Gotchas

## Goal

Document non-obvious behaviors and operational caveats that can surprise implementers or operators.

## Authentication and Session Gotchas

- Frontend stores only accessToken and user in localStorage.
- API login returns refreshToken, but frontend does not persist or use automatic refresh flow.
- Any 401 response triggers immediate local logout and redirect to login page.

Operational impact:
- Long-lived sessions rely on access token expiration value.
- Refresh endpoint exists but is not currently integrated in frontend session lifecycle.

## Authorization Gotchas

- JWT payload includes role and permissions.
- Backend currently checks authentication, but most routes do not enforce role-based permission gates.

Operational impact:
- Access control is effectively authentication + ownership checks, not full RBAC policy enforcement.

## CORS Gotchas

- Backend has a hardcoded localhost allowlist and GitHub Pages pattern allow.
- CORS_ORIGIN extends this list, not replaces it.
- Origin comparison is normalized to lowercase and trailing slash removed.

Operational impact:
- Some non-browser tools that omit Origin will still pass CORS check (allowed by design).

## Data Lifecycle Gotchas

- Assets and incidents are soft-deleted, not physically removed.
- Model-level pre-find and pre-count hooks hide soft-deleted data by default.

Operational impact:
- Direct database inspections can show more records than API responses.
- Restoring deleted records requires direct DB operation or dedicated endpoint (not currently implemented).

## AI Dependency Gotchas

- Incident creation depends on AI classification path.
- Missing/invalid Gemini configuration can break incident creation and threat analysis endpoints.
- AI config has model fallback and retry logic, but failures can still surface as generic operation errors.

Operational impact:
- For high reliability, monitor AI error rates and consider graceful fallback classification rules.

## Validation and Error Shape Gotchas

- Validation errors can come from express-validator (route layer) or custom validators (controller layer).
- Error response structures are mostly consistent but not fully uniform across all controllers.

Operational impact:
- Frontend should handle both:
  - message-only errors
  - message + errors arrays/objects

## Performance and Scaling Notes

- Some dashboard trend endpoints perform repeated per-day count queries in a loop.
- Search endpoints use regex filters without explicit text indexes.

Operational impact:
- At larger data volumes, dashboard and search latency may increase.
- Consider aggregation pipelines and indexed search strategy for scale.

## Production Hardening Checklist

1. Set strong JWT and refresh secrets.
2. Restrict CORS_ORIGIN to trusted frontend domains.
3. Disable default seeded credentials in production data.
4. Add centralized request ID correlation in logs.
5. Add permission checks per route/action.
6. Add monitoring for 401 spikes, rate-limit rejects, and AI failures.
7. Add backup and retention policy for MongoDB.
