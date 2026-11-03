# Keystone API v1

All JSON responses use `Cache-Control: no-store`. Request responses carry `X-Request-ID`. Application errors use `{ "error": { "code": "...", "message": "..." } }`; malformed JSON/query extraction errors may use Axum's default 4xx response. No error returns credentials.

| Method | Endpoint | Authentication | Purpose |
| --- | --- | --- | --- |
| GET | `/health/live` | None | Process liveness |
| GET | `/health/ready` | None | Database query readiness; 503 if unavailable |
| GET | `/api/v1/info` | None | Name, version and API version |
| GET | `/api/v1/auth/config` | None | Public issuer/client/scopes and configured flag |
| GET | `/api/v1/auth/me` | Portal access token + `ROLE_ADMIN` | Verified profile and expiry |
| GET | `/api/v1/blog/stats?slug=example` | `X-Keystone-Key` | Read counts |
| POST | `/api/v1/blog/stats` | `X-Keystone-Key` | Idempotent like or daily view |
| * | `/api/v1/admin/vault/**` | Portal access token + `ROLE_ADMIN` | Manage vault applications, environments, keys, files, versions and tokens |
| GET | `/api/v1/vault/**`, `/config/{app}/{profile}` | Keystone application token (`ksv_…`) | Applications load secrets and configuration at startup |

The vault endpoints are documented in [VAULT.md](VAULT.md).

## Blog contract

The portfolio server supplies a visitor UUID from its HttpOnly cookie:

```json
{ "slug": "example", "action": "like", "visitor": "d3486ae3-dd4b-4f98-8ac3-e44310016ef8" }
```

`action` is `like` or `view`. Slugs are 1–100 lowercase ASCII letters/digits/hyphens, starting with a letter or digit. Invalid input returns 400, invalid service credentials 401, and missing server configuration/storage failures 503.

```json
{ "views": 120, "likes": 15, "configured": true }
```

Do not call this backend endpoint directly from browser code or expose its shared key. The existing portfolio `/api/stats` gateway remains the browser-facing endpoint. There is no public admin registration, password login, arbitrary-URL probe, or destructive counter endpoint.

## Browser token transport

POST `/api/v1/auth/token` accepts URL-encoded public-client authorization-code/PKCE and refresh-token grants with `X-Portal-Token-Relay: 1`. Keystone forwards only validated fields to its configured Portal issuer, with its configured client ID and fixed Portal popup callback. It returns OAuth token/error JSON, never caches responses, and does not enable cross-origin access. Both initial sign-in and refresh use this same-origin relay because Portal token responses may omit browser CORS headers.
