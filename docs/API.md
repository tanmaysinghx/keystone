# Keystone API v1

All JSON responses use `Cache-Control: no-store`. Request responses carry `X-Request-ID`. Application errors use `{ "error": { "code": "...", "message": "..." } }`; malformed JSON/query extraction errors may use Axum's default 4xx response. No error returns credentials.

| Method | Endpoint | Authentication | Purpose |
| --- | --- | --- | --- |
| GET | `/health/live` | None | Process liveness |
| GET | `/health/ready` | None | Database query readiness; 503 if unavailable |
| GET | `/api/v1/info` | None | Name, version and API version |
| GET | `/api/v1/auth/config` | None | Public issuer/client/scopes and configured flag |
| GET | `/api/v1/auth/me` | Portal access token + `ROLE_ADMIN` | Verified profile and expiry |
| GET | `/api/v1/admin/services` | Portal access token + `ROLE_ADMIN` | Live dependency checks and timestamps |
| GET | `/api/v1/admin/overview` | Portal access token + `ROLE_ADMIN` | Total likes/views/posts, uptime and version |
| GET | `/api/v1/admin/posts?page=0` | Portal access token + `ROLE_ADMIN` | 50 post summaries per page |
| GET | `/api/v1/blog/stats?slug=example` | `X-Keystone-Key` | Read counts |
| POST | `/api/v1/blog/stats` | `X-Keystone-Key` | Idempotent like or daily view |

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

## Service status contract

```json
{
  "checkedAt": 1793380000,
  "services": [
    { "name": "Keystone API", "status": "up", "detail": "Serving requests", "latencyMs": 0 }
  ]
}
```

`status` is `up`, `down`, or `unconfigured`. External checks require a successful HTTP status; Portal additionally verifies the discovery issuer. A 200 health endpoint is not proof that every operation within a remote service works. External checks run concurrently and have bounded timeouts. The UI shows stale results as Unknown on refresh failure.
