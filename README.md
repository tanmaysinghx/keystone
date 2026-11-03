<p align="center">
  <img src="ui/public/logo.svg" width="96" height="96" alt="Keystone logo" />
</p>

<h1 align="center">Keystone</h1>

<p align="center">
  <strong>Secrets and configuration vault for the Portal suite, with a Portal SSO-protected admin console.</strong><br />
  Rust backend. Angular console. Encrypted keys and whole config files that apps load at startup.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Rust-Backend-047857?logo=rust&amp;logoColor=white" alt="Rust backend" />
  <img src="https://img.shields.io/badge/Angular-21-059669?logo=angular&amp;logoColor=white" alt="Angular 21" />
  <img src="https://img.shields.io/badge/SQLite-Storage-065F46?logo=sqlite&amp;logoColor=white" alt="SQLite storage" />
  <img src="https://img.shields.io/badge/Portal_SSO-PKCE-047857" alt="Portal SSO with PKCE" />
</p>

---

## What you get

- **Keystone Vault:** per-application encrypted secrets, stored as individual keys or as whole files (`.properties`, YAML, JSON, certificates). Includes `default`-inherited environments, version history with rollback, `.properties`/`.env` import and export, and a mandatory audit trail. See [docs/VAULT.md](docs/VAULT.md).
- **Startup loading for every app:** a Spring Cloud Config-compatible endpoint (Spring Boot apps such as Portal need no custom code), plus JSON, `.properties`, dotenv and shell formats. Each app authenticates with a read-only token scoped to one environment.
- **Portal-native:** vault application ids are Portal `client_id`s, administrators sign in with Portal SSO, and Portal's App Connect recognizes the `keystone` product.
- **Admin console:** Portal SSO-styled workspace with an emerald accent, plus built-in docs at `/docs`.
- **Portal SSO:** popup sign-in with PKCE and session refresh; every admin API requires a verified access token and the administrator role.
- **Blog reactions:** persistent likes and daily unique views, with duplicate-safe retries and per-post activity totals.
- **Graceful outages:** the portfolio remains readable when Keystone is unavailable and displays a small retry message.
- **Single monorepo:** the Rust server serves the compiled Angular UI and same-origin APIs, backed by SQLite.

---

## Layout

```text
back/                 Rust / Axum API, SQLx migrations, integration tests
ui/                   Angular standalone admin console
packages/portal-sso/  Pinned official Portal browser SDK source snapshot
scripts/              Local setup and Portal onboarding helpers
docs/                 API and registration reference
data/                 SQLite database (ignored; persists across restarts)
```

## Run locally

Requires Rust, Node 22.12+ or 24, npm, and the platform C/C++ build tools for SQLite. Run commands from this directory. Use `npm.cmd` in Windows PowerShell if execution policy blocks `npm`.

```sh
npm --prefix ui ci
npm run build:ui
cargo run -p keystone
```

Open **http://localhost:8090**. The Rust server serves the built Angular UI and same-origin APIs. The UI is a public sign-in shell; every admin API validates the access token and requires `ROLE_ADMIN`. There is no development auth bypass.

For UI development, run `npm run dev:ui` in another terminal (port 4300). The proxy targets the Rust server. Register `http://localhost:4300` with the same public Portal client before using sign-in from this additional origin. Use port 8090 for the already-onboarded local application.

For a release build: `npm run build:ui` then `npm run build:back`. Ship the executable together with `ui/dist/keystone-ui/browser`, configure environment variables, and run from the repository/package root. `KEYSTONE_UI_DIR` can point to a different absolute UI directory.

## Configuration

The server reads `.env` in its working directory. `.env.example` lists setting names without credentials. Actual `.env` files are ignored.

| Setting | Meaning / default |
| --- | --- |
| `KEYSTONE_BIND` | `127.0.0.1:8090`; use a deliberate interface behind your HTTPS reverse proxy |
| `KEYSTONE_DATABASE_URL` | `sqlite://data/keystone.db`; migrations run at startup |
| `KEYSTONE_UI_DIR` | `ui/dist/keystone-ui/browser` |
| `KEYSTONE_SERVICE_KEY` | At least 32 characters; required for server-to-server blog API access |
| `KEYSTONE_MASTER_KEY` | 32 bytes, base64 (`openssl rand -base64 32`). Wraps each vault application's data key. Unset: the vault is sealed. **Back it up separately from the database**; it cannot be recovered |
| `KEYSTONE_TRUST_PROXY` | `false`. Set `true` only behind a reverse proxy, so audit records the client IP from `X-Forwarded-For` instead of the proxy's |
| `PORTAL_URL` | Exact verified issuer, no trailing slash |
| `PORTAL_CLIENT_ID` | Registered **public** OAuth client ID |
| `RUST_LOG` | Rust log filter; defaults to Keystone + request tracing |

Missing SSO settings leave all admin routes locked. Missing the service key leaves blog routes locked. A missing master key leaves the vault sealed.

## Portal SSO

The local application has been connected to **https://portal.tanmaysinghx.com** using Portal's native admin-approved onboarding flow. The resulting public client ID is `keystone` and the app URL is `http://localhost:8090`. These non-secret facts do not replace the environment settings.

The SDK uses authorization code + PKCE S256, the Portal-hosted popup callback, and rotating refresh tokens. Rust verifies RS256 signatures from `/oauth2/jwks`, exact issuer, audience, expiry, not-before, access-token scope, and `ROLE_ADMIN`. ID tokens are not accepted as API credentials. Public keys are cached for five minutes and unknown-key refresh attempts are throttled. Unverifiable identity fails closed.

For another deployment, onboard its **actual URL** in Portal and use the returned registration; do not reuse the localhost URL in production. `docs/portal-onboarding.example.json` illustrates the registration request. For a manual restricted catalog entry, populate `application.roleIds` with Portal's actual `ROLE_ADMIN` role UUID. Do not invent that UUID. Keystone enforces the admin role regardless of catalog visibility.

For the local native connection helper, stop Keystone first, then run:

```sh
node scripts/connect-portal.mjs https://portal.tanmaysinghx.com
```

It temporarily listens on port 8090, prints an approval URL, redeems the admin-approved code with its in-memory verifier, and saves only issuer/client ID. Reconnecting an existing Portal app can rotate its credentials; use this only when onboarding/reconnecting intentionally. The helper exits after success or 30 minutes. No Portal password or private client secret is copied into this app.

Sign out clears Keystone's local session. It does **not** sign the user out of all Portal applications. The SDK snapshot and its upstream commit are documented in `packages/portal-sso/UPSTREAM.md`.

## Connect Selfie Portfolio

From Keystone, `node scripts/configure-local.mjs` links the sibling `selfie-portfolio` project using a random shared server key. It preserves existing keys and refuses to overwrite mismatched credentials. This has been run for this checkout.

In the portfolio's `.env.local` (or Vercel server environment), configure `KEYSTONE_URL` and the same `KEYSTONE_SERVICE_KEY`. Neither belongs in Angular/browser configuration. The portfolio's `/api/stats` gateway forwards to `/api/v1/blog/stats` with a 2.5-second timeout.

To run the portfolio locally with the gateway:

```sh
cd ../selfie-portfolio
npm run blog
npm run start:keystone
```

Open http://localhost:4200. Plain `npm start` does not run Vercel functions; it deliberately shows the reactions-unavailable notice if the gateway is absent. In production, `KEYSTONE_URL` must point to a deployed HTTPS endpoint reachable by Vercel, not localhost.

The gateway sets an opaque HttpOnly, SameSite visitor cookie and never stores raw IPs. Keystone hashes that visitor ID and enforces a unique database key: one like per visitor/post and one view per visitor/post/UTC day. Concurrent retries cannot increment twice. This is anonymous browser-level deduplication, **not** proof of a unique person. Clearing cookies creates another visitor; use reverse-proxy/WAF rate limits before public exposure.

The Angular blog only remembers likes after a confirmed response. If Keystone is unavailable, reading and navigation keep working, counts are not replaced with fake zeros, and a small retry message appears. A timed-out write may already have committed; retries use the same visitor identity.

The former Upstash counters are not automatically migrated or deleted. Keystone starts a new dataset, and a distinct local liked key avoids carrying forward unconfirmed legacy likes. Back up/export old counters before any planned migration.

## Checks

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm --prefix ui test
npm --prefix ui run build
```

From the portfolio, run `npm run test:stats`, `npm test -- --watch=false`, and `npm run build`.

## Operational boundaries

This initial version uses one SQLite database with WAL and migrations; run one backend instance on durable local storage. Do not put the database on an ephemeral serverless filesystem or run independent replicas with divergent databases. Back up SQLite using its supported backup mechanism, including a restore drill. For multiple writers/instances, plan a PostgreSQL migration.

Expose the server through HTTPS with request/rate limits and a durable volume. API bodies are limited to 16 KiB (1 MiB on vault admin routes, for file uploads); the portfolio gateway limits requests to 2 KiB. Secrets and bearer tokens are not logged. Portal role changes take effect when a new token is issued or an old token expires; no immediate revocation/introspection workflow is implemented in this first version.
