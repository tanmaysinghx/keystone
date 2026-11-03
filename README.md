<p align="center">
  <img src="ui/public/logo.svg" width="96" height="96" alt="Keystone logo" />
</p>

<h1 align="center">Keystone Vault</h1>

<p align="center">
  <strong>Encrypted secrets and configuration for the Portal SSO suite.</strong><br />
  One executable with its console built in. Apps load their keys and whole <code>.properties</code> files at startup.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Rust-single_binary-047857?logo=rust&amp;logoColor=white" alt="Rust single binary" />
  <img src="https://img.shields.io/badge/Angular-21-059669?logo=angular&amp;logoColor=white" alt="Angular 21" />
  <img src="https://img.shields.io/badge/AES--256--GCM-envelope_encryption-065F46" alt="AES-256-GCM" />
  <img src="https://img.shields.io/badge/Portal_SSO-PKCE-047857" alt="Portal SSO with PKCE" />
</p>

---

## What you get

- **Secrets as keys or whole files.** Store individual keys or whole files (`application.properties`, YAML, JSON, certificates) per application and per environment. Environments inherit from `default`, every write is versioned with rollback, and `.properties`/`.env` files can be imported and exported.
- **Loads at startup, everywhere.** A Spring Cloud Config-compatible endpoint means Spring Boot apps, Portal included, need no code. There is also JSON, `.properties`, dotenv and shell output, and `keystone run -- <your app>` for any language. Live reload works through ETags and a watch endpoint.
- **Least privilege.** Each app gets a read-only token for one environment, optionally limited to its servers' IP addresses. Repeated failed attempts lock the IP address out.
- **Two-person control.** Protected environments turn every change into a change request that a second administrator approves. Compare & promote copies values between environments without revealing them.
- **Sign in your way.** Use Portal SSO (PKCE), Keystone's own email-and-password accounts, or both, for a break-glass administrator when Portal is down. Roles are the same either way: `ROLE_ADMIN` manages everything, and `ROLE_VAULT_<APP>` lets a team manage only its own application.
- **SQLite or MySQL.** The built-in SQLite needs nothing installed. MySQL 8+ / MariaDB is chosen in the setup wizard or moved to later with `keystone migrate`, with every secret, user and audit record intact.
- **Audit and alerts.** Every pull, reveal and change is recorded with who, when, IP and client, with filters and CSV export. Slack, Teams or webhook alerts fire for refused tokens, deletions, pending approvals and more. Health checks rank what to fix.
- **Easy to run.** One binary (or container) and one commented `keystone.properties`. The master key is generated on first start. Automatic encrypted backups, verified restore, and master-key rotation without re-encrypting anything.

---

## Quick start

```bash
# Linux / macOS: downloads the latest release and verifies its checksum
curl -fsSL https://raw.githubusercontent.com/tanmaysinghx/keystone-vault/main/install.sh | bash

keystone          # prints a one-time setup key; open http://127.0.0.1:8090
```

The console opens on **first-time setup**, the same flow as Portal SSO's:

1. **License**: review and accept the Apache License 2.0.
2. **Setup key**: paste the key Keystone printed (also in `~/.keystone/secrets/setup.key`). It proves you control the server.
3. **Sign-in**: Portal SSO, a local administrator (email and password), or both.
4. **Database**: keep the built-in SQLite, or enter MySQL details and test the connection.
5. **Finish**: Keystone saves your choices to `keystone.properties` and restarts itself.

On first start Keystone creates `~/.keystone/` with the database, `keystone.properties` (every option, commented out) and a generated master key in `secrets/master.key`. **Back that key up somewhere else.** Data backups never include it, and without it nothing can be decrypted.

<details>
<summary><strong>Unattended (CI, Kubernetes, scripted installs)</strong></summary>

Skip the wizard with configuration. `KEYSTONE_SETUP_ACCEPT_LICENSE=true` means you accept the Apache-2.0 license. Add Portal SSO (`KEYSTONE_PORTAL_URL`, `KEYSTONE_PORTAL_CLIENT_ID`) and/or a first local administrator (`KEYSTONE_BOOTSTRAP_ADMIN_EMAIL`, `KEYSTONE_BOOTSTRAP_ADMIN_PASSWORD`; remove the password after the first sign-in), and optionally `KEYSTONE_STORAGE_DATABASE_URL=mysql://…`.
</details>

<details>
<summary><strong>Docker</strong></summary>

```bash
docker run -d --name keystone -p 8090:8090 -v keystone-data:/var/lib/keystone \
  ghcr.io/tanmaysinghx/keystone-vault:latest
docker logs keystone        # the setup key
```

Or `docker compose up -d` with [compose.yaml](compose.yaml), and `--profile mysql` for a MySQL container next to it. The image is distroless, runs as non-root, and health-checks itself.
</details>

<details>
<summary><strong>Linux service (systemd)</strong></summary>

```bash
curl -fsSL https://raw.githubusercontent.com/tanmaysinghx/keystone-vault/main/install.sh | sudo bash -s -- --service
sudo nano /etc/keystone/keystone.properties && sudo systemctl restart keystone
```

The data is in `/var/lib/keystone` and the unit is [distribution/keystone.service](distribution/keystone.service), which is sandboxed.
</details>

<details>
<summary><strong>From source</strong></summary>

Requires Rust and Node 22.12+ or 24. `./build.sh` produces `target/release/keystone` with the console embedded.
</details>

## Configuration: one file

Everything lives in **`keystone.properties`** ([template](back/keystone.properties.template)). Uncomment what you need and restart. Precedence, highest first:

1. command line: `keystone --server.port=9000` (Portal-style `--httpPort=9000` also works)
2. environment: `KEYSTONE_SERVER_PORT=9000` (any key, upper case, with `.` and `-` replaced by `_`)
3. the file: `~/.keystone/keystone.properties`, or `--config=/etc/keystone/keystone.properties`
4. built-in defaults

| Setting | Default | Purpose |
| --- | --- | --- |
| `server.address` / `server.port` | `127.0.0.1` / `8090` | Listen address (`0.0.0.0` in containers) |
| `server.trust-proxy` | `false` | Take client IPs from `X-Forwarded-For` behind your reverse proxy |
| `auth.local` | `false` (set by setup) | Email + password accounts, managed in **Settings → Users** |
| `portal.url` / `portal.client-id` | none | Portal SSO issuer and public client (setup or `keystone connect-portal` sets both) |
| `vault.master-key-file` / `vault.master-key` | `secrets/master.key` (generated) | The key that wraps every application key |
| `storage.database-url` | `<home>/data/keystone.db` | SQLite, or `mysql://user:pass@host:3306/keystone?ssl-mode=required` |
| `backup.interval-hours` / `backup.keep` / `backup.dir` | `24` / `14` / `<home>/backups` | Automatic encrypted snapshots |
| `security.failed-token-limit` / `security.lockout-minutes` | `10` / `15` | IP lockout after failed token attempts |
| `security.rotation-days` / `security.token-expiry-warning-days` | `90` / `14` | Health-check thresholds |
| `alerts.webhook-url` | none (or set in Settings) | Slack / Teams / JSON webhook |
| `log.level` | `info` | Log filter |

`keystone config` prints the effective configuration with secrets redacted. Legacy variables such as `PORTAL_URL` and `KEYSTONE_MASTER_KEY` still work.

## Loading secrets in an app

Create the application in the console, using its Portal `client_id`. Add keys or upload its `application.properties` per environment, then issue a token. The app needs only `KEYSTONE_URL` and `KEYSTONE_TOKEN`:

```properties
# Spring Boot: add spring-cloud-starter-config, then
spring.application.name=orders-service
spring.config.import=configserver:
spring.cloud.config.uri=${KEYSTONE_URL}/config
spring.cloud.config.username=keystone
spring.cloud.config.password=${KEYSTONE_TOKEN}
spring.cloud.config.fail-fast=true
```

```bash
keystone run -- node server.js            # any language: every key becomes an env variable
keystone pull --format=properties --out=config/application.properties
```

[examples/spring-boot](examples/spring-boot) is a complete app that CI starts against a real Keystone on every push. Full guides are in the built-in docs at **`/docs`** (also at [docs/VAULT.md](docs/VAULT.md)).

## Operating it

| Task | How |
| --- | --- |
| Back up now / restore | `keystone backup` · `keystone restore FILE` (stop the server first; the key is verified before anything changes) |
| Move to MySQL | `keystone migrate --to mysql://…` (stop the server first; copies everything and updates the config) |
| Add a local user | **Settings → Users** (local accounts) |
| Rotate the master key | `keystone rotate-master-key` (stop the server first; re-wraps app keys and keeps the old key as `master.key.retired-*`) |
| Let a team manage its app | Create `ROLE_VAULT_<APP>` in Portal (shown in the app's ⋯ menu) and assign it |
| Require approval in prod | App ⋯ menu → **Protect prod**; changes then wait in **Security → Approvals** |
| See who pulled secrets | **Security → Audit log** (IP, client, time; CSV export) |
| What needs attention | **Security → Health checks** |
| Alerts | **Settings → Alerts** (Slack / Teams webhook) |

## Pipeline, releases and tags

Modelled on Portal SSO's ([.github/workflows](.github/workflows)):

| Stage | Proves |
| --- | --- |
| 1 · Build & test | `cargo fmt`, `clippy -D warnings`, all backend tests on **SQLite and on MySQL 8.4** (count asserted), console unit tests and build |
| 2 · Static analysis | CodeQL (Rust and TypeScript, security-extended), `cargo audit`, `npm audit` |
| 3 · Package | Release binary smoke test (first start, setup wizard over the API with in-place restart, local sign-in, embedded console, backup, key rotation); container builds, runs non-root and becomes healthy; a real Spring Boot app loads its `qa` configuration, refuses a wrong token, and `keystone pull`/`run` work |
| 4 · Gate | One required status check |
| 5 · Release | Every green push to `main` is tagged **`v1.0.<run number>`**, with binaries for Linux (x86_64, arm64), macOS (Apple silicon, Intel) and Windows, `SHA256SUMS`, and a multi-arch image `ghcr.io/tanmaysinghx/keystone-vault:<version>` / `:latest` |

For a hand-picked version, push a tag (`git tag v1.2.0 && git push origin v1.2.0`) or run **Release** from the Actions tab. Dependabot opens grouped weekly updates for Cargo, npm, Maven, Actions and Docker.

## Development

```bash
npm --prefix ui ci && npm run build:ui   # console (embedded into the binary at build time)
cargo run -p keystone                    # http://localhost:8090, reads .env in a checkout
npm run dev:ui                           # console with live reload on :4300 (register that origin in Portal)
npm run check && npm run test:back && npm --prefix ui test
```

```text
back/                 Rust server and CLI: vault, approvals, backups, alerts, insights, migrations, tests
ui/                   Angular console and docs (/docs)
examples/spring-boot/ Reference Spring Boot client (exercised by CI)
distribution/         systemd unit
packages/portal-sso/  Pinned Portal browser SDK snapshot
```

<details>
<summary><strong>Legacy: Selfie Portfolio blog reactions</strong></summary>

Keystone still serves the portfolio's like and view counters at `/api/v1/blog/stats`, protected by `blog.service-key` (`KEYSTONE_SERVICE_KEY`). `node scripts/configure-local.mjs` links the sibling `selfie-portfolio` checkout with a random shared key. The portfolio's server-side `/api/stats` gateway calls Keystone, and the key never reaches the browser. Visitor IDs are hashed, and one like per visitor/post and one view per visitor/post/UTC day are enforced atomically.
</details>

## License

Keystone Vault is licensed under the [Apache License 2.0](LICENSE), the same license as Portal SSO. The setup wizard asks you to accept it once and records when, and from where, it was accepted.
