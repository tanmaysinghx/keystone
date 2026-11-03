# Keystone Vault

Encrypted secrets and configuration files for every application in the Portal suite. Each app loads
its configuration at startup, either as individual keys or as whole files.

Give this file to an app's coding agent when you integrate that app.

---

## 1. Mental model

| Concept | What it is |
| --- | --- |
| **Application** | One per Portal app. Its id is the app's Portal SSO `client_id` (same slug rules), so Portal and Keystone use the same name for it. Each application has its own random data key. |
| **Environment** | Works like a Spring profile. Each application defines its own environments (`qa`, `uat`, `perf`, `prod-eu`, up to 50), when it is created or later. Every app also has `default`, which the others inherit from and override. |
| **Key** | One property, for example `spring.datasource.password`. Values are UTF-8 text, at most 64 KiB. |
| **File** | A whole file stored byte for byte: `application.properties`, YAML, a JSON service account, a certificate. At most 512 KiB. `.properties` files are also merged into the configuration apps receive. |
| **Version** | Each write creates a new version. The last 20 versions are kept. A rollback writes the old content again as the newest version, so history is never rewritten. |
| **Access token** | `ksv_<id>.<secret>`. A read-only token bound to one application environment. Stored only as a SHA-256 hash and shown once. It can expire and be revoked. |

### Precedence

The configuration an app receives in environment `E`, from highest to lowest precedence:

1. keys in `E`
2. `.properties` files in `E` (merged in name order)
3. keys in `default`
4. `.properties` files in `default`

Single-key and single-file reads try `E` first and fall back to `default`.

## 2. Identity and the Portal suite

- **People:** sign in with Portal SSO (PKCE popup), with Keystone's local accounts (email and
  password, `auth.local=true`), or both. Every admin API needs a verified Portal access token or a
  local session (`kss_…`), plus `ROLE_ADMIN` or the application's `ROLE_VAULT_<APP>` role.
- **Applications:** Portal SSO doesn't issue `client_credentials` tokens yet (see its
  `docs/ARCHITECTURE.md`, "Known gaps"). Apps therefore authenticate with Keystone access tokens,
  which an administrator issues in the Keystone console. Portal access tokens are never accepted
  on the machine API, and Keystone tokens are never accepted on the admin API.
- **Naming:** create the Keystone application with the same id as the app's Portal `client_id`.
  Spring apps use that id as their `spring.application.name`.
- Portal recognizes the `keystone` product id in App Connect, so the onboarding approval page shows
  it as **Keystone Vault** (category *Security*).

## 3. Loading configuration at startup

Every app needs two settings, both supplied by its deployment, never by source control or browser code:

```sh
KEYSTONE_URL=https://keystone.example.com
KEYSTONE_TOKEN=ksv_…            # Keystone console → app → Access tokens
```

### Spring Boot (Portal itself, and other JVM apps)

A complete, verified example is in [`examples/spring-boot`](../examples/spring-boot).

Keystone implements the Spring Cloud Config Server protocol, so the app needs no custom code.
Add `org.springframework.cloud:spring-cloud-starter-config` and set:

```properties
spring.application.name=billing
spring.config.import=configserver:
spring.cloud.config.uri=${KEYSTONE_URL}/config
spring.cloud.config.username=keystone
spring.cloud.config.password=${KEYSTONE_TOKEN}
spring.cloud.config.fail-fast=true
```

The token decides the environment. `spring.application.name` must match the token's
application; otherwise Keystone returns 403.

### Node.js

```js
// vault.mjs: node --import ./vault.mjs server.js
const response = await fetch(`${process.env.KEYSTONE_URL}/api/v1/vault/config`, {
  headers: { Authorization: `Bearer ${process.env.KEYSTONE_TOKEN}` },
  signal: AbortSignal.timeout(5000),
});
if (!response.ok) throw new Error(`Keystone Vault refused configuration: HTTP ${response.status}`);
for (const [key, value] of Object.entries(await response.json())) {
  const name = key.replace(/\]/g, '').replace(/[^A-Za-z0-9]/g, '_').toUpperCase();
  process.env[name] ??= value;
}
```

### Docker, systemd, shell

```sh
#!/bin/sh
set -eu
eval "$(curl -fsS -H "Authorization: Bearer $KEYSTONE_TOKEN" "$KEYSTONE_URL/api/v1/vault/config?format=shell")"
exec "$@"
```

`format=env` produces a dotenv file, for example for systemd's `EnvironmentFile=`. Key names follow
Spring relaxed binding: `spring.datasource.url` becomes `SPRING_DATASOURCE_URL`.

### Whole files and single keys

```sh
curl -fsS -H "Authorization: Bearer $KEYSTONE_TOKEN" \
  -o config/application.properties "$KEYSTONE_URL/api/v1/vault/files/application.properties"
curl -fsS -H "Authorization: Bearer $KEYSTONE_TOKEN" "$KEYSTONE_URL/api/v1/vault/keys/spring.datasource.password"
```

Fail fast: if Keystone can't be reached, an app should refuse to start rather than run without
its secrets.

## 4. Machine API (application token)

The token can be sent as `Authorization: Bearer ksv_…`, as `X-Keystone-Token: ksv_…`, or as HTTP
Basic with any username and the token as the password.

| Method | Endpoint | Returns |
| --- | --- | --- |
| GET | `/api/v1/vault/whoami` | `{app, environment, tokenId, expiresAt}` |
| GET | `/api/v1/vault/config?format=json\|properties\|env\|shell` | Merged configuration (default `json`: flat `{key: value}`) |
| GET | `/api/v1/vault/keys/{name}` | One value as `text/plain` |
| GET | `/api/v1/vault/files/{name}` | One file, byte for byte, with its stored content type |
| GET | `/config/{application}/{profiles}[/{label}]` | Spring Cloud Config `Environment` JSON |

Raw responses carry `X-Keystone-Version`, `Content-Disposition: attachment` and
`Content-Security-Policy: default-src 'none'; sandbox`. Errors: 401 `invalid_vault_token`,
403 `wrong_application`, 404 `item_not_found`, 503 `vault_sealed`.

## 5. Admin API (Portal access token + `ROLE_ADMIN`)

Prefix: `/api/v1/admin/vault`.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/status` | Sealed flag and totals |
| GET | `/audit/summary?app=` | Last-24-hour totals: pulls, refused tokens, changes, distinct IPs |
| GET | `/audit?app=&kind=pulls` | Vault events with IP and User-Agent, newest first. Filters: `kind=pulls|changes|denied|tokens`, `q=` (who, target, IP, client), `from=`/`to=` (unix seconds); paging with `limit=` (at most 500) and `before=` (the `nextBefore` cursor); `format=csv` exports up to 10,000 events and is itself audited |
| GET, POST | `/apps` | List; create `{id, name, description?, portalClientId?, environments?}` |
| PATCH, DELETE | `/apps/{app}` | Update `{name, description, portalClientId}`; delete needs `?confirm={app}` |
| POST | `/apps/{app}/environments` | `{name}` |
| DELETE | `/apps/{app}/environments/{env}?confirm={env}` | Deletes its keys, files and tokens (`default` can't be deleted) |
| GET | `/apps/{app}/environments/{env}/items` | Metadata only, never values |
| GET, PUT, DELETE | `/apps/{app}/environments/{env}/keys/{name}` | Reveal (`?version=`), write `{value}`, delete |
| GET, PUT, DELETE | `/apps/{app}/environments/{env}/files/{name}` | Download (`?version=`), upload raw body with `Content-Type`, delete |
| GET | `/apps/{app}/environments/{env}/{keys\|files}/{name}/versions` | History |
| POST | `/apps/{app}/environments/{env}/{keys\|files}/{name}/rollback` | `{version}` |
| POST | `/apps/{app}/environments/{env}/import` | `{format: properties\|env, content, replace?}` splits a file into keys; unchanged values are skipped |
| GET | `/apps/{app}/environments/{env}/config?format=` | Exactly what that environment's tokens receive |
| GET, POST | `/apps/{app}/tokens` | List; issue `{name, environment, expiresInDays?}` (0 = never). The token is returned once |
| DELETE | `/apps/{app}/tokens/{id}` | Revoke immediately |

Names: application and environment ids are lowercase slugs. Keys use letters, digits and
`. _ - [ ]` (at most 200 characters). File names use letters, digits and `. _ -` (at most 128
characters, no leading dot).

## 6. Security

- **Envelope encryption:** `KEYSTONE_MASTER_KEY` (32 bytes, base64) wraps one random AES-256 data
  key per application. Each value version is sealed with AES-256-GCM. The associated data binds
  each ciphertext to `app/env/kind/name@version`, so a row moved or swapped in the database fails
  to decrypt instead of being served somewhere else.
- **Sealed by default:** without a master key, every vault route returns 503 `vault_sealed`. Other
  Keystone features keep working.
- **Back up the master key separately from the database.** Losing it makes every stored secret
  unrecoverable. A wrong key returns 503 `vault_key_mismatch`; it never returns garbage.
- **Audit is mandatory:** every reveal, write, delete, rollback, import, token issue or revoke,
  and every app read is recorded in `audit_events` before the response is sent. If the event
  can't be recorded, the operation fails. Each event records who (`admin:<email>` or
  `token:<id> (<token name>)`), what, when, the client IP and the User-Agent. A known token
  presented with a wrong secret, or after revocation or expiry, is recorded as
  `vault.token.denied`. **Activity → Secret pulls only** in the console lists who pulled secrets,
  from which IP, and when.
- **Client IP:** this is the TCP peer address. Behind a reverse proxy, set `KEYSTONE_TRUST_PROXY=true`
  so the proxy's `X-Forwarded-For` is used instead. Never set it when Keystone is reachable
  directly, because clients could then forge their address.
- **Tokens** carry 256 random bits, are compared in constant time, and are read-only. Each token
  is scoped to one environment, so a `prod` token never sees `dev`. `last_used_at` is updated at
  most once a minute.
- **Raw files** are served as attachments under a sandbox CSP, so an uploaded HTML or SVG file
  can't run script on Keystone's origin.
- Values are never logged. The admin UI masks values until an administrator reveals them, and
  each reveal is audited.

## 7. Access, approvals and operations

| Feature | Summary |
| --- | --- |
| **Roles** | `ROLE_ADMIN` manages everything. `ROLE_VAULT_<APP>` (e.g. `ROLE_VAULT_ORDERS_SERVICE`) manages only that application. The role name is shown in the app's ⋯ menu. |
| **Protected environments** | `PUT /apps/{app}/environments/{env}/protection {"protected": true}` (admins). Writes, deletes, rollbacks, imports and promotes become change requests (`202 {"pendingApproval": id}`); a different person approves with `POST /changes/{id}/approve`. |
| **Promote** | `POST /apps/{app}/environments/{target}/promote {"from": "qa", "dryRun": true}` returns `added`/`changed`/`same`/`only-in-target` without values; without `dryRun`, it copies (or proposes) the chosen `items`. |
| **Token IP allow-lists** | `allowedCidrs` on create, `PATCH /apps/{app}/tokens/{id}` later. Other addresses are refused and audited (`address not allowed`). |
| **Lockout** | `security.failed-token-limit` failures per IP within `security.lockout-minutes` → 429 `too_many_attempts`. |
| **Live reload** | `ETag` / `If-None-Match` → 304 on `/api/v1/vault/config`; `/api/v1/vault/watch?version=…&timeout=30` long-polls for changes. Spring's `version` field carries the same fingerprint. |
| **Backups** | Automatic (`backup.interval-hours`, `backup.keep`), `POST/GET /backups`, `keystone backup`, `keystone restore FILE` (verifies the key first). |
| **Master-key rotation** | `keystone rotate-master-key`: re-wraps application keys, snapshots first, keeps the retired key. A wrong key is refused at startup. |
| **Alerts** | `alerts.webhook-url` or Settings → Alerts: refused tokens, lockouts, protected reveals, deletions, protection removed, approvals needed, audit exports, failed backups. |
| **Health checks** | `GET /insights`: ranked findings with the place to fix each. |
| **CLI** | `keystone pull`, `get key|file`, `run -- CMD`, `whoami` with `KEYSTONE_URL` / `KEYSTONE_TOKEN`. |

### Not yet implemented

- An external KMS (AWS KMS, Vault Transit) as the master-key holder. Rotation already only
  re-wraps per-application keys, so a KMS would wrap those instead of a local key.
- Portal-issued machine identity (`client_credentials`). When Portal adds it, Keystone can accept
  Portal service tokens alongside `ksv_` tokens.
- Lockout counters live in memory, per server process: they reset on restart and are not shared
  between instances (Keystone runs as one instance on SQLite).
