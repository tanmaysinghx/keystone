/**
 * Every page under /docs, as data, one guide per task (same structure as Portal SSO's docs).
 * Text supports `code`, **bold** and [links](guide-id). Code blocks may contain {{ORIGIN}}, which the
 * page replaces with this server's own address so snippets are copy-paste ready.
 */
export type DocBlock =
  | { kind: 'p'; text: string }
  | { kind: 'h'; text: string }
  | { kind: 'steps'; items: { title: string; body: string }[] }
  | { kind: 'list'; items: string[] }
  | { kind: 'code'; label: string; code: string }
  | { kind: 'table'; head: string[]; rows: string[][] }
  | { kind: 'note'; tone: 'tip' | 'warn'; text: string }
  | { kind: 'links'; items: { guide: string; text: string }[] }
  | { kind: 'stacks' }
  | { kind: 'endpoints' };

export interface DocGuide { id: string; group: string; title: string; summary: string; blocks: DocBlock[] }

export const DOC_GROUPS = ['Start here', 'Administer', 'Integrate', 'Operate', 'Reference'];

export interface Stack { id: string; label: string; caption: string; code: string }

export const STACKS: Stack[] = [
  { id: 'spring', label: 'Spring Boot', caption: 'application.properties: Spring Cloud Config client, no code', code: `# pom.xml: org.springframework.cloud:spring-cloud-starter-config
spring.application.name=orders-service
spring.config.import=configserver:
spring.cloud.config.uri=\${KEYSTONE_URL}/config
spring.cloud.config.username=keystone
spring.cloud.config.password=\${KEYSTONE_TOKEN}
spring.cloud.config.fail-fast=true` },
  { id: 'node', label: 'Node.js', caption: 'vault.mjs: preload before the app starts', code: `// node --import ./vault.mjs server.js
const response = await fetch(\`\${process.env.KEYSTONE_URL}/api/v1/vault/config\`, {
  headers: { Authorization: \`Bearer \${process.env.KEYSTONE_TOKEN}\` },
  signal: AbortSignal.timeout(5000),
});
if (!response.ok) throw new Error(\`Keystone Vault: HTTP \${response.status}\`);
for (const [key, value] of Object.entries(await response.json())) {
  const name = key.replace(/\\]/g, '').replace(/[^A-Za-z0-9]/g, '_').toUpperCase();
  process.env[name] ??= value;   // spring.datasource.url -> SPRING_DATASOURCE_URL
}` },
  { id: 'docker', label: 'Docker / shell', caption: 'docker-entrypoint.sh', code: `#!/bin/sh
set -eu
eval "$(curl -fsS -H "Authorization: Bearer $KEYSTONE_TOKEN" \\
  "$KEYSTONE_URL/api/v1/vault/config?format=shell")"
exec "$@"` },
  { id: 'python', label: 'Python', caption: 'Load into os.environ at import time', code: `import os, re, urllib.request, json

req = urllib.request.Request(
    f"{os.environ['KEYSTONE_URL']}/api/v1/vault/config",
    headers={"Authorization": f"Bearer {os.environ['KEYSTONE_TOKEN']}"},
)
with urllib.request.urlopen(req, timeout=5) as response:
    for key, value in json.load(response).items():
        os.environ.setdefault(re.sub(r"[^A-Za-z0-9]", "_", key.replace("]", "")).upper(), value)` },
  { id: 'go', label: 'Go', caption: 'Read the merged config as a map', code: `req, _ := http.NewRequest("GET", os.Getenv("KEYSTONE_URL")+"/api/v1/vault/config", nil)
req.Header.Set("Authorization", "Bearer "+os.Getenv("KEYSTONE_TOKEN"))
res, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
if err != nil || res.StatusCode != 200 {
    log.Fatalf("keystone vault: %v %v", err, res)
}
var config map[string]string
json.NewDecoder(res.Body).Decode(&config)` },
  { id: 'cli', label: 'keystone CLI', caption: 'Any language: start the app with every key in its environment', code: `# The same single binary is also the client (no server-side setup)
export KEYSTONE_URL={{ORIGIN}} KEYSTONE_TOKEN=ksv_...
keystone run -- java -jar orders-service.jar
keystone pull --format=properties --out=config/application.properties
keystone get key spring.datasource.password` },
  { id: 'file', label: 'Whole file', caption: 'Write application.properties to disk before start', code: `curl -fsS -H "Authorization: Bearer $KEYSTONE_TOKEN" \\
  -o config/application.properties \\
  "$KEYSTONE_URL/api/v1/vault/files/application.properties"
chmod 600 config/application.properties` },
];

export interface Endpoint { method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'; path: string; summary: string; auth: 'App token' | 'Admin' | 'Public' }

export const ENDPOINTS: Endpoint[] = [
  { method: 'GET', path: '/api/v1/vault/config?format=json|properties|env|shell', summary: 'Merged configuration for the token\'s environment', auth: 'App token' },
  { method: 'GET', path: '/api/v1/vault/keys/{name}', summary: 'One value as text/plain (falls back to default)', auth: 'App token' },
  { method: 'GET', path: '/api/v1/vault/files/{name}', summary: 'One file, byte for byte (falls back to default)', auth: 'App token' },
  { method: 'GET', path: '/api/v1/vault/whoami', summary: 'Application, environment and expiry of the token', auth: 'App token' },
  { method: 'GET', path: '/config/{application}/{profile}', summary: 'Spring Cloud Config Server protocol', auth: 'App token' },
  { method: 'GET', path: '/api/v1/admin/vault/apps', summary: 'List applications', auth: 'Admin' },
  { method: 'POST', path: '/api/v1/admin/vault/apps', summary: 'Create an application and its environments', auth: 'Admin' },
  { method: 'POST', path: '/api/v1/admin/vault/apps/{app}/environments', summary: 'Add an environment', auth: 'Admin' },
  { method: 'PUT', path: '/api/v1/admin/vault/apps/{app}/environments/{env}/keys/{name}', summary: 'Write a key ({"value": "…"})', auth: 'Admin' },
  { method: 'PUT', path: '/api/v1/admin/vault/apps/{app}/environments/{env}/files/{name}', summary: 'Upload a whole file (raw body)', auth: 'Admin' },
  { method: 'POST', path: '/api/v1/admin/vault/apps/{app}/environments/{env}/import', summary: 'Split a .properties or .env file into keys', auth: 'Admin' },
  { method: 'POST', path: '/api/v1/admin/vault/apps/{app}/tokens', summary: 'Issue an access token (returned once)', auth: 'Admin' },
  { method: 'DELETE', path: '/api/v1/admin/vault/apps/{app}/tokens/{id}', summary: 'Revoke a token immediately', auth: 'Admin' },
  { method: 'GET', path: '/api/v1/admin/vault/audit?app=&kind=pulls', summary: 'Who pulled what, when and from which IP', auth: 'Admin' },
  { method: 'GET', path: '/api/v1/vault/watch?version=&timeout=30', summary: 'Long-poll until the configuration changes (live reload)', auth: 'App token' },
  { method: 'PUT', path: '/api/v1/admin/vault/apps/{app}/environments/{env}/protection', summary: 'Protect an environment ({"protected": true})', auth: 'Admin' },
  { method: 'POST', path: '/api/v1/admin/vault/apps/{app}/environments/{env}/promote', summary: 'Compare ({"from","dryRun":true}) or copy items between environments', auth: 'Admin' },
  { method: 'GET', path: '/api/v1/admin/vault/changes?status=pending', summary: 'Change requests waiting for approval', auth: 'Admin' },
  { method: 'POST', path: '/api/v1/admin/vault/changes/{id}/approve', summary: 'Approve and apply (a different administrator)', auth: 'Admin' },
  { method: 'PATCH', path: '/api/v1/admin/vault/apps/{app}/tokens/{id}', summary: 'Change a token\'s IP allow-list', auth: 'Admin' },
  { method: 'GET', path: '/api/v1/admin/vault/insights', summary: 'Health checks', auth: 'Admin' },
  { method: 'POST', path: '/api/v1/admin/vault/backups', summary: 'Take a backup now', auth: 'Admin' },
  { method: 'GET', path: '/health/ready', summary: 'Readiness (database reachable)', auth: 'Public' },
];

export const DOC_GUIDES: DocGuide[] = [
  {
    id: 'introduction', group: 'Start here', title: 'What is Keystone Vault',
    summary: 'Encrypted secrets and configuration for every application in the Portal suite, loaded by each app when it starts.',
    blocks: [
      { kind: 'p', text: 'Keystone Vault keeps the configuration your applications must not commit to git: database passwords, API keys, certificates, whole `application.properties` files. Each application gets only its own values, for its own environment, using a read-only token.' },
      { kind: 'table', head: ['Concept', 'What it is'], rows: [
        ['**Application**', 'One per app. Its id is the app\'s Portal SSO `client_id`, so both registries use the same name. Each application has its own encryption key.'],
        ['**Environment**', 'Each application defines its own environments, such as `qa`, `uat` or `prod-eu`. All of them inherit from `default`.'],
        ['**Key**', 'One property, for example `spring.datasource.password`. Versioned and audited on its own.'],
        ['**File**', 'A whole file served byte for byte: `.properties`, YAML, JSON, certificates. `.properties` files are also merged into the configuration.'],
        ['**Access token**', '`ksv_…`, read-only and bound to one environment of one application. Shown once.'],
      ] },
      { kind: 'h', text: 'How it fits the Portal suite' },
      { kind: 'list', items: [
        '**People** sign in with Portal SSO. Only Portal administrators (`ROLE_ADMIN`) can open the console.',
        '**Applications** authenticate with Keystone access tokens. Portal does not issue machine-to-machine tokens yet.',
        '**Spring Boot apps**, Portal included, load Keystone with the standard Spring Cloud Config client and no custom code.',
      ] },
      { kind: 'links', items: [{ guide: 'quick-start', text: 'Quick start: first secret to running app' }, { guide: 'environments', text: 'Applications & environments' }] },
    ],
  },
  {
    id: 'quick-start', group: 'Start here', title: 'Quick start',
    summary: 'Go from an empty vault to an application that loads its qa configuration at startup.',
    blocks: [
      { kind: 'steps', items: [
        { title: 'Create the application', body: 'In the console, click **New application**. Use the app\'s Portal client id as the Keystone id, for example `orders-service`. List the environments it needs, such as `qa, uat, prod`. You can add more later.' },
        { title: 'Add its configuration', body: 'Pick the **qa** environment. Under **Files**, upload your qa `application.properties`. Under **Keys**, add the secrets you want versioned and audited one by one, such as `spring.datasource.password`. Values every environment shares go in **default**.' },
        { title: 'Issue a token', body: 'Open **Access tokens**, then **Issue token** for `qa`. Copy it: Keystone stores only a hash and cannot show it again.' },
        { title: 'Give the app two settings', body: 'Set `KEYSTONE_URL` and `KEYSTONE_TOKEN` in the deployment\'s secret store, never in git. The token is the only secret the app holds.' },
        { title: 'Load at startup', body: 'Use the snippet for your stack below. With fail-fast enabled, the app refuses to start without its configuration.' },
      ] },
      { kind: 'stacks' },
      { kind: 'note', tone: 'tip', text: 'Each application\'s **Load at startup** tab in the console shows these snippets with its own id filled in.' },
    ],
  },
  {
    id: 'environments', group: 'Administer', title: 'Applications & environments',
    summary: 'Model each app and its environments, and understand which value wins.',
    blocks: [
      { kind: 'p', text: 'Different applications have different environments, so each one defines its own: one app might use `dev, qa, prod` and another `qa, uat, perf, prod-eu, prod-us`. Add an environment at any time from the environment bar (up to 50 per application).' },
      { kind: 'h', text: 'Inheritance and precedence' },
      { kind: 'p', text: 'Every application has `default`. Every other environment inherits from it. A qa token receives these values, highest precedence first:' },
      { kind: 'table', head: ['#', 'Source', 'Example'], rows: [
        ['1', 'Keys in the environment', '`qa` → `spring.datasource.password`'],
        ['2', '`.properties` files in the environment', '`qa` → `application.properties`'],
        ['3', 'Keys in `default`', '`orders.payment-gateway`'],
        ['4', '`.properties` files in `default`', 'shared `application.properties`'],
      ] },
      { kind: 'p', text: 'Several `.properties` files in one environment are merged in name order, so `application-z.properties` overrides `application.properties`.' },
      { kind: 'note', tone: 'warn', text: 'Deleting an environment destroys its keys, files, versions and tokens. Apps using those tokens stop receiving configuration. The console asks you to type the environment name to confirm.' },
    ],
  },
  {
    id: 'keys-and-files', group: 'Administer', title: 'Keys, files & versions',
    summary: 'When to store a file whole, when to split it into keys, and how to roll back.',
    blocks: [
      { kind: 'table', head: ['Store as', 'Use for', 'Limits'], rows: [
        ['**Key**', 'Secrets you rotate or audit individually: passwords, API keys, tokens.', '64 KiB · letters, digits, `. _ - [ ]`'],
        ['**File**', 'Anything an app reads as a file: `application.properties`, YAML, JSON service accounts, PEM certificates.', '512 KiB · letters, digits, `. _ -`'],
      ] },
      { kind: 'h', text: 'Import an existing file as keys' },
      { kind: 'p', text: '**Keys → Import file** splits a `.properties` or `.env` file into keys. Values that didn\'t change are skipped, so re-importing creates no new versions. Tick **Delete keys not in this file** to make the environment match the file exactly.' },
      { kind: 'h', text: 'Versions and rollback' },
      { kind: 'p', text: 'Every write creates a new version, and the last 20 are kept. **History → Restore** writes the old content again as the newest version, so history is never rewritten and the rollback itself is audited.' },
      { kind: 'h', text: 'Export' },
      { kind: 'p', text: '**Export .properties / .env** downloads exactly what that environment\'s tokens receive, with inheritance applied. Exports are audited as reveals.' },
    ],
  },
  {
    id: 'tokens', group: 'Administer', title: 'Access tokens',
    summary: 'Issue, store, rotate and revoke the credentials applications use.',
    blocks: [
      { kind: 'list', items: [
        'A token reads **one environment of one application** and can never write. A `qa` token can\'t see `prod`.',
        'It is shown **once**. Keystone keeps only a SHA-256 hash of its 256-bit secret.',
        'Choose an expiry: 30 days, 90 days, 1 year, or never. **Last used** shows whether a deployment still uses it.',
        '**Revoke** takes effect on the next request. Running apps keep the configuration they already loaded until they restart.',
      ] },
      { kind: 'h', text: 'Where to keep it' },
      { kind: 'table', head: ['Platform', 'Store KEYSTONE_TOKEN in'], rows: [
        ['Kubernetes', 'A `Secret`, mounted as an environment variable'],
        ['Docker / Compose', 'A Docker secret or the orchestrator\'s secret store, not an image layer or committed `.env`'],
        ['systemd', '`LoadCredential=` or an `EnvironmentFile=` readable only by the service user'],
        ['CI/CD', 'The pipeline\'s masked secret variables'],
      ] },
      { kind: 'h', text: 'Rotate without downtime' },
      { kind: 'steps', items: [
        { title: 'Issue a second token', body: 'Same environment, new name, for example "orders qa 2026-11".' },
        { title: 'Roll it out', body: 'Update the deployment secret and restart instances.' },
        { title: 'Revoke the old one', body: 'Once its **Last used** time stops advancing.' },
      ] },
    ],
  },
  {
    id: 'audit', group: 'Administer', title: 'Audit & activity',
    summary: 'See who pulled which secrets, when, and from which IP address.',
    blocks: [
      { kind: 'p', text: 'Keystone records every event before it responds: app reads, admin reveals, writes, rollbacks, imports, and token issue or revoke. If an event can\'t be recorded, the operation fails.' },
      { kind: 'table', head: ['Field', 'Example'], rows: [
        ['Who', '`admin:you@example.com` or `token:9f2c… (orders qa k8s)`'],
        ['Action', 'App loaded configuration · Revealed key · Token refused'],
        ['What', '`orders-service/qa`, `orders-service/qa/spring.datasource.password@4`'],
        ['IP address', 'The client address'],
        ['Client', 'User-Agent, for example `Java/21`, `curl/8.5`, `node`'],
        ['When', 'Timestamp'],
      ] },
      { kind: 'p', text: '**Security → Audit log** in the sidebar shows every application in one place. It has 24-hour totals (secret pulls, refused tokens, changes, source IPs), filters by application, event type, time range and free text (who, IP, key, client), and **Export CSV** for compliance reviews. The export is itself audited. Click a row for the full User-Agent and subject.' },
      { kind: 'p', text: 'Within one application, open, then **Activity → Secret pulls only**, to see who read secrets. **Token refused** rows (highlighted) are a known token presented with a wrong secret, or after revocation or expiry: either a stale deployment or someone holding an old credential.' },
      { kind: 'note', tone: 'warn', text: 'Behind a reverse proxy, set `KEYSTONE_TRUST_PROXY=true` so the client IP comes from `X-Forwarded-For` rather than the proxy. Never set it when Keystone is reachable directly, because clients could then forge their address.' },
    ],
  },
  {
    id: 'spring-boot', group: 'Integrate', title: 'Spring Boot',
    summary: 'Load configuration through the Spring Cloud Config client before the context starts.',
    blocks: [
      { kind: 'p', text: 'Keystone implements the Spring Cloud Config Server protocol. Add one dependency and set a few properties. `@Value`, `@ConfigurationProperties` and `spring.datasource.*` then work unchanged. This has been verified with Spring Boot 4.0 and Spring Cloud 2025.1.' },
      { kind: 'code', label: 'pom.xml', code: `<dependency>
  <groupId>org.springframework.cloud</groupId>
  <artifactId>spring-cloud-starter-config</artifactId>
</dependency>
<!-- with the spring-cloud-dependencies BOM matching your Boot version -->` },
      { kind: 'code', label: 'src/main/resources/application.properties (the only config in git)', code: `spring.application.name=orders-service
spring.config.import=configserver:
spring.cloud.config.uri=\${KEYSTONE_URL}/config
spring.cloud.config.username=keystone
spring.cloud.config.password=\${KEYSTONE_TOKEN}
spring.cloud.config.fail-fast=true` },
      { kind: 'code', label: 'Run', code: `KEYSTONE_URL={{ORIGIN}} KEYSTONE_TOKEN=ksv_… java -jar orders-service.jar` },
      { kind: 'list', items: [
        '`spring.application.name` must equal the Keystone application id; otherwise Keystone returns 403.',
        'The **token** decides the environment. `spring.profiles.active` is not needed to select it.',
        '`fail-fast=true` stops startup on a wrong, revoked or expired token, or when Keystone is unreachable.',
      ] },
    ],
  },
  {
    id: 'other-apps', group: 'Integrate', title: 'Node.js, Python, Go & Docker',
    summary: 'Any language that can make an HTTPS request can load its configuration.',
    blocks: [
      { kind: 'p', text: '`GET /api/v1/vault/config` returns the merged configuration. Pick the format your runtime reads most easily:' },
      { kind: 'table', head: ['format=', 'Output', 'Use with'], rows: [
        ['`json` (default)', '`{"spring.datasource.url": "…"}`', 'Node, Python, Go'],
        ['`properties`', 'Java `.properties`, Latin-1 safe', 'JVM apps, Spring `--spring.config.location`'],
        ['`env`', '`SPRING_DATASOURCE_URL="…"`', 'dotenv libraries, systemd `EnvironmentFile=`'],
        ['`shell`', '`export SPRING_DATASOURCE_URL=\'…\'`', '`eval` in an entrypoint script'],
      ] },
      { kind: 'p', text: 'Key names become environment variables using Spring\'s relaxed binding: `spring.datasource.url` becomes `SPRING_DATASOURCE_URL`.' },
      { kind: 'stacks' },
    ],
  },
  {
    id: 'install', group: 'Start here', title: 'Install & configure',
    summary: 'One binary, one folder, one optional config file. Running in a minute, production-ready in ten.',
    blocks: [
      { kind: 'p', text: 'Keystone Vault ships as a **single executable** with the console built in, like Portal SSO\'s single jar. On first start it creates its home folder (`~/.keystone`, or `/var/lib/keystone` as a service) with the database, a generated master key in `secrets/master.key`, and a fully commented `keystone.properties`.' },
      { kind: 'code', label: 'Linux / macOS installer (downloads the latest release, verifies its checksum)', code: `curl -fsSL https://raw.githubusercontent.com/tanmaysinghx/keystone-vault/main/install.sh | bash
keystone          # prints a one-time setup key, then open http://127.0.0.1:8090` },
      { kind: 'h', text: 'First-time setup' },
      { kind: 'steps', items: [
        { title: 'License', body: 'Read and accept the Apache License 2.0.' },
        { title: 'Setup key', body: 'Paste the key Keystone printed at startup (also in `secrets/setup.key` in its home). It proves you control the server, not just the web page.' },
        { title: 'Sign-in', body: 'Choose [Portal SSO, local accounts, or both](signin). Local accounts need a first administrator.' },
        { title: 'Database', body: 'Keep the built-in SQLite, or [connect MySQL](database). Keystone copies what setup has stored, saves the choice to `keystone.properties`, and restarts by itself.' },
      ] },
      { kind: 'code', label: 'Docker (open the console and follow setup; the key is in docker logs keystone)', code: `docker run -d --name keystone -p 8090:8090 \\
  -v keystone-data:/var/lib/keystone \\
  ghcr.io/tanmaysinghx/keystone-vault:latest` },
      { kind: 'code', label: 'Unattended (CI, Kubernetes): skip the wizard', code: `KEYSTONE_SETUP_ACCEPT_LICENSE=true        # you accept the Apache-2.0 license
KEYSTONE_PORTAL_URL=https://sso.example.com KEYSTONE_PORTAL_CLIENT_ID=keystone
# and/or a first local administrator (remove the password after the first sign-in):
KEYSTONE_BOOTSTRAP_ADMIN_EMAIL=ops@example.com KEYSTONE_BOOTSTRAP_ADMIN_PASSWORD=...
KEYSTONE_STORAGE_DATABASE_URL=mysql://keystone:...@db:3306/keystone   # optional` },
      { kind: 'code', label: 'As a Linux service (installer with --service)', code: `curl -fsSL https://raw.githubusercontent.com/tanmaysinghx/keystone-vault/main/install.sh | sudo bash -s -- --service
sudo nano /etc/keystone/keystone.properties
sudo systemctl restart keystone` },
      { kind: 'h', text: 'One configuration file' },
      { kind: 'p', text: 'Every setting lives in `keystone.properties`. Uncomment what you need and restart. Precedence, highest first: command line (`--server.port=9000`), environment (`KEYSTONE_SERVER_PORT=9000`: upper case, `.` and `-` become `_`), the file, built-in defaults. `keystone config` prints the effective configuration with secrets redacted.' },
      { kind: 'table', head: ['Setting', 'Default', 'Purpose'], rows: [
        ['`server.address` / `server.port`', '`127.0.0.1` / `8090`', 'Listen address. `0.0.0.0` in containers'],
        ['`server.trust-proxy`', '`false`', 'Real client IPs from `X-Forwarded-For` behind your proxy'],
        ['`auth.local`', '`false` (setup sets it)', 'Email + password accounts, with or without Portal SSO'],
        ['`storage.database-url`', 'built-in SQLite', '`mysql://user:pass@host:3306/keystone` for MySQL 8+ / MariaDB'],
        ['`portal.url` / `portal.client-id`', '', 'Portal SSO. Easiest: `keystone connect-portal`'],
        ['`vault.master-key-file`', '`secrets/master.key`', 'Or `vault.master-key` inline. Generated on first start'],
        ['`backup.interval-hours` / `backup.keep`', '`24` / `14`', 'Automatic encrypted snapshots'],
        ['`security.failed-token-limit` / `lockout-minutes`', '`10` / `15`', 'IP lockout after failed token attempts'],
        ['`security.rotation-days`', '`90`', 'Flag keys not changed for longer'],
        ['`alerts.webhook-url`', '', 'Slack / Teams / JSON webhook (or set in Settings)'],
      ] },
      { kind: 'note', tone: 'warn', text: '**Back up `secrets/master.key` somewhere other than the server** (a password manager or your secret store). Data backups never include it, and without it nothing can be decrypted.' },
    ],
  },
  {
    id: 'roles', group: 'Administer', title: 'Roles & access',
    summary: 'Use Portal SSO roles to let each team manage only its own application.',
    blocks: [
      { kind: 'table', head: ['Portal role', 'Can'], rows: [
        ['`ROLE_ADMIN`', 'Everything: create and delete applications, protect environments, approve changes, settings, backups, the full audit log'],
        ['`ROLE_VAULT_<APP>`', 'Manage one application: its keys, files, environments, tokens, promote, approvals and audit log. Example: `orders-service` → `ROLE_VAULT_ORDERS_SERVICE`'],
      ] },
      { kind: 'steps', items: [
        { title: 'Copy the role name', body: 'In the application\'s **⋯** menu, under "Portal role for owners".' },
        { title: 'Create it in Portal SSO', body: 'Portal → **Roles** → New role, then assign it to the team\'s users.' },
        { title: 'They sign in to Keystone', body: 'The sidebar lists only their applications. Roles change on their next sign-in.' },
      ] },
    ],
  },
  {
    id: 'signin', group: 'Administer', title: 'Sign-in: Portal SSO or local accounts',
    summary: 'Use Portal SSO, Keystone\'s own email-and-password accounts, or both.',
    blocks: [
      { kind: 'table', head: ['Mode', 'Good for', 'How'], rows: [
        ['**Portal SSO**', 'Teams already on Portal: one identity, MFA, offboarding in one place', 'Setup wizard, or `keystone connect-portal https://sso…`'],
        ['**Local accounts**', 'Running without Portal, small teams, isolated networks', 'Setup wizard creates the first administrator; add others in **Settings → Users**'],
        ['**Both**', 'A break-glass administrator that still works when Portal is down', 'Enable both in the wizard, or set `auth.local=true` next to `portal.url`'],
      ] },
      { kind: 'p', text: 'Local accounts use the same roles as Portal: **Administrator** (`ROLE_ADMIN`) or owner of specific applications (`ROLE_VAULT_<APP>`). Passwords need at least 12 characters mixing three character classes and are stored as Argon2id hashes. Repeated failed sign-ins lock the address out (`security.failed-token-limit`), and every sign-in, success or failure, is in the audit log.' },
      { kind: 'list', items: [
        'Sessions last `auth.session-hours` (12 by default). Signing out, a password change, or disabling the user ends them.',
        'Without Portal SSO, the last enabled administrator cannot be deleted, disabled or demoted, so you can never lock yourself out.',
        'Anyone signed in with a local account can change their own password from the account panel.',
      ] },
    ],
  },
  {
    id: 'database', group: 'Operate', title: 'Database: SQLite or MySQL',
    summary: 'Built-in SQLite needs nothing installed. MySQL 8.0+ or MariaDB 10.6+ when you want a managed database.',
    blocks: [
      { kind: 'p', text: 'Secrets are encrypted before they reach either database, and the master key never goes into it. SQLite keeps everything in one file in the Keystone home and suits most teams. Use MySQL for an existing managed database, its backups and high availability.' },
      { kind: 'code', label: 'Prepare MySQL (once)', code: `CREATE DATABASE keystone CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
CREATE USER 'keystone'@'%' IDENTIFIED BY 'a-long-random-password';
GRANT ALL PRIVILEGES ON keystone.* TO 'keystone'@'%';` },
      { kind: 'code', label: 'keystone.properties', code: `storage.database-url=mysql://keystone:a-long-random-password@db.example.com:3306/keystone?ssl-mode=required` },
      { kind: 'p', text: 'Keystone creates its tables on start. Choose it in the setup wizard (**Database → MySQL → Test connection**), or move a running vault, with all applications, secrets, users and audit history, with:' },
      { kind: 'code', label: 'Move an existing vault (stop Keystone first)', code: `keystone migrate --to "mysql://keystone:…@db.example.com:3306/keystone?ssl-mode=required"
keystone        # now runs on MySQL; the old SQLite file is left untouched` },
      { kind: 'list', items: [
        'On MySQL, backups are portable `.json` exports (still encrypted). `keystone restore FILE` restores `.db` or `.json` into either database.',
        'Percent-encode special characters in the password (`@` → `%40`). The URL is stored only in `keystone.properties` (mode 600) and is never shown in the console or logs.',
        'CI runs the entire test suite against MySQL 8.4 as well as SQLite.',
      ] },
    ],
  },
  {
    id: 'approvals', group: 'Administer', title: 'Protected environments & approvals',
    summary: 'Two-person control for production: every change needs a second administrator.',
    blocks: [
      { kind: 'p', text: 'An administrator protects an environment from its **⋯** menu. From then on, every set, delete, rollback, import and promote there becomes a **change request**: its proposed content is stored encrypted, and nothing changes until a *different* person approves it under **Security → Approvals**. Approvals show the current and proposed values side by side (audited as a reveal).' },
      { kind: 'list', items: [
        'You cannot approve your own change. Withdrawing it is recorded as cancelled.',
        'Approval applies the change exactly once, even if two people click at the same time.',
        'Values record who made them: `admin:alice (approved by admin:bob)`.',
        'Turning protection off needs an administrator, is audited, and triggers an alert.',
      ] },
      { kind: 'h', text: 'Compare & promote' },
      { kind: 'p', text: '**⋯ → Compare & promote** lists which keys and files differ between two environments without revealing any value, then copies the ones you tick. Into a protected environment, each item becomes a change request.' },
    ],
  },
  {
    id: 'reload', group: 'Integrate', title: 'Live reload & CLI',
    summary: 'Pick up changes without restarting, and use the keystone binary as a client.',
    blocks: [
      { kind: 'p', text: '`/api/v1/vault/config` sends an `ETag`. `If-None-Match` with the current one answers 304 (nothing is disclosed or audited). `/api/v1/vault/watch?version=…&timeout=30` waits until the configuration changes, then returns the new version, so a running app knows exactly when to fetch again.' },
      { kind: 'code', label: 'Node.js: watch and reload', code: `let version = null;
for (;;) {
  const r = await fetch(\`\${process.env.KEYSTONE_URL}/api/v1/vault/watch?timeout=30\${version ? '&version=' + version : ''}\`,
    { headers: { Authorization: \`Bearer \${process.env.KEYSTONE_TOKEN}\` } });
  const { version: latest, changed } = await r.json();
  if (changed || version === null) reload();   // fetch /api/v1/vault/config again
  version = latest;
}` },
      { kind: 'p', text: 'Spring Boot: add `spring-boot-starter-actuator` and call `POST /actuator/refresh` when the watch reports a change; `@RefreshScope` beans pick up the new values.' },
      { kind: 'h', text: 'keystone CLI' },
      { kind: 'code', label: 'Read-only, with an application token', code: `export KEYSTONE_URL={{ORIGIN}} KEYSTONE_TOKEN=ksv_...
keystone run -- ./start-my-app.sh          # every key as an environment variable
keystone pull --format=env --out=.env       # json | properties | env | shell
keystone get file application.properties --out=config/application.properties
keystone whoami` },
    ],
  },
  {
    id: 'backups', group: 'Operate', title: 'Backups, restore & key rotation',
    summary: 'Encrypted snapshots on a schedule, verified restores, and master-key rotation without re-encrypting.',
    blocks: [
      { kind: 'p', text: 'Keystone takes a consistent snapshot every `backup.interval-hours` (default 24) into `backup.dir`, keeping the newest `backup.keep`. **Settings → Backups** lists them, takes one now, and downloads them. Secrets stay encrypted inside; the master key is never included.' },
      { kind: 'code', label: 'Command line', code: `keystone backup                      # now, into backup.dir
keystone restore keystone-auto-20261103T020000Z.db   # stop the server first
keystone rotate-master-key           # stop the server first` },
      { kind: 'list', items: [
        '**Restore** first proves the snapshot opens with the current master key, then saves the current database as `*.pre-restore-*.db` before replacing it.',
        '**Rotate** re-wraps each application\'s key under a new master key (no secret is re-encrypted), takes a pre-rotation snapshot, installs the new key file, and keeps the old one as `master.key.retired-*`. You need the old key only to restore backups taken before the rotation: `keystone restore FILE --vault.master-key-file=secrets/master.key.retired-…`.',
        'Starting with the wrong master key is refused with a clear message, instead of failing every request.',
      ] },
    ],
  },
  {
    id: 'alerts', group: 'Operate', title: 'Alerts & health checks',
    summary: 'Hear about what matters immediately, and see what to fix in one list.',
    blocks: [
      { kind: 'p', text: '**Settings → Alerts** takes a Slack or Microsoft Teams incoming-webhook URL, or any HTTPS endpoint that accepts JSON (`text`, `event`, `subject`, `ip`, `time`). **Send test alert** checks it. The URL is stored encrypted.' },
      { kind: 'table', head: ['Alert', 'When'], rows: [
        ['Token refused', 'Wrong secret, revoked, expired, or from an address outside its allow-list'],
        ['Lockout', 'An IP made `security.failed-token-limit` failed attempts'],
        ['Protected reveal', 'Someone revealed a value in a protected environment'],
        ['Approval needed', 'A change request was created'],
        ['Deletion / protection off', 'An application, environment, key or file was deleted, or protection was removed'],
        ['Audit export, backup failed', 'Self-explanatory'],
      ] },
      { kind: 'p', text: 'Repeats are throttled to one per event, target and IP every 10 minutes. **Security → Health checks** ranks what to fix: backups off or stale, the master key stored only next to the data, expiring, unused or unrestricted tokens, keys not rotated, unprotected production environments, refused tokens and pending approvals.' },
    ],
  },
  {
    id: 'api', group: 'Reference', title: 'HTTP API',
    summary: 'Endpoints applications and administrators call.',
    blocks: [
      { kind: 'p', text: 'Applications send their token as `Authorization: Bearer ksv_…`, as `X-Keystone-Token`, or as HTTP Basic with any username and the token as the password. Admin endpoints need a Portal SSO access token with `ROLE_ADMIN`.' },
      { kind: 'endpoints' },
      { kind: 'table', head: ['Status', 'Code', 'Meaning'], rows: [
        ['401', '`invalid_vault_token`', 'Missing, wrong, revoked or expired token'],
        ['403', '`wrong_application`', 'Spring `spring.application.name` doesn\'t match the token\'s application'],
        ['404', '`item_not_found`', 'No such key or file in the environment or in `default`'],
        ['503', '`vault_sealed`', 'The server has no `KEYSTONE_MASTER_KEY`'],
        ['503', '`vault_key_mismatch`', 'The master key is not the one this data was written with'],
      ] },
    ],
  },
  {
    id: 'security', group: 'Reference', title: 'Security & operations',
    summary: 'How values are protected, and what operators must back up.',
    blocks: [
      { kind: 'list', items: [
        '**Envelope encryption:** `KEYSTONE_MASTER_KEY` wraps a random AES-256 key per application. Each value version is sealed with AES-256-GCM and bound to `app/env/name@version`, so a row moved in the database fails to decrypt.',
        '**Sealed by default:** without a master key, every vault endpoint returns 503.',
        '**Least privilege:** tokens are read-only and limited to one environment. Admin access requires Portal `ROLE_ADMIN`.',
        '**Masked UI:** values stay hidden until an administrator reveals them, and every reveal is audited.',
        '**Safe file serving:** raw files are served as attachments under a sandbox CSP, so uploaded HTML or SVG can\'t run on Keystone\'s origin.',
      ] },
      { kind: 'code', label: 'Generate the master key (once per deployment)', code: 'openssl rand -base64 32' },
      { kind: 'note', tone: 'warn', text: '**Back up the master key separately from the database.** Losing it makes every stored secret unrecoverable. Back up the SQLite database with its supported backup mechanism and test a restore.' },
      { kind: 'table', head: ['Setting', 'Purpose'], rows: [
        ['`KEYSTONE_MASTER_KEY`', '32 bytes, base64. Unset: vault sealed'],
        ['`PORTAL_URL` / `PORTAL_CLIENT_ID`', 'Portal SSO issuer and Keystone\'s public client'],
        ['`KEYSTONE_TRUST_PROXY`', '`true` only behind a reverse proxy (client IPs in audit)'],
        ['`server.port` / `server.address`', 'Listen address, default `127.0.0.1:8090`. Serve over HTTPS.'],
        ['`auth.local`', 'Local email + password accounts'],
        ['`storage.database-url`', 'SQLite (default) or `mysql://…`'],
      ] },
    ],
  },
];
