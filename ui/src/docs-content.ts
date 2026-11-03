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

export const DOC_GROUPS = ['Start here', 'Administer', 'Integrate', 'Reference'];

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
        ['`KEYSTONE_BIND`', 'Listen address, default `127.0.0.1:8090`. Serve over HTTPS.'],
      ] },
    ],
  },
];
