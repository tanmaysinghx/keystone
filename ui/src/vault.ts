import { Component, HostListener, OnInit, computed, effect, inject, input, signal, untracked } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Api, AuditEvent, IssuedToken, VaultApp, VaultItem, VaultStatus, VaultToken, VaultVersion } from './api';
import { VaultStore } from './vault-store';

type Tab = 'keys' | 'files' | 'tokens' | 'integrate' | 'activity';
interface Editor { name: string; value: string; isNew: boolean }
interface History { kind: 'keys' | 'files'; name: string; versions: VaultVersion[] }
interface Importer { format: 'properties' | 'env'; content: string; replace: boolean }
interface NewApp { id: string; name: string; description: string; portalClientId: string; environments: string }
interface TokenForm { name: string; environment: string; expiresInDays: number; allowedCidrs: string }
interface AllowList { token: VaultToken; value: string }
interface PromoteForm { from: string; diff: { item: string; status: string }[] | null; chosen: Record<string, boolean> }
interface Pending { pendingApproval?: number | number[]; message?: string }
interface Confirm { title: string; message: string; expect: string; typed: string; run: () => Promise<void> }

const BASE = '/api/v1/admin/vault';
const enc = encodeURIComponent;

@Component({ selector: 'keystone-vault', standalone: true, imports: [CommonModule], templateUrl: './vault.html', styleUrl: './vault.css' })
export class VaultComponent implements OnInit {
  private api = inject(Api);
  readonly portalUrl = input('');

  readonly store = inject(VaultStore);
  readonly status = this.store.status;
  readonly apps = this.store.apps;
  readonly selectedId = this.store.selectedId;
  readonly env = this.store.env;
  /** Open dropdown: 'app' (header overflow), 'env-add', or a row key. */
  readonly menu = signal<string | null>(null);
  readonly tab = signal<Tab>('keys');
  readonly items = this.store.items;
  readonly tokens = signal<VaultToken[]>([]);
  readonly audit = signal<AuditEvent[]>([]);
  readonly pullsOnly = signal(true);
  readonly revealed = signal<Record<string, string>>({});
  readonly filter = signal('');
  readonly busy = signal(false);
  readonly loaded = signal(false);
  readonly error = signal('');
  readonly toast = signal('');

  readonly editor = signal<Editor | null>(null);
  readonly history = signal<History | null>(null);
  readonly importer = signal<Importer | null>(null);
  readonly newApp = signal<NewApp | null>(null);
  readonly tokenForm = signal<TokenForm | null>(null);
  readonly issued = signal<IssuedToken | null>(null);
  readonly confirm = signal<Confirm | null>(null);
  readonly newEnv = signal('');
  readonly snippet = signal<'spring' | 'node' | 'shell' | 'cli' | 'reload' | 'file'>('spring');
  readonly allowList = signal<AllowList | null>(null);
  readonly promote = signal<PromoteForm | null>(null);
  readonly protectedEnv = computed(() => this.selected()?.protectedEnvironments?.includes(this.env()) ?? false);
  isProtected(env: string): boolean { return this.selected()?.protectedEnvironments?.includes(env) ?? false; }

  readonly selected = computed(() => this.apps().find(a => a.id === this.selectedId()) ?? null);
  readonly keyCount = computed(() => this.items().filter(i => i.kind === 'key').length);
  readonly fileCount = computed(() => this.items().filter(i => i.kind === 'file').length);
  readonly activeTokens = computed(() => this.tokens().filter(t => t.active).length);
  readonly keys = computed(() => this.items().filter(i => i.kind === 'key' && i.name.toLowerCase().includes(this.filter().trim().toLowerCase())));
  readonly files = computed(() => this.items().filter(i => i.kind === 'file' && i.name.toLowerCase().includes(this.filter().trim().toLowerCase())));
  readonly origin = typeof location === 'undefined' ? 'https://keystone.example' : location.origin;

  constructor() {
    effect(() => {
      const r = this.store.requestedApp(); if (!r) return;
      untracked(async () => {
        if (r.id !== this.selectedId() || (r.env && r.env !== this.env())) await this.select(r.id, r.env ?? 'default');
        if (r.item) { this.tab.set(r.item.kind === 'key' ? 'keys' : 'files'); this.filter.set(r.item.name); }
        else if (r.tab) await this.chooseTab(r.tab);
      });
    });
    effect(() => { if (this.store.newAppRequests() > 0) untracked(() => this.openNewApp()); });
  }
  async ngOnInit(): Promise<void> { await this.load(); }
  @HostListener('document:click') closeMenus(): void { this.menu.set(null); }
  toggleMenu(name: string, event: Event): void { event.stopPropagation(); this.menu.set(this.menu() === name ? null : name); }

  private path(...parts: string[]): string {
    return `${BASE}/apps/${enc(this.selectedId() ?? '')}${parts.length ? '/' + parts.join('/') : ''}`;
  }
  private envPath(...parts: string[]): string { return this.path('environments', enc(this.env()), ...parts); }

  async load(): Promise<void> {
    await this.run(async () => {
      const [status, apps] = await Promise.all([
        this.api.get<VaultStatus>(`${BASE}/status`),
        this.api.get<{ items: VaultApp[] }>(`${BASE}/apps`),
      ]);
      this.status.set(status); this.apps.set(apps.items);
      const current = this.selected();
      if (!current && apps.items.length) await this.select(apps.items[0].id);
      else if (current && !current.environments.includes(this.env())) this.env.set('default');
      if (this.selectedId()) await this.loadTab();
    });
    this.loaded.set(true);
  }

  async select(id: string, env = 'default'): Promise<void> {
    this.selectedId.set(id); this.env.set(env); this.revealed.set({}); this.filter.set('');
    if (this.tab() === 'activity' || this.tab() === 'tokens' || this.tab() === 'integrate') { /* keep tab */ } else this.tab.set('keys');
    await this.run(() => this.loadTab());
  }
  async chooseEnv(env: string): Promise<void> { this.env.set(env); this.revealed.set({}); await this.run(() => this.loadTab()); }
  async togglePulls(on: boolean): Promise<void> { this.pullsOnly.set(on); await this.run(() => this.loadTab()); }
  async chooseTab(tab: Tab): Promise<void> { this.tab.set(tab); await this.run(() => this.loadTab()); }

  private async loadTab(): Promise<void> {
    if (!this.selectedId()) return;
    const tab = this.tab();
    this.items.set((await this.api.get<{ items: VaultItem[] }>(this.envPath('items'))).items);
    if (tab === 'tokens' || tab === 'integrate') this.tokens.set((await this.api.get<{ items: VaultToken[] }>(this.path('tokens'))).items);
    if (tab === 'activity') this.audit.set((await this.api.get<{ items: AuditEvent[] }>(`${BASE}/audit?app=${enc(this.selectedId()!)}${this.pullsOnly() ? '&kind=pulls' : ''}`)).items);
  }
  private async refreshApps(): Promise<void> {
    this.apps.set((await this.api.get<{ items: VaultApp[] }>(`${BASE}/apps`)).items);
    this.status.set(await this.api.get<VaultStatus>(`${BASE}/status`));
  }

  // ----- applications & environments
  openNewApp(): void { this.newApp.set({ id: '', name: '', description: '', portalClientId: '', environments: 'dev, staging, prod' }); }
  patchNewApp(patch: Partial<NewApp>): void {
    const current = this.newApp(); if (!current) return;
    const next = { ...current, ...patch };
    // Default the id (and Portal client id) from the name, Portal's own slug rule.
    if (patch.name !== undefined && (current.id === '' || current.id === slug(current.name))) next.id = slug(patch.name);
    if (patch.name !== undefined && (current.portalClientId === '' || current.portalClientId === slug(current.name))) next.portalClientId = slug(patch.name);
    this.newApp.set(next);
  }
  async createApp(): Promise<void> {
    const form = this.newApp(); if (!form) return;
    await this.run(async () => {
      await this.api.send('POST', `${BASE}/apps`, {
        id: form.id.trim(), name: form.name.trim(), description: form.description.trim(),
        portalClientId: form.portalClientId.trim() || null,
        environments: form.environments.split(',').map(e => e.trim().toLowerCase()).filter(Boolean),
      });
      this.newApp.set(null); await this.refreshApps(); await this.select(form.id.trim());
      this.flash(`${form.name.trim()} created with its own encryption key.`);
    });
  }
  async addEnv(): Promise<void> {
    const name = this.newEnv().trim().toLowerCase(); if (!name) return;
    await this.run(async () => {
      await this.api.send('POST', this.path('environments'), { name });
      this.newEnv.set(''); this.menu.set(null); await this.refreshApps(); await this.chooseEnv(name);
    });
  }
  askDeleteEnv(): void {
    const env = this.env();
    this.confirm.set({ title: `Delete environment “${env}”?`, message: 'Every key, file, version and access token in this environment is destroyed. Applications using its tokens stop receiving configuration.', expect: env, typed: '',
      run: async () => { await this.api.send('DELETE', `${this.path('environments', enc(env))}?confirm=${enc(env)}`); await this.refreshApps(); await this.chooseEnv('default'); } });
  }
  askDeleteApp(): void {
    const app = this.selected(); if (!app) return;
    this.confirm.set({ title: `Delete ${app.name}?`, message: 'The application, its encryption key, every secret, file, version and access token are permanently destroyed. This cannot be undone.', expect: app.id, typed: '',
      run: async () => { await this.api.send('DELETE', `${this.path()}?confirm=${enc(app.id)}`); this.selectedId.set(null); await this.load(); } });
  }

  // ----- keys
  async reveal(name: string): Promise<void> {
    if (name in this.revealed()) { const { [name]: _, ...rest } = this.revealed(); this.revealed.set(rest); return; }
    await this.run(async () => {
      const result = await this.api.get<{ value: string }>(this.envPath('keys', enc(name)));
      this.revealed.update(r => ({ ...r, [name]: result.value }));
    });
  }
  async copyKey(name: string): Promise<void> {
    await this.run(async () => {
      const value = this.revealed()[name] ?? (await this.api.get<{ value: string }>(this.envPath('keys', enc(name)))).value;
      await navigator.clipboard.writeText(value); this.flash(`Copied ${name}. The clipboard is outside Keystone's protection.`);
    });
  }
  openEditor(name?: string): void {
    if (name === undefined) { this.editor.set({ name: '', value: '', isNew: true }); return; }
    const known = this.revealed()[name];
    if (known !== undefined) { this.editor.set({ name, value: known, isNew: false }); return; }
    void this.run(async () => {
      const result = await this.api.get<{ value: string }>(this.envPath('keys', enc(name)));
      this.editor.set({ name, value: result.value, isNew: false });
    });
  }
  async saveKey(): Promise<void> {
    const form = this.editor(); if (!form) return;
    const name = form.name.trim();
    await this.run(async () => {
      if (form.isNew && this.items().some(i => i.kind === 'key' && i.name === name)) throw new Error(`“${name}” already exists in ${this.env()}. Edit it instead.`);
      const result = await this.api.send<{ version: number } & Pending>('PUT', this.envPath('keys', enc(name)), { value: form.value });
      this.editor.set(null); this.revealed.update(({ [name]: _, ...rest }) => rest);
      await this.loadTab(); await this.refreshApps();
      if (!this.pending(result)) this.flash(`${name} saved as version ${result.version}.`);
    });
  }
  askDelete(kind: 'keys' | 'files', name: string): void {
    this.confirm.set({ title: `Delete ${name}?`, message: `The ${kind === 'keys' ? 'key' : 'file'} and all of its versions are removed from ${this.env()}. Applications reading it will no longer receive it.`, expect: '', typed: '',
      run: async () => { const r = await this.api.send<Pending | null>('DELETE', this.envPath(kind, enc(name))); await this.loadTab(); await this.refreshApps(); this.pending(r); } });
  }
  async showHistory(kind: 'keys' | 'files', name: string): Promise<void> {
    await this.run(async () => {
      const result = await this.api.get<{ items: VaultVersion[] }>(this.envPath(kind, enc(name), 'versions'));
      this.history.set({ kind, name, versions: result.items });
    });
  }
  async rollback(version: number): Promise<void> {
    const history = this.history(); if (!history) return;
    await this.run(async () => {
      const result = await this.api.send<{ version: number } & Pending>('POST', this.envPath(history.kind, enc(history.name), 'rollback'), { version });
      this.history.set(null); this.revealed.set({}); await this.loadTab();
      if (!this.pending(result)) this.flash(`Restored version ${version} of ${history.name} as version ${result.version}.`);
    });
  }
  async viewVersion(version: number): Promise<void> {
    const history = this.history(); if (!history) return;
    if (history.kind === 'files') { await this.download(history.name, version); return; }
    await this.run(async () => {
      const result = await this.api.get<{ value: string }>(`${this.envPath('keys', enc(history.name))}?version=${version}`);
      this.revealed.update(r => ({ ...r, [`${history.name}@${version}`]: result.value }));
    });
  }

  // ----- import / export
  openImport(): void { this.importer.set({ format: 'properties', content: '', replace: false }); }
  async importFile(event: Event): Promise<void> {
    const file = (event.target as HTMLInputElement).files?.[0]; if (!file) return;
    const content = await file.text();
    this.importer.update(i => i && { ...i, content, format: /\.env$|^\.env/.test(file.name) ? 'env' : 'properties' });
  }
  async runImport(): Promise<void> {
    const form = this.importer(); if (!form) return;
    await this.run(async () => {
      const r = await this.api.send<{ written: number; unchanged: number; removed: number } & Pending>('POST', this.envPath('import'), form);
      this.importer.set(null); this.revealed.set({}); await this.loadTab(); await this.refreshApps();
      if (!this.pending(r)) this.flash(`Imported into ${this.env()}: ${r.written} written, ${r.unchanged} unchanged${r.removed ? `, ${r.removed} removed` : ''}.`);
    });
  }
  async exportConfig(format: 'properties' | 'env'): Promise<void> {
    await this.run(async () => {
      const text = await this.api.text(`${this.envPath('config')}?format=${format}`);
      save(new Blob([text], { type: 'text/plain' }), format === 'env' ? `${this.selectedId()}-${this.env()}.env` : `${this.selectedId()}-${this.env()}.properties`);
    });
  }

  // ----- files
  async upload(event: Event): Promise<void> {
    const input = event.target as HTMLInputElement; const file = input.files?.[0]; input.value = '';
    if (!file) return;
    const name = file.name.replace(/[^A-Za-z0-9._-]/g, '-').replace(/^\.+/, '');
    await this.run(async () => {
      if (file.size > 512 * 1024) throw new Error('Files are limited to 512 KiB.');
      const result = await this.api.send<{ version: number } & Pending>('PUT', this.envPath('files', enc(name)), file, file.type || guessType(name));
      await this.loadTab(); await this.refreshApps();
      if (!this.pending(result)) this.flash(`${name} stored as version ${result.version}.`);
    });
  }
  async download(name: string, version?: number): Promise<void> {
    await this.run(async () => save(await this.api.blob(`${this.envPath('files', enc(name))}${version ? `?version=${version}` : ''}`), name));
  }

  // ----- tokens
  openTokenForm(): void { this.tokenForm.set({ name: `${this.selectedId()} ${this.env()}`, environment: this.env(), expiresInDays: 365, allowedCidrs: '' }); }
  openAllowList(token: VaultToken): void { this.allowList.set({ token, value: token.allowedCidrs ?? '' }); }
  async saveAllowList(): Promise<void> {
    const form = this.allowList(); if (!form) return;
    await this.run(async () => {
      await this.api.send('PATCH', this.path('tokens', enc(form.token.id)), { allowedCidrs: form.value.trim() });
      this.allowList.set(null); await this.loadTab();
      this.flash(form.value.trim() ? `“${form.token.name}” now works only from ${form.value.trim()}.` : `“${form.token.name}” works from any address.`);
    });
  }
  async createToken(): Promise<void> {
    const form = this.tokenForm(); if (!form) return;
    await this.run(async () => {
      const issued = await this.api.send<IssuedToken>('POST', this.path('tokens'), { name: form.name.trim(), environment: form.environment, expiresInDays: Number(form.expiresInDays) || 0, allowedCidrs: form.allowedCidrs.trim() || null });
      this.tokenForm.set(null); this.issued.set(issued); await this.loadTab(); await this.refreshApps();
    });
  }
  askRevoke(token: VaultToken): void {
    this.confirm.set({ title: `Revoke “${token.name}”?`, message: 'Any application using this token is refused immediately, including on its next restart.', expect: '', typed: '',
      run: async () => { await this.api.send('DELETE', this.path('tokens', enc(token.id))); await this.loadTab(); await this.refreshApps(); } });
  }
  async copy(text: string, what = 'Copied'): Promise<void> {
    try { await navigator.clipboard.writeText(text); this.flash(`${what} to the clipboard.`); }
    catch { this.error.set('The browser blocked clipboard access. Select the text and copy it manually.'); }
  }

  // ----- protection & promote
  async setProtection(on: boolean): Promise<void> {
    const env = this.env();
    if (!on) {
      this.confirm.set({ title: `Remove protection from ${env}?`, message: 'Changes to this environment will apply immediately, without a second administrator. This is audited and alerted.', expect: env, typed: '',
        run: async () => { await this.api.send('PUT', this.envPath('protection'), { protected: false }); await this.refreshApps(); this.flash(`${env} is no longer protected.`); } });
      return;
    }
    await this.run(async () => { await this.api.send('PUT', this.envPath('protection'), { protected: true }); await this.refreshApps(); this.flash(`${env} is protected: every change now needs another administrator's approval.`); });
  }
  openPromote(): void {
    const from = this.selected()?.environments.find(e => e !== this.env() && e !== 'default') ?? 'default';
    this.promote.set({ from, diff: null, chosen: {} }); void this.comparePromote();
  }
  async comparePromote(): Promise<void> {
    const form = this.promote(); if (!form) return;
    await this.run(async () => {
      const r = await this.api.send<{ diff: { item: string; status: string }[] }>('POST', this.envPath('promote'), { from: form.from, dryRun: true });
      const chosen: Record<string, boolean> = {};
      for (const d of r.diff) if (d.status === 'added' || d.status === 'changed') chosen[d.item] = true;
      this.promote.set({ ...form, diff: r.diff, chosen });
    });
  }
  async applyPromote(): Promise<void> {
    const form = this.promote(); if (!form) return;
    const items = Object.entries(form.chosen).filter(([, on]) => on).map(([item]) => item);
    await this.run(async () => {
      const r = await this.api.send<{ copied: number; pendingApproval: number[] }>('POST', this.envPath('promote'), { from: form.from, items });
      this.promote.set(null); await this.loadTab(); await this.refreshApps();
      if (r.pendingApproval.length) { this.store.badges.update(b => ({ ...b, approvals: b.approvals + r.pendingApproval.length })); this.flash(`${r.pendingApproval.length} changes submitted for approval in ${this.env()}.`); }
      else this.flash(`Copied ${r.copied} items from ${form.from} into ${this.env()}.`);
    });
  }
  choose(item: string, on: boolean): void { this.promote.update(p => p && { ...p, chosen: { ...p.chosen, [item]: on } }); }
  itemLabel(item: string): string { return item.replace(/^(key|file):/, ''); }
  /** A protected environment answers 202 with a change request instead of applying. */
  private pending(result: Pending | null | undefined): boolean {
    const ids = result?.pendingApproval; if (ids === undefined) return false;
    const count = Array.isArray(ids) ? ids.length : 1;
    this.store.badges.update(b => ({ ...b, approvals: b.approvals + count }));
    this.flash(`${this.env()} is protected: your change is waiting for another administrator in Approvals.`);
    return true;
  }

  // ----- confirmation
  async confirmRun(): Promise<void> {
    const c = this.confirm(); if (!c || (c.expect && c.typed !== c.expect)) return;
    await this.run(async () => { await c.run(); this.confirm.set(null); });
  }

  // ----- integration snippets
  readonly snippets = computed(() => {
    const app = this.selectedId() ?? 'my-app'; const url = this.origin;
    return {
      spring: `# pom.xml: org.springframework.cloud:spring-cloud-starter-config
# application.properties: everything else comes from Keystone Vault
spring.application.name=${app}
spring.config.import=configserver:
spring.cloud.config.uri=${url}/config
spring.cloud.config.username=keystone
spring.cloud.config.password=\${KEYSTONE_TOKEN}
spring.cloud.config.fail-fast=true`,
      node: `// vault.mjs: node --import ./vault.mjs server.js
// Loads every key into process.env before the app starts (spring.datasource.url -> SPRING_DATASOURCE_URL).
const response = await fetch('${url}/api/v1/vault/config', {
  headers: { Authorization: \`Bearer \${process.env.KEYSTONE_TOKEN}\` },
  signal: AbortSignal.timeout(5000),
});
if (!response.ok) throw new Error(\`Keystone Vault refused configuration: HTTP \${response.status}\`);
for (const [key, value] of Object.entries(await response.json())) {
  const name = key.replace(/\\]/g, '').replace(/[^A-Za-z0-9]/g, '_').toUpperCase();
  process.env[name] ??= value;
}`,
      shell: `#!/bin/sh
# docker-entrypoint.sh: export every key, then start the app
set -eu
eval "$(curl -fsS -H "Authorization: Bearer $KEYSTONE_TOKEN" '${url}/api/v1/vault/config?format=shell')"
exec "$@"`,
      cli: `# The keystone binary doubles as a client (same read-only token)
export KEYSTONE_URL=${url} KEYSTONE_TOKEN=ksv_...

# Start any app with every key as an environment variable
keystone run -- java -jar ${app}.jar

# Or write the configuration / a whole file to disk
keystone pull --format=properties --out=config/application.properties
keystone get file application.properties --out=config/application.properties
keystone get key spring.datasource.password`,
      reload: `// Reload without restarting: long-poll for a new version, then fetch again.
// (Spring Boot: add spring-boot-starter-actuator and POST /actuator/refresh when it changes.)
let version = null;
for (;;) {
  const r = await fetch(\`${url}/api/v1/vault/watch?timeout=30\${version ? '&version=' + version : ''}\`,
    { headers: { Authorization: \`Bearer \${process.env.KEYSTONE_TOKEN}\` } });
  const { version: latest, changed } = await r.json();
  if (changed || version === null) applyConfig(await (await fetch('${url}/api/v1/vault/config',
    { headers: { Authorization: \`Bearer \${process.env.KEYSTONE_TOKEN}\` } })).json());
  version = latest;
}`,
      file: `# Whole files, byte for byte (falls back to the default environment)
curl -fsS -H "Authorization: Bearer $KEYSTONE_TOKEN" \\
  -o config/application.properties '${url}/api/v1/vault/files/application.properties'

# One key, as plain text
curl -fsS -H "Authorization: Bearer $KEYSTONE_TOKEN" '${url}/api/v1/vault/keys/spring.datasource.password'

# Merged configuration as .properties / .env / JSON
curl -fsS -H "Authorization: Bearer $KEYSTONE_TOKEN" '${url}/api/v1/vault/config?format=properties'`,
    };
  });

  // ----- helpers
  size(bytes: number): string { return bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(1)} KiB`; }
  who(subject: string): string { return subject.replace(/^admin:/, '').replace(/^token:\S+ \((.*)\)$/, 'app · $1').replace(/^token:/, 'token '); }
  isApp(subject: string): boolean { return subject.startsWith('token:'); }
  client(ua: string | null): string {
    if (!ua) return '—';
    const known = /(Java-http-client|ReactorNetty|Apache-HttpClient|okhttp|curl|node|undici|Wget|python-requests|Go-http-client)[/ ]?[\w.]*/i.exec(ua);
    if (known) return known[0];
    const browser = /(Firefox|Edg|Chrome|Safari)\/[\d]+/.exec(ua);
    return browser ? browser[0].replace('Edg', 'Edge') : ua.slice(0, 40);
  }
  label(event: string): string {
    return ({ 'vault.app.create': 'Created application', 'vault.app.update': 'Updated application', 'vault.app.delete': 'Deleted application',
      'vault.environment.create': 'Added environment', 'vault.environment.delete': 'Deleted environment', 'vault.key.write': 'Wrote key',
      'vault.key.reveal': 'Revealed key', 'vault.key.delete': 'Deleted key', 'vault.key.rollback': 'Rolled back key', 'vault.key.read': 'App read key',
      'vault.file.write': 'Uploaded file', 'vault.file.reveal': 'Downloaded file', 'vault.file.delete': 'Deleted file', 'vault.file.rollback': 'Rolled back file',
      'vault.file.read': 'App read file', 'vault.import': 'Imported file', 'vault.config.read': 'App loaded configuration', 'vault.config.reveal': 'Exported configuration',
      'vault.token.create': 'Issued token', 'vault.token.revoke': 'Revoked token', 'vault.token.denied': 'Token refused' } as Record<string, string>)[event] ?? event;
  }
  private flash(message: string): void { this.toast.set(message); setTimeout(() => { if (this.toast() === message) this.toast.set(''); }, 4000); }
  private async run(task: () => Promise<void>): Promise<void> {
    this.busy.set(true); this.error.set('');
    try { await task(); }
    catch (error) { this.error.set(message(error)); }
    finally { this.busy.set(false); }
  }
}

function slug(text: string): string { return text.toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 63); }
function guessType(name: string): string {
  if (name.endsWith('.properties')) return 'text/x-java-properties';
  if (name.endsWith('.json')) return 'application/json';
  if (/\.ya?ml$/.test(name)) return 'application/yaml';
  if (/\.(env|txt|conf|ini|pem|crt|key)$/.test(name)) return 'text/plain';
  return 'application/octet-stream';
}
function save(blob: Blob, name: string): void {
  const url = URL.createObjectURL(blob); const a = document.createElement('a');
  a.href = url; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function message(error: unknown): string {
  if (error instanceof HttpErrorResponse) {
    const server = error.error?.error?.message;
    if (typeof server === 'string') return server;
    if (error.status === 401) return 'Your session has ended. Sign in with Portal SSO again.';
    if (error.status === 403) return 'Administrator access is required.';
    return 'Keystone could not complete the request. Retry in a moment.';
  }
  return error instanceof Error ? error.message : 'Something went wrong.';
}
