import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { HttpErrorResponse } from '@angular/common/http';
import { Api, SetupStatus } from './api';

type Step = 'license' | 'key' | 'signin' | 'database' | 'finish';
const STEPS: { id: Step; label: string; hint: string }[] = [
  { id: 'license', label: 'License', hint: 'Review and accept' },
  { id: 'key', label: 'Setup key', hint: 'Prove you run this server' },
  { id: 'signin', label: 'Sign-in', hint: 'Portal SSO and/or local accounts' },
  { id: 'database', label: 'Database', hint: 'Built-in SQLite or MySQL' },
  { id: 'finish', label: 'Finish', hint: 'Review and start' },
];

/** First-time setup: license → setup key → sign-in → database → finish (Portal SSO's flow). */
@Component({ selector: 'keystone-setup', standalone: true, templateUrl: './setup.html', styleUrl: './setup.css' })
export class SetupComponent implements OnInit {
  private api = inject(Api);
  readonly steps = STEPS;
  readonly step = signal<Step>('license');
  readonly index = computed(() => STEPS.findIndex(s => s.id === this.step()));
  readonly status = signal<SetupStatus | null>(null);
  readonly busy = signal(false);
  readonly error = signal('');

  // License
  readonly licenseText = signal('');
  readonly paragraphs = computed(() => this.licenseText().trim().split(/\n\s*\n/).map(p => p.replace(/\s+/g, ' ').trim()).filter(Boolean));
  readonly accepted = signal(false);
  // Key
  readonly key = signal('');
  // Sign-in
  readonly usePortal = signal(false);
  readonly portalUrl = signal('');
  readonly clientId = signal('keystone');
  readonly portalOk = signal(false);
  readonly useLocal = signal(true);
  readonly adminEmail = signal('');
  readonly adminName = signal('');
  readonly adminPassword = signal('');
  readonly adminConfirm = signal('');
  // Database
  readonly engine = signal<'sqlite' | 'mysql'>('sqlite');
  readonly mysql = signal({ host: '', port: '3306', database: 'keystone', user: 'keystone', password: '', tls: true });
  readonly databaseOk = signal('');
  // Finish
  readonly restarting = signal(false);

  readonly passwordProblem = computed(() => {
    const p = this.adminPassword();
    if (!p) return '';
    const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter(r => r.test(p)).length;
    if (p.length < 12) return 'Use at least 12 characters.';
    if (classes < 3) return 'Mix at least three of: lower case, upper case, digits, symbols.';
    if (this.adminConfirm() && this.adminConfirm() !== p) return 'The passwords do not match.';
    return '';
  });
  readonly mysqlUrl = computed(() => {
    const m = this.mysql(); const enc = encodeURIComponent;
    return `mysql://${enc(m.user)}:${enc(m.password)}@${m.host.trim()}:${m.port.trim() || '3306'}/${enc(m.database.trim())}${m.tls ? '?ssl-mode=required' : ''}`;
  });
  readonly portalFixed = computed(() => this.status()?.portal?.fixed ?? false);
  readonly existingPortal = computed(() => this.status()?.portal?.configured ?? false);
  readonly existingAdmins = computed(() => this.status()?.local?.admins ?? 0);
  readonly signInReady = computed(() => {
    const portal = this.usePortal() && (this.portalOk() || (this.existingPortal() && this.portalUrl() === this.status()?.portal?.url));
    const local = this.useLocal() && (this.existingAdmins() > 0 || (!!this.adminEmail().trim() && !!this.adminName().trim() && !!this.adminPassword() && this.adminPassword() === this.adminConfirm() && !this.passwordProblem()));
    return (portal || local) && (!this.usePortal() || portal) && (!this.useLocal() || local);
  });

  async ngOnInit(): Promise<void> {
    try {
      const [status, text] = await Promise.all([this.api.setup<SetupStatus>('GET', 'status'), this.api.setupText('license')]);
      this.status.set(status); this.licenseText.set(text);
      if (status.licenseAccepted) this.accepted.set(true);
      if (status.portal?.configured) { this.usePortal.set(true); this.portalUrl.set(status.portal.url); this.clientId.set(status.portal.clientId); this.useLocal.set((status.local?.admins ?? 0) > 0); }
      if ((status.local?.admins ?? 0) > 0) this.useLocal.set(true);
    } catch { this.error.set('Keystone could not be reached. Refresh the page.'); }
  }

  go(step: Step): void { if (STEPS.findIndex(s => s.id === step) <= this.index()) this.step.set(step); }

  async continueKey(): Promise<void> {
    await this.run(async () => {
      await this.api.setup('POST', 'verify', this.key().trim());
      await this.api.setup('POST', 'license', this.key().trim(), { accept: true, licenseId: this.status()?.licenseId ?? 'Apache-2.0' });
      this.step.set('signin');
    });
  }
  async testPortal(): Promise<void> {
    this.portalOk.set(false);
    await this.run(async () => {
      await this.api.setup('POST', 'portal/test', this.key().trim(), { url: this.portalUrl().trim().replace(/\/+$/, '') });
      this.portalOk.set(true);
    });
  }
  async testDatabase(): Promise<void> {
    this.databaseOk.set('');
    await this.run(async () => {
      const r = await this.api.setup<{ server: string }>('POST', 'database/test', this.key().trim(), { url: this.mysqlUrl() });
      this.databaseOk.set(r.server);
    });
  }
  setMysql(patch: Partial<{ host: string; port: string; database: string; user: string; password: string; tls: boolean }>): void {
    this.mysql.update(m => ({ ...m, ...patch })); this.databaseOk.set('');
  }
  async finish(): Promise<void> {
    await this.run(async () => {
      const r = await this.api.setup<{ restart: boolean }>('POST', 'finish', this.key().trim(), {
        portal: this.usePortal() && !(this.existingPortal() && this.portalUrl() === this.status()?.portal?.url && this.clientId() === this.status()?.portal?.clientId)
          ? { url: this.portalUrl().trim().replace(/\/+$/, ''), clientId: this.clientId().trim() } : null,
        admin: this.useLocal() && this.existingAdmins() === 0
          ? { email: this.adminEmail().trim(), name: this.adminName().trim(), password: this.adminPassword() } : null,
        databaseUrl: this.engine() === 'mysql' ? this.mysqlUrl() : null,
      });
      if (r.restart) { this.restarting.set(true); await this.waitForRestart(); }
      this.reload();
    });
  }
  /** Reloads into the sign-in page (overridable in tests). */
  reload = (): void => location.reload();
  private async waitForRestart(): Promise<void> {
    await new Promise(r => setTimeout(r, 1500));
    for (let i = 0; i < 60; i++) {
      try { const s = await this.api.setup<SetupStatus>('GET', 'status'); if (!s.required) return; } catch { /* restarting */ }
      await new Promise(r => setTimeout(r, 1000));
    }
  }
  private async run(task: () => Promise<void>): Promise<void> {
    this.busy.set(true); this.error.set('');
    try { await task(); }
    catch (e) {
      this.error.set(e instanceof HttpErrorResponse && typeof e.error?.error?.message === 'string' ? e.error.error.message : 'The request failed. Check that Keystone is running and retry.');
    } finally { this.busy.set(false); }
  }
}
