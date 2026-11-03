import { Component, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Api, Backup, LocalUser, ServerSettings } from './api';
import { VaultStore } from './vault-store';

/** Administration → Settings: alerts, backups, and how this server is configured. */
@Component({ selector: 'keystone-settings', standalone: true, imports: [CommonModule], templateUrl: './settings.html', styleUrl: './screens.css' })
export class SettingsComponent implements OnInit {
  private api = inject(Api);
  readonly s = signal<ServerSettings | null>(null);
  readonly backups = signal<Backup[]>([]);
  readonly store = inject(VaultStore);
  readonly users = signal<LocalUser[]>([]);
  readonly localEnabled = signal(false);
  readonly userForm = signal<{ id: number | null; email: string; name: string; password: string; admin: boolean; apps: string } | null>(null);
  readonly webhook = signal('');
  readonly busy = signal(false);
  readonly error = signal('');
  readonly toast = signal('');

  async ngOnInit(): Promise<void> { await this.load(); }
  async load(): Promise<void> {
    try {
      const [s, b, u] = await Promise.all([
        this.api.get<ServerSettings>('/api/v1/admin/vault/settings'),
        this.api.get<{ items: Backup[] }>('/api/v1/admin/vault/backups'),
        this.api.get<{ enabled: boolean; items: LocalUser[] }>('/api/v1/admin/users'),
      ]);
      this.s.set(s); this.backups.set(b.items); this.users.set(u.items); this.localEnabled.set(u.enabled); this.error.set('');
    } catch (e) { this.error.set(this.message(e)); }
  }
  async saveWebhook(remove = false): Promise<void> {
    await this.run(async () => {
      await this.api.send('PUT', '/api/v1/admin/vault/settings/alerts', { webhookUrl: remove ? null : this.webhook().trim() });
      this.webhook.set(''); await this.load(); this.flash(remove ? 'Webhook removed.' : 'Webhook saved. Send a test alert to check it.');
    });
  }
  async testAlert(): Promise<void> {
    await this.run(async () => {
      const r = await this.api.send<{ delivered: boolean; error: string | null }>('POST', '/api/v1/admin/vault/settings/alerts/test', {});
      if (r.delivered) this.flash('Test alert delivered.'); else this.error.set(`The webhook did not accept the alert: ${r.error ?? 'unknown error'}`);
    });
  }
  async backupNow(): Promise<void> {
    await this.run(async () => { const r = await this.api.send<{ name: string }>('POST', '/api/v1/admin/vault/backups', {}); await this.load(); this.flash(`Backup ${r.name} written.`); });
  }
  async download(b: Backup): Promise<void> {
    await this.run(async () => {
      const blob = await this.api.blob(`/api/v1/admin/vault/backups/${encodeURIComponent(b.name)}`);
      const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = b.name; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
  }
  // ----- local users
  newUser(): void { this.userForm.set({ id: null, email: '', name: '', password: '', admin: false, apps: '' }); }
  editUser(u: LocalUser): void {
    this.userForm.set({ id: u.id, email: u.email, name: u.name, password: '', admin: u.roles.includes('ROLE_ADMIN'),
      apps: u.roles.filter(r => r.startsWith('ROLE_VAULT_')).map(r => r.slice(11).toLowerCase().replace(/_/g, '-')).join(', ') });
  }
  patchUser(patch: Partial<{ email: string; name: string; password: string; admin: boolean; apps: string }>): void { this.userForm.update(f => f && { ...f, ...patch }); }
  private roles(f: { admin: boolean; apps: string }): string[] {
    const apps = f.apps.split(/[\s,]+/).map(a => a.trim()).filter(Boolean).map(a => 'ROLE_VAULT_' + a.toUpperCase().replace(/-/g, '_'));
    return [...(f.admin ? ['ROLE_ADMIN'] : []), ...apps];
  }
  async saveUser(): Promise<void> {
    const f = this.userForm(); if (!f) return;
    await this.run(async () => {
      if (f.id === null) await this.api.send('POST', '/api/v1/admin/users', { email: f.email.trim(), name: f.name.trim(), password: f.password, roles: this.roles(f) });
      else await this.api.send('PATCH', `/api/v1/admin/users/${f.id}`, { name: f.name.trim(), roles: this.roles(f), ...(f.password ? { password: f.password } : {}) });
      this.userForm.set(null); await this.load(); this.flash(f.id === null ? `${f.email} can now sign in.` : `${f.email} updated.`);
    });
  }
  async toggleUser(u: LocalUser): Promise<void> {
    await this.run(async () => { await this.api.send('PATCH', `/api/v1/admin/users/${u.id}`, { disabled: !u.disabled }); await this.load(); this.flash(u.disabled ? `${u.email} enabled.` : `${u.email} disabled and signed out.`); });
  }
  async deleteUser(u: LocalUser): Promise<void> {
    await this.run(async () => { await this.api.send('DELETE', `/api/v1/admin/users/${u.id}`); await this.load(); this.flash(`${u.email} deleted.`); });
  }
  roleLabel(r: string): string { return r === 'ROLE_ADMIN' ? 'Administrator' : r.slice(11).toLowerCase().replace(/_/g, '-'); }
  size(n: number): string { return n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} KiB` : `${(n / 1048576).toFixed(1)} MiB`; }
  private async run(task: () => Promise<void>): Promise<void> {
    this.busy.set(true); this.error.set('');
    try { await task(); } catch (e) { this.error.set(this.message(e)); } finally { this.busy.set(false); }
  }
  private flash(m: string): void { this.toast.set(m); setTimeout(() => { if (this.toast() === m) this.toast.set(''); }, 4000); }
  private message(e: unknown): string {
    return e instanceof HttpErrorResponse && typeof e.error?.error?.message === 'string' ? e.error.error.message : 'The request failed. Retry in a moment.';
  }
}
