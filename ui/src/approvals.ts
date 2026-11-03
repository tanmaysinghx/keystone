import { Component, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Api, ChangeRequest } from './api';
import { VaultStore } from './vault-store';

/** Security → Approvals: changes to protected environments, waiting for a second administrator. */
@Component({ selector: 'keystone-approvals', standalone: true, imports: [CommonModule], templateUrl: './approvals.html', styleUrl: './screens.css' })
export class ApprovalsComponent implements OnInit {
  private api = inject(Api);
  readonly store = inject(VaultStore);
  readonly status = signal<'pending' | 'all'>('pending');
  readonly items = signal<ChangeRequest[]>([]);
  readonly review = signal<Record<number, { proposed: string | null; current: string | null }>>({});
  readonly busy = signal<number | null>(null);
  readonly error = signal('');
  readonly toast = signal('');
  readonly loaded = signal(false);

  async ngOnInit(): Promise<void> { await this.load(); }
  async load(): Promise<void> {
    try {
      const r = await this.api.get<{ items: ChangeRequest[] }>(`/api/v1/admin/vault/changes?status=${this.status()}`);
      this.items.set(r.items); this.error.set('');
      if (this.status() === 'pending') this.store.badges.update(b => ({ ...b, approvals: r.items.length }));
    } catch (e) { this.error.set(this.message(e)); }
    this.loaded.set(true);
  }
  setStatus(s: 'pending' | 'all'): void { this.status.set(s); void this.load(); }
  async show(c: ChangeRequest): Promise<void> {
    if (this.review()[c.id]) { const { [c.id]: _, ...rest } = this.review(); this.review.set(rest); return; }
    try { const r = await this.api.get<{ proposed: string | null; current: string | null }>(`/api/v1/admin/vault/changes/${c.id}/reveal`); this.review.update(v => ({ ...v, [c.id]: r })); }
    catch (e) { this.error.set(this.message(e)); }
  }
  async decide(c: ChangeRequest, decision: 'approve' | 'reject'): Promise<void> {
    this.busy.set(c.id); this.error.set('');
    try {
      await this.api.send('POST', `/api/v1/admin/vault/changes/${c.id}/${decision}`, {});
      this.flash(decision === 'approve' ? `Applied: ${c.summary} in ${c.app}/${c.environment}.` : `Withdrawn or rejected: ${c.summary}.`);
      await this.load();
    } catch (e) { this.error.set(this.message(e)); }
    finally { this.busy.set(null); }
  }
  who(s: string | null): string { return (s ?? '').replace(/admin:/g, ''); }
  private flash(m: string): void { this.toast.set(m); setTimeout(() => { if (this.toast() === m) this.toast.set(''); }, 4000); }
  private message(e: unknown): string {
    return e instanceof HttpErrorResponse && typeof e.error?.error?.message === 'string' ? e.error.error.message : 'The request failed. Retry in a moment.';
  }
}
