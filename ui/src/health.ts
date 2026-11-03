import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { Api, Finding, Insights } from './api';
import { VaultStore } from './vault-store';

/** Security → Health checks: what to fix, ranked, each with a way to go and fix it. */
@Component({ selector: 'keystone-health', standalone: true, templateUrl: './health.html', styleUrl: './screens.css' })
export class HealthComponent implements OnInit {
  private api = inject(Api);
  readonly store = inject(VaultStore);
  readonly data = signal<Insights | null>(null);
  readonly severity = signal<'all' | 'high' | 'medium' | 'low'>('all');
  readonly error = signal('');
  readonly items = computed(() => (this.data()?.items ?? []).filter(f => this.severity() === 'all' || f.severity === this.severity()));

  async ngOnInit(): Promise<void> { await this.load(); }
  async load(): Promise<void> {
    try {
      const data = await this.api.get<Insights>('/api/v1/admin/vault/insights');
      this.data.set(data); this.error.set('');
      this.store.badges.update(b => ({ ...b, health: data.counts.high + data.counts.medium, approvals: data.counts.pendingApprovals }));
    } catch { this.error.set('Health checks could not be loaded. Retry in a moment.'); }
  }
  open(f: Finding): void {
    if (f.action === 'settings') { this.store.show('settings'); return; }
    if (f.action === 'approvals') { this.store.show('approvals'); return; }
    if (f.action === 'audit') { this.store.show('audit'); return; }
    if (!f.app) return;
    const tab = f.action === 'tokens' ? 'tokens' : f.action === 'keys' ? 'keys' : undefined;
    this.store.select(f.app, f.environment ?? undefined, undefined, tab);
  }
  label(f: Finding): string {
    return ({ settings: 'Open settings', approvals: 'Review', audit: 'Open audit log', tokens: 'Open tokens', keys: 'Open keys', protect: 'Open environment' } as Record<string, string>)[f.action] ?? 'Open';
  }
}
