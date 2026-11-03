import { Component, OnDestroy, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Api, AuditEvent } from './api';
import { VaultStore } from './vault-store';
import { clientName, eventLabel, eventTone, isAppSubject, subjectName } from './audit-format';

type Kind = 'all' | 'pulls' | 'changes' | 'denied' | 'tokens';
type Range = '24h' | '7d' | '30d' | 'all';
interface Summary { pulls: number; denied: number; changes: number; distinctIps: number; activeTokens: number }
const RANGE_SECONDS: Record<Range, number | null> = { '24h': 86400, '7d': 7 * 86400, '30d': 30 * 86400, all: null };

/** Every vault event across applications: who pulled which secrets, when, and from where. */
@Component({ selector: 'keystone-audit', standalone: true, imports: [CommonModule], templateUrl: './audit.html', styleUrl: './audit.css' })
export class AuditComponent implements OnInit, OnDestroy {
  private api = inject(Api);
  readonly store = inject(VaultStore);
  readonly kinds: [Kind, string][] = [['all', 'All'], ['pulls', 'Secret pulls'], ['changes', 'Changes'], ['denied', 'Refused'], ['tokens', 'Tokens']];
  readonly ranges: Range[] = ['24h', '7d', '30d', 'all'];
  readonly kind = signal<Kind>('all');
  readonly range = signal<Range>('7d');
  readonly app = signal('');
  readonly q = signal('');
  readonly items = signal<AuditEvent[]>([]);
  readonly next = signal<number | null>(null);
  readonly summary = signal<Summary | null>(null);
  readonly expanded = signal<number | null>(null);
  readonly busy = signal(false);
  readonly loaded = signal(false);
  readonly error = signal('');
  readonly label = eventLabel; readonly tone = eventTone; readonly isApp = isAppSubject; readonly who = subjectName; readonly client = clientName;
  private debounce?: ReturnType<typeof setTimeout>;

  async ngOnInit(): Promise<void> { await this.reload(); }
  ngOnDestroy(): void { clearTimeout(this.debounce); }

  private query(extra: Record<string, string | number> = {}): string {
    const params = new URLSearchParams();
    if (this.app()) params.set('app', this.app());
    if (this.kind() !== 'all') params.set('kind', this.kind());
    if (this.q().trim()) params.set('q', this.q().trim());
    const span = RANGE_SECONDS[this.range()];
    if (span) params.set('from', String(Math.floor(Date.now() / 1000) - span));
    for (const [k, v] of Object.entries(extra)) params.set(k, String(v));
    return params.toString();
  }

  async reload(): Promise<void> {
    await this.run(async () => {
      const [page, summary] = await Promise.all([
        this.api.get<{ items: AuditEvent[]; nextBefore: number | null }>(`/api/v1/admin/vault/audit?${this.query({ limit: 100 })}`),
        this.api.get<Summary>(`/api/v1/admin/vault/audit/summary${this.app() ? `?app=${encodeURIComponent(this.app())}` : ''}`),
      ]);
      this.items.set(page.items); this.next.set(page.nextBefore); this.summary.set(summary);
    });
    this.loaded.set(true);
  }
  async more(): Promise<void> {
    const before = this.next(); if (before === null) return;
    await this.run(async () => {
      const page = await this.api.get<{ items: AuditEvent[]; nextBefore: number | null }>(`/api/v1/admin/vault/audit?${this.query({ limit: 100, before })}`);
      this.items.update(list => [...list, ...page.items]); this.next.set(page.nextBefore);
    });
  }
  setKind(kind: Kind): void { this.kind.set(kind); void this.reload(); }
  setRange(range: Range): void { this.range.set(range); void this.reload(); }
  setApp(app: string): void { this.app.set(app); void this.reload(); }
  setQuery(q: string): void { this.q.set(q); clearTimeout(this.debounce); this.debounce = setTimeout(() => void this.reload(), 250); }
  showRefused(): void { this.kind.set('denied'); this.range.set('24h'); void this.reload(); }

  async exportCsv(): Promise<void> {
    await this.run(async () => {
      const blob = await this.api.blob(`/api/v1/admin/vault/audit?${this.query({ format: 'csv' })}`);
      const url = URL.createObjectURL(blob); const a = document.createElement('a');
      a.href = url; a.download = `keystone-vault-audit-${new Date().toISOString().slice(0, 10)}.csv`; a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
  }
  appOf(target: string | null): string { return target?.split(/[/ ]/)[0] ?? ''; }

  private async run(task: () => Promise<void>): Promise<void> {
    this.busy.set(true); this.error.set('');
    try { await task(); }
    catch (e) { this.error.set(e instanceof HttpErrorResponse && typeof e.error?.error?.message === 'string' ? e.error.error.message : 'The audit log could not be loaded. Retry in a moment.'); }
    finally { this.busy.set(false); }
  }
}
