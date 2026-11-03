import { Injectable, signal } from '@angular/core';

export type View = 'vault' | 'audit' | 'health' | 'approvals' | 'settings';
export type VaultTab = 'keys' | 'files' | 'tokens' | 'integrate' | 'activity';
const VIEWS: View[] = ['vault', 'audit', 'health', 'approvals', 'settings'];
import { VaultApp, VaultItem, VaultStatus } from './api';

/** Vault state shared by the console shell (sidebar, header search) and the vault workspace. */
@Injectable({ providedIn: 'root' })
export class VaultStore {
  readonly apps = signal<VaultApp[]>([]);
  readonly status = signal<VaultStatus | null>(null);
  readonly selectedId = signal<string | null>(null);
  readonly env = signal('default');
  /** Keys and files of the selected environment (names and metadata only, never values). */
  readonly items = signal<VaultItem[]>([]);
  /** Requests from the shell, handled by the workspace. */
  readonly requestedApp = signal<{ id: string; env?: string; item?: VaultItem; tab?: VaultTab } | null>(null);
  /** Console screen, mirrored in the URL hash (#audit, #health, ...). */
  readonly view = signal<View>(fromHash());
  constructor() {
    // Back/forward and pasted links (#audit, #settings, …) switch screens without a reload.
    if (typeof window !== 'undefined') window.addEventListener('hashchange', () => this.view.set(fromHash()));
  }
  readonly newAppRequests = signal(0);
  /** The signed-in person's scope: administrators manage everything. */
  readonly isAdmin = signal(false);
  /** Health-check and approval counts for sidebar badges. */
  readonly badges = signal<{ health: number; approvals: number }>({ health: 0, approvals: 0 });
  select(id: string, env?: string, item?: VaultItem, tab?: VaultTab): void { this.show('vault'); this.requestedApp.set({ id, env, item, tab }); }
  show(view: View): void {
    this.view.set(view);
    if (typeof history !== 'undefined') history.replaceState(null, '', view === 'vault' ? location.pathname : `#${view}`);
  }
  createApp(): void { this.newAppRequests.update(n => n + 1); }
}

function fromHash(): View {
  const hash = typeof location === 'undefined' ? '' : location.hash.slice(1);
  return (VIEWS as string[]).includes(hash) ? hash as View : 'vault';
}
