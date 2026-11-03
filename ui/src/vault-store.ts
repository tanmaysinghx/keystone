import { Injectable, signal } from '@angular/core';
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
  readonly requestedApp = signal<{ id: string; env?: string; item?: VaultItem } | null>(null);
  readonly newAppRequests = signal(0);
  select(id: string, env?: string, item?: VaultItem): void { this.requestedApp.set({ id, env, item }); }
  createApp(): void { this.newAppRequests.update(n => n + 1); }
}
