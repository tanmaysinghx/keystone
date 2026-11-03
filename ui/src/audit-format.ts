/** Shared presentation of audit events (vault workspace Activity tab and the Audit log screen). */
export const EVENT_LABELS: Record<string, string> = {
  'vault.app.create': 'Created application', 'vault.app.update': 'Updated application', 'vault.app.delete': 'Deleted application',
  'vault.environment.create': 'Added environment', 'vault.environment.delete': 'Deleted environment',
  'vault.key.write': 'Wrote key', 'vault.key.reveal': 'Revealed key', 'vault.key.delete': 'Deleted key', 'vault.key.rollback': 'Rolled back key', 'vault.key.read': 'App read key',
  'vault.file.write': 'Uploaded file', 'vault.file.reveal': 'Downloaded file', 'vault.file.delete': 'Deleted file', 'vault.file.rollback': 'Rolled back file', 'vault.file.read': 'App read file',
  'vault.import': 'Imported file', 'vault.config.read': 'App loaded configuration', 'vault.config.reveal': 'Exported configuration',
  'vault.token.create': 'Issued token', 'vault.token.revoke': 'Revoked token', 'vault.token.denied': 'Token refused', 'vault.audit.export': 'Exported audit log',
};
export const eventLabel = (event: string) => EVENT_LABELS[event] ?? event;
export type Tone = 'pull' | 'change' | 'denied' | 'token' | 'other';
export function eventTone(event: string): Tone {
  if (event === 'vault.token.denied') return 'denied';
  if (/\.(read|reveal)$/.test(event)) return 'pull';
  if (event.startsWith('vault.token.')) return 'token';
  if (/\.(write|delete|create|update|rollback)$/.test(event) || event === 'vault.import') return 'change';
  return 'other';
}
export const isAppSubject = (subject: string) => subject.startsWith('token:');
export function subjectName(subject: string): string {
  return subject.replace(/^admin:/, '').replace(/^token:\S+ \((.*)\)$/, '$1').replace(/^token:/, 'token ');
}
export function clientName(ua: string | null): string {
  if (!ua) return '—';
  const known = /(Java-http-client|Java|ReactorNetty|Apache-HttpClient|okhttp|curl|node|undici|Wget|python-requests|python-urllib|Go-http-client)[/ ]?[\w.]*/i.exec(ua);
  if (known) return known[0];
  const browser = /(Firefox|Edg|Chrome|Safari)\/\d+/.exec(ua);
  return browser ? browser[0].replace('Edg', 'Edge') : ua.slice(0, 40);
}
