import { Component, OnDestroy, OnInit, computed, input, signal } from '@angular/core';
import { NgTemplateOutlet } from '@angular/common';
import { DOC_GROUPS, DOC_GUIDES, DocGuide, ENDPOINTS, STACKS } from './docs-content';

interface Segment { text: string; kind: 'text' | 'code' | 'bold' | 'link'; guide?: string }
const INLINE = /`([^`]+)`|\*\*([^*]+)\*\*|\[([^\]]+)\]\(([a-z0-9-]+)\)/g;

/** Public documentation, one page per guide at /docs/:guide (mirrors Portal SSO's docs). */
@Component({ selector: 'keystone-docs', standalone: true, imports: [NgTemplateOutlet], templateUrl: './docs.html', styleUrl: './docs.css' })
export class DocsComponent implements OnInit, OnDestroy {
  readonly version = input('0.1.0');
  readonly origin = typeof location === 'undefined' ? 'https://keystone.example.com' : location.origin;
  readonly groups = DOC_GROUPS.map(group => ({ group, guides: DOC_GUIDES.filter(g => g.group === group) }));
  readonly stacks = STACKS;
  readonly endpoints = ENDPOINTS;
  readonly activeStack = signal(STACKS[0].id);
  readonly stack = computed(() => STACKS.find(s => s.id === this.activeStack()) ?? STACKS[0]);
  readonly copied = signal<string | null>(null);
  readonly menuOpen = signal(false);
  private readonly guideId = signal(this.fromPath());
  readonly guide = computed<DocGuide>(() => DOC_GUIDES.find(g => g.id === this.guideId()) ?? DOC_GUIDES[0]);
  readonly position = computed(() => DOC_GUIDES.indexOf(this.guide()));
  readonly previous = computed(() => DOC_GUIDES[this.position() - 1] ?? null);
  readonly next = computed(() => DOC_GUIDES[this.position() + 1] ?? null);
  private readonly onPop = () => this.guideId.set(this.fromPath());

  ngOnInit(): void {
    addEventListener('popstate', this.onPop);
    document.title = `${this.guide().title} · Keystone Vault docs`;
  }
  ngOnDestroy(): void { removeEventListener('popstate', this.onPop); }

  private fromPath(): string { return typeof location === 'undefined' ? '' : location.pathname.replace(/^\/docs\/?/, '').split('/')[0]; }

  open(id: string, event?: Event): void {
    event?.preventDefault();
    if (id !== this.guide().id) history.pushState(null, '', `/docs/${id}`);
    this.guideId.set(id); this.menuOpen.set(false);
    document.title = `${this.guide().title} · Keystone Vault docs`;
    scrollTo({ top: 0 });
  }

  segments(text: string): Segment[] {
    const out: Segment[] = []; let last = 0;
    for (const m of text.matchAll(INLINE)) {
      if (m.index! > last) out.push({ kind: 'text', text: text.slice(last, m.index) });
      if (m[1] !== undefined) out.push({ kind: 'code', text: m[1] });
      else if (m[2] !== undefined) out.push({ kind: 'bold', text: m[2] });
      else out.push({ kind: 'link', text: m[3], guide: m[4] });
      last = m.index! + m[0].length;
    }
    if (last < text.length) out.push({ kind: 'text', text: text.slice(last) });
    return out;
  }
  code(text: string): string { return text.replace(/\{\{ORIGIN\}\}/g, this.origin); }
  title(id: string): string { return DOC_GUIDES.find(g => g.id === id)?.title ?? id; }

  async copy(text: string, key: string): Promise<void> {
    try { await navigator.clipboard.writeText(this.code(text)); this.copied.set(key); setTimeout(() => { if (this.copied() === key) this.copied.set(null); }, 1600); }
    catch { /* selection still works */ }
  }
}
