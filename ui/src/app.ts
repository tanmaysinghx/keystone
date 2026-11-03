import { Component, ElementRef, HostListener, OnInit, computed, inject, signal, viewChild } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { Api, Admin, AuthConfig, VaultApp } from './api';
import { VaultComponent } from './vault';
import { AuditComponent } from './audit';
import { DocsComponent } from './docs';
import { VaultStore } from './vault-store';
import { DOC_GUIDES } from './docs-content';

interface SearchResult { group: string; label: string; detail: string; run: () => void }

@Component({selector:'app-root',standalone:true,imports:[CommonModule,VaultComponent,AuditComponent,DocsComponent],templateUrl:'./app.html'})
export class AppComponent implements OnInit {
  private api=inject(Api);
  private http=inject(HttpClient);
  readonly store=inject(VaultStore);
  /** Public documentation at /docs, like Portal SSO's; everything else is the signed-in console. */
  readonly docs=typeof location!=='undefined' && /^\/docs(\/|$)/.test(location.pathname);
  readonly config=signal<AuthConfig|null>(null);
  readonly admin=signal<Admin|null>(null);
  readonly version=signal('0.1.0');
  readonly error=signal('');
  readonly busy=signal(false);
  readonly starting=signal(true);
  readonly menuOpen=signal(false);
  /** Console screen: the vault workspace or the audit log (#audit). */
  readonly view=signal<'vault'|'audit'>(typeof location!=='undefined'&&location.hash==='#audit'?'audit':'vault');
  show(view:'vault'|'audit'):void {this.view.set(view);this.menuOpen.set(false);history.replaceState(null,'',view==='audit'?'#audit':location.pathname);}
  openApp(id:string,env?:string,item?:import('./api').VaultItem):void {this.show('vault');this.store.select(id,env,item);}
  readonly search=signal('');
  readonly active=signal(0);
  private searchBox=viewChild<ElementRef<HTMLInputElement>>('searchBox');
  /** Applications, their environments, keys and files of the open environment, and the docs. */
  readonly results=computed<SearchResult[]>(()=>{
    const q=this.search().trim().toLowerCase(); if(!q)return [];
    const hit=(...t:(string|null|undefined)[])=>t.some(v=>v?.toLowerCase().includes(q));
    const out:SearchResult[]=[];
    for(const app of this.store.apps()){
      if(hit(app.name,app.id,app.portalClientId))out.push({group:'Applications',label:app.name,detail:`${app.id} · ${app.environments.length} environments`,run:()=>this.openApp(app.id)});
      for(const env of app.environments)if(env!=='default'&&hit(env))out.push({group:'Environments',label:`${app.name} / ${env}`,detail:'Open environment',run:()=>this.openApp(app.id,env)});
    }
    const current=this.store.selectedId();
    if(current)for(const item of this.store.items())if(hit(item.name))out.push({group:item.kind==='key'?'Keys':'Files',label:item.name,detail:`${current} / ${this.store.env()} · v${item.version}`,run:()=>this.openApp(current,this.store.env(),item)});
    if(hit('audit log','activity','who pulled','ip address'))out.unshift({group:'Screens',label:'Audit log',detail:'Every pull, reveal and change',run:()=>this.show('audit')});
    for(const g of DOC_GUIDES)if(hit(g.title,g.summary))out.push({group:'Docs',label:g.title,detail:g.group,run:()=>window.open(`/docs/${g.id}`,'_blank','noopener')});
    return out.slice(0,12);
  });
  choose(result:SearchResult):void {result.run();this.search.set('');this.active.set(0);this.menuOpen.set(false);this.searchBox()?.nativeElement.blur();}
  onSearchKey(event:KeyboardEvent):void {
    const list=this.results();
    if(event.key==='ArrowDown'){event.preventDefault();this.active.set(Math.min(this.active()+1,list.length-1));}
    else if(event.key==='ArrowUp'){event.preventDefault();this.active.set(Math.max(this.active()-1,0));}
    else if(event.key==='Enter'&&list[this.active()]){event.preventDefault();this.choose(list[this.active()]);}
    else if(event.key==='Escape'){this.search.set('');(event.target as HTMLInputElement).blur();}
  }
  /** ⌘K / Ctrl+K focuses search, as in Portal SSO. */
  @HostListener('document:keydown',['$event']) shortcut(event:KeyboardEvent):void {
    if((event.metaKey||event.ctrlKey)&&event.key.toLowerCase()==='k'&&this.admin()){event.preventDefault();this.searchBox()?.nativeElement.focus();}
  }
  readonly mac=typeof navigator!=='undefined'&&/Mac|iPhone|iPad/.test(navigator.platform);

  async ngOnInit():Promise<void> {
    firstValueFrom(this.http.get<{version:string}>('/api/v1/info')).then(info=>this.version.set(info.version)).catch(()=>{});
    if(!this.docs) await this.initialize();
  }
  async initialize():Promise<void> {
    this.starting.set(true);this.error.set('');
    try {
      this.config.set(await this.api.configure());
      if(this.api.sso?.getCurrentUser()) await this.authorize();
    } catch(error) {this.error.set(this.message(error));}
    finally {this.starting.set(false);}
  }
  async login():Promise<void> {
    if(!this.api.sso || this.busy())return;
    this.busy.set(true);this.error.set('');
    try {await this.api.sso.loginWithPopup();await this.authorize();}
    catch(error){this.api.logout();this.admin.set(null);this.error.set(this.message(error));}
    finally{this.busy.set(false);}
  }
  private async authorize():Promise<void> {
    try {
      this.admin.set(await this.api.get<Admin>('/api/v1/auth/me'));
      this.api.get<{items:VaultApp[]}>('/api/v1/admin/vault/apps').then(r=>{if(!this.store.apps().length)this.store.apps.set(r.items);}).catch(()=>{});
    }
    catch(error){if(error instanceof HttpErrorResponse && [401,403].includes(error.status))this.api.logout();throw error;}
  }
  logout():void {this.menuOpen.set(false);this.api.logout();this.admin.set(null);this.busy.set(false);this.error.set('');}
  private message(error:unknown):string {
    if(error instanceof HttpErrorResponse){
      if(error.status===403)return 'Administrator access is required. Ask a Portal administrator to review your role.';
      if(error.status===401)return 'Your session has ended. Sign in with Portal SSO again.';
      return 'Keystone could not complete the request. Check service availability and retry.';
    }
    if(error instanceof Error) {
      if(error.message.includes('invalid_grant'))return 'Portal rejected the sign-in code. Please sign in again.';
      if(error.message.includes('Popup blocked'))return 'Allow popups for Keystone and try signing in again.';
      if(error.message.includes('temporarily_unavailable'))return 'Portal token exchange is temporarily unavailable. Please retry.';
      if(error.message.includes('Failed to fetch'))return 'The sign-in token exchange could not reach Keystone. Please retry.';
      if(error.message==='Your session has ended. Sign in again.')return error.message;
    }
    return 'Unable to connect. Check the service or Portal SSO connection and retry.';
  }
}
