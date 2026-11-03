import { Component, OnDestroy, OnInit, inject, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Api, Admin, AuthConfig, Health, Overview, PostPage } from './api';
import { VaultComponent } from './vault';

@Component({selector:'app-root',standalone:true,imports:[CommonModule,VaultComponent],templateUrl:'./app.html'})
export class AppComponent implements OnInit,OnDestroy {
  private api=inject(Api);
  readonly config=signal<AuthConfig|null>(null);
  readonly admin=signal<Admin|null>(null);
  readonly health=signal<Health|null>(null);
  readonly overview=signal<Overview|null>(null);
  readonly posts=signal<PostPage|null>(null);
  readonly error=signal('');
  readonly busy=signal(false);
  readonly starting=signal(true);
  readonly stale=signal(false);
  readonly page=signal(0);
  readonly menuOpen=signal(false);
  readonly search=signal('');
  readonly navigation=[{id:'vault',label:'Vault: secrets & config'},{id:'overview',label:'Overview'},{id:'services',label:'Services'},{id:'blog',label:'Blog activity'}];
  readonly matches=computed(()=>this.navigation.filter(item=>item.label.toLowerCase().includes(this.search().trim().toLowerCase())));
  readonly section=signal(location.hash==='#overview'||location.hash==='#services'||location.hash==='#blog'?location.hash.slice(1):'vault');
  navigate(section:string):void {this.section.set(section);this.menuOpen.set(false);this.search.set('');if(section!=='vault')setTimeout(()=>document.getElementById(section)?.scrollIntoView());}

  readonly up=computed(()=>this.health()?.services.filter(s=>s.status==='up').length??0);
  private timer?:ReturnType<typeof setInterval>;
  private generation=0;

  async ngOnInit():Promise<void> { await this.initialize(); }
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
    this.admin.set(await this.api.get<Admin>('/api/v1/auth/me'));
    await this.refresh(true);
    if(!this.timer && this.admin())this.timer=setInterval(()=>{if(!document.hidden)void this.refresh();},15000);
  }
  async refresh(force=false):Promise<void> {
    if(!this.admin() || (this.busy()&&!force))return;
    const generation=this.generation;
    this.busy.set(true);
    try {
      const [health,overview,posts]=await Promise.all([
        this.api.get<Health>('/api/v1/admin/services'),this.api.get<Overview>('/api/v1/admin/overview'),
        this.api.get<PostPage>(`/api/v1/admin/posts?page=${this.page()}`)
      ]);
      if(generation!==this.generation)return;
      this.health.set(health);this.overview.set(overview);this.posts.set(posts);this.stale.set(false);this.error.set('');
    } catch(error) {
      if(generation!==this.generation)return;
      if((error instanceof HttpErrorResponse && [401,403].includes(error.status)) || (error instanceof Error && error.message==='Your session has ended. Sign in again.'))this.logout();
      this.stale.set(true);this.error.set(this.message(error));
    } finally {if(generation===this.generation)this.busy.set(false);}
  }
  changePage(delta:number):void {this.page.update(p=>Math.max(0,p+delta));void this.refresh();}
  logout():void {
    this.menuOpen.set(false);this.search.set('');this.section.set('vault');
    this.generation++;if(this.timer)clearInterval(this.timer);this.timer=undefined;
    this.api.logout();this.admin.set(null);this.health.set(null);this.overview.set(null);this.posts.set(null);this.page.set(0);this.busy.set(false);this.error.set('');
  }
  ngOnDestroy():void {if(this.timer)clearInterval(this.timer);this.generation++;}
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
    }
    return error instanceof Error && error.message==='Your session has ended. Sign in again.' ? error.message : 'Unable to connect. Check the service or Portal SSO connection and retry.';
  }
}
