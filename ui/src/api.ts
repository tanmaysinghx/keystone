import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom, from, timeout } from 'rxjs';
import { PortalSSO } from '@tanmaysinghx/portal-sso';
export interface AuthConfig { configured:boolean; portalUrl:string; clientId:string; scope:string; local:boolean; setupRequired:boolean }
export interface SetupStatus {required:boolean;version?:string;licenseId?:string;licenseAccepted?:boolean;keyFile?:string;configFile?:string;portal?:{configured:boolean;url:string;clientId:string;fixed:boolean};local?:{enabled:boolean;admins:number;users:number};database?:{engine:string;url:string;fixed:boolean}}
export interface LocalUser {id:number;email:string;name:string;roles:string[];disabled:boolean;createdAt:number;lastLoginAt:number|null}
export interface Admin {subject:string; name:string|null; email:string|null; roles:string[]; expiresAt:number; admin:boolean; apps:string[]}
export interface VaultStatus {sealed:boolean;apps:number;keys:number;files:number;activeTokens:number;portalUrl:string}
export interface VaultApp {id:string;name:string;description:string;portalClientId:string|null;createdAt:number;updatedAt:number;environments:string[];protectedEnvironments:string[];role:string;keyCount:number;fileCount:number;activeTokens:number}
export interface VaultItem {kind:'key'|'file';name:string;version:number;contentType:string;size:number;updatedBy:string;updatedAt:number}
export interface VaultVersion {version:number;size:number;createdBy:string;createdAt:number;current:boolean}
export interface VaultToken {id:string;name:string;environment:string;createdBy:string;createdAt:number;expiresAt:number|null;lastUsedAt:number|null;revokedAt:number|null;active:boolean;allowedCidrs:string|null}
export interface IssuedToken {id:string;token:string;app:string;environment:string;expiresAt:number|null}
export interface ChangeRequest {id:number;app:string;environment:string;operation:'put'|'delete'|'import';kind:'key'|'file';name:string;summary:string;requestedBy:string;createdAt:number;status:'pending'|'applied'|'rejected'|'cancelled';decidedBy:string|null;decidedAt:number|null;note:string|null}
export interface Finding {severity:'high'|'medium'|'low';kind:string;title:string;detail:string;app:string|null;environment:string|null;action:string}
export interface Insights {items:Finding[];counts:{high:number;medium:number;low:number;pendingApprovals:number}}
export interface Backup {name:string;createdAt:number;size:number;automatic:boolean}
export interface ServerSettings {version:string;home:string;configFile:string|null;bind:string;trustProxy:boolean;portal:{url:string;clientId:string};masterKey:{configured:boolean;source:string};backups:{dir:string;intervalHours:number;keep:number;last:{name:string;createdAt:number;size:number}|null};security:{failedTokenLimit:number;lockoutMinutes:number;rotationDays:number;tokenExpiryWarningDays:number};alerts:{configured:boolean;source:'config'|'console'|null;host:string|null}}
export interface AuditEvent {id:number;subject:string;event:string;target:string|null;ip:string|null;userAgent:string|null;createdAt:number}
@Injectable({providedIn:'root'})
export class Api {
  private http=inject(HttpClient);
  sso?:PortalSSO;
  async configure():Promise<AuthConfig> {
    const config=await firstValueFrom(this.http.get<AuthConfig>('/api/v1/auth/config').pipe(timeout(6000)));
    if(config.configured && (!this.sso || this.sso.portalUrl!==config.portalUrl || this.sso.clientId!==config.clientId)) {
      this.sso?.logout();
      this.sso=new PortalSSO({portalUrl:config.portalUrl,clientId:config.clientId,scope:config.scope,storageKey:'keystone:portal-session',tokenEndpoint:'/api/v1/auth/token'});
    }
    return config;
  }
  /** Local-account session (email + password sign-in), kept until it expires or you sign out. */
  private static readonly LOCAL='keystone:local-session';
  localSession():{token:string;expiresAt:number}|null {
    try {
      const raw=localStorage.getItem(Api.LOCAL); if(!raw)return null;
      const session=JSON.parse(raw) as {token:string;expiresAt:number};
      if(!session.token || session.expiresAt*1000<=Date.now()){localStorage.removeItem(Api.LOCAL);return null;}
      return session;
    } catch {return null;}
  }
  async loginLocal(email:string,password:string):Promise<void> {
    const session=await firstValueFrom(this.http.post<{token:string;expiresAt:number}>('/api/v1/auth/local/login',{email,password}).pipe(timeout(15000)));
    try {localStorage.setItem(Api.LOCAL,JSON.stringify(session));} catch {/* private mode: session lasts for this page */}
    this.memoryLocal=session;
  }
  private memoryLocal:{token:string;expiresAt:number}|null=null;
  isLocal():boolean {return !!(this.localSession()??this.memoryLocal);}
  /** First-time setup calls carry the one-time setup key instead of a sign-in. */
  setup<T>(method:'GET'|'POST',path:string,key?:string,body?:unknown):Promise<T> {
    const headers:Record<string,string>=key?{'X-Setup-Key':key}:{};
    return firstValueFrom(this.http.request<T>(method,`/api/v1/setup/${path}`,{body,headers}).pipe(timeout(60000)));
  }
  setupText(path:string):Promise<string> {return firstValueFrom(this.http.get(`/api/v1/setup/${path}`,{responseType:'text'}).pipe(timeout(10000)));}
  private async bearer():Promise<string> {
    const local=this.localSession()??this.memoryLocal;
    if(local)return `Bearer ${local.token}`;
    const token=this.sso ? await firstValueFrom(from(this.sso.getAccessTokenAsync()).pipe(timeout(8000))) : null;
    if(!token) throw new Error('Your session has ended. Sign in again.');
    return `Bearer ${token}`;
  }
  async get<T>(path:string):Promise<T> {
    const headers={Authorization:await this.bearer()};
    return firstValueFrom(this.http.get<T>(path,{headers}).pipe(timeout(8000)));
  }
  /** JSON (or raw Blob) request with the Portal access token. */
  async send<T>(method:'POST'|'PUT'|'PATCH'|'DELETE',path:string,body?:unknown,contentType?:string):Promise<T> {
    const headers:Record<string,string>={Authorization:await this.bearer()};
    if(contentType)headers['Content-Type']=contentType;
    return firstValueFrom(this.http.request<T>(method,path,{body,headers}).pipe(timeout(15000)));
  }
  async blob(path:string):Promise<Blob> {
    const headers={Authorization:await this.bearer()};
    return firstValueFrom(this.http.get(path,{headers,responseType:'blob'}).pipe(timeout(15000)));
  }
  async text(path:string):Promise<string> {
    const headers={Authorization:await this.bearer()};
    return firstValueFrom(this.http.get(path,{headers,responseType:'text'}).pipe(timeout(8000)));
  }
  logout():void {
    const local=this.localSession()??this.memoryLocal;
    if(local)this.http.post('/api/v1/auth/local/logout',{},{headers:{Authorization:`Bearer ${local.token}`}}).subscribe({error:()=>{}});
    try {localStorage.removeItem(Api.LOCAL);} catch {/* ignore */}
    this.memoryLocal=null;
    this.sso?.logout();
  }
}
