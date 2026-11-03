import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom, from, timeout } from 'rxjs';
import { PortalSSO } from '@tanmaysinghx/portal-sso';
export interface AuthConfig { configured:boolean; portalUrl:string; clientId:string; scope:string }
export interface Admin {subject:string; name:string|null; email:string|null; roles:string[]; expiresAt:number}
export interface Service {name:string;status:'up'|'down'|'unconfigured';detail:string;latencyMs:number}
export interface Health {checkedAt:number;services:Service[]}
export interface Overview {likes:number;views:number;posts:number;uptimeSeconds:number;version:string}
export interface VaultStatus {sealed:boolean;apps:number;keys:number;files:number;activeTokens:number;portalUrl:string}
export interface VaultApp {id:string;name:string;description:string;portalClientId:string|null;createdAt:number;updatedAt:number;environments:string[];keyCount:number;fileCount:number;activeTokens:number}
export interface VaultItem {kind:'key'|'file';name:string;version:number;contentType:string;size:number;updatedBy:string;updatedAt:number}
export interface VaultVersion {version:number;size:number;createdBy:string;createdAt:number;current:boolean}
export interface VaultToken {id:string;name:string;environment:string;createdBy:string;createdAt:number;expiresAt:number|null;lastUsedAt:number|null;revokedAt:number|null;active:boolean}
export interface IssuedToken {id:string;token:string;app:string;environment:string;expiresAt:number|null}
export interface AuditEvent {id:number;subject:string;event:string;target:string|null;ip:string|null;userAgent:string|null;createdAt:number}
export interface PostPage {page:number;pageSize:number;total:number;items:{slug:string;likes:number;views:number}[]}
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
  private async bearer():Promise<string> {
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
  logout():void {this.sso?.logout();}
}
