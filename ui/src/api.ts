import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom, from, timeout } from 'rxjs';
import { PortalSSO } from '@tanmaysinghx/portal-sso';
export interface AuthConfig { configured:boolean; portalUrl:string; clientId:string; scope:string }
export interface Admin {subject:string; name:string|null; email:string|null; roles:string[]; expiresAt:number}
export interface Service {name:string;status:'up'|'down'|'unconfigured';detail:string;latencyMs:number}
export interface Health {checkedAt:number;services:Service[]}
export interface Overview {likes:number;views:number;posts:number;uptimeSeconds:number;version:string}
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
  async get<T>(path:string):Promise<T> {
    const token=this.sso ? await firstValueFrom(from(this.sso.getAccessTokenAsync()).pipe(timeout(8000))) : null;
    if(!token) throw new Error('Your session has ended. Sign in again.');
    return firstValueFrom(this.http.get<T>(path,{headers:{Authorization:`Bearer ${token}`}}).pipe(timeout(8000)));
  }
  logout():void {this.sso?.logout();}
}
