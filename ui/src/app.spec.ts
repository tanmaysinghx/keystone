import { TestBed } from '@angular/core/testing';
import { HttpErrorResponse } from '@angular/common/http';
import { AppComponent } from './app';
import { Api } from './api';
describe('admin console boundaries',()=>{
  it('does not show the dashboard until the backend verifies admin access',async()=>{
    const api={configure:async()=>({configured:true,portalUrl:'https://portal.test',clientId:'test',scope:'openid'}),sso:{getCurrentUser:()=>null,loginWithPopup:async()=>({})},get:async()=>{throw new HttpErrorResponse({status:403});},logout:()=>{}};
    TestBed.configureTestingModule({imports:[AppComponent],providers:[{provide:Api,useValue:api}]});
    const fixture=TestBed.createComponent(AppComponent);fixture.detectChanges();await fixture.whenStable();await fixture.componentInstance.login();fixture.detectChanges();
    expect(fixture.componentInstance.admin()).toBeNull();expect(fixture.nativeElement.textContent).toContain('Administrator access is required');expect(fixture.nativeElement.querySelector('.metrics')).toBeNull();
  });
  it('marks stale health results unknown after a backend failure',async()=>{
    const api={get:async()=>{throw new HttpErrorResponse({status:503});},logout:()=>{}};
    TestBed.configureTestingModule({imports:[AppComponent],providers:[{provide:Api,useValue:api}]});
    const fixture=TestBed.createComponent(AppComponent);const component=fixture.componentInstance;
    component.admin.set({subject:'admin',name:null,email:null,roles:['ROLE_ADMIN'],expiresAt:9999999999});
    component.health.set({checkedAt:1,services:[{name:'API',status:'up',detail:'Ready',latencyMs:1}]});
    await component.refresh();expect(component.stale()).toBe(true);expect(component.error()).toContain('availability');
  });
});
