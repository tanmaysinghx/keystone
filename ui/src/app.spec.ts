import { TestBed } from '@angular/core/testing';
import { HttpErrorResponse, provideHttpClient } from '@angular/common/http';
import { AppComponent } from './app';
import { Api } from './api';
describe('admin console boundaries',()=>{
  it('does not show the vault until the backend verifies admin access',async()=>{
    const api={configure:async()=>({configured:true,portalUrl:'https://portal.test',clientId:'test',scope:'openid'}),sso:{getCurrentUser:()=>null,loginWithPopup:async()=>({})},get:async()=>{throw new HttpErrorResponse({status:403});},logout:()=>{}};
    TestBed.configureTestingModule({imports:[AppComponent],providers:[provideHttpClient(),{provide:Api,useValue:api}]});
    const fixture=TestBed.createComponent(AppComponent);fixture.detectChanges();await fixture.whenStable();await fixture.componentInstance.login();fixture.detectChanges();
    expect(fixture.componentInstance.admin()).toBeNull();
    expect(fixture.nativeElement.textContent).toContain('Administrator access is required');
    expect(fixture.nativeElement.querySelector('keystone-vault')).toBeNull();
  });
});
