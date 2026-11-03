import { TestBed } from '@angular/core/testing';
import { VaultComponent } from './vault';
import { Api } from './api';
const status={sealed:false,apps:1,keys:1,files:0,activeTokens:0,portalUrl:'https://portal.test'};
const app={id:'billing',name:'Billing',description:'',portalClientId:'billing',createdAt:1,updatedAt:1,environments:['default','prod'],protectedEnvironments:['prod'],role:'ROLE_VAULT_BILLING',keyCount:1,fileCount:0,activeTokens:0};
function fake(overrides:Record<string,unknown>={}){
  const calls:string[]=[];
  const api={calls,
    get:async(path:string)=>{calls.push('GET '+path);
      if(path.endsWith('/status'))return overrides['status']??status;
      if(path.endsWith('/apps'))return {items:overrides['apps']??[app]};
      if(path.endsWith('/items'))return {items:[{kind:'key',name:'db.password',version:2,contentType:'text/plain',size:6,updatedBy:'admin:a@test',updatedAt:1}]};
      if(path.includes('/keys/'))return {name:'db.password',version:2,value:'hunter'};
      return {items:[]};},
    send:async(method:string,path:string)=>{calls.push(method+' '+path);return {version:3};},
  };
  return api;
}
describe('vault workspace',()=>{
  it('lists keys masked and reveals a value only on request',async()=>{
    const api=fake();
    TestBed.configureTestingModule({imports:[VaultComponent],providers:[{provide:Api,useValue:api}]});
    const fixture=TestBed.createComponent(VaultComponent);fixture.detectChanges();await fixture.componentInstance.load();fixture.detectChanges();
    const text=()=>fixture.nativeElement.textContent as string;
    expect(text()).toContain('db.password');expect(text()).not.toContain('hunter');
    expect(api.calls.some(c=>c.includes('/keys/'))).toBe(false);
    await fixture.componentInstance.reveal('db.password');fixture.detectChanges();
    expect(text()).toContain('hunter');
  });
  it('shows the sealed notice and disables creation without a master key',async()=>{
    TestBed.configureTestingModule({imports:[VaultComponent],providers:[{provide:Api,useValue:fake({status:{...status,sealed:true},apps:[]})}]});
    const fixture=TestBed.createComponent(VaultComponent);fixture.detectChanges();await fixture.componentInstance.load();fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('The vault is sealed');
    expect(fixture.nativeElement.querySelector('.blank.hero')).toBeNull();
  });
  it('requires typing the application id before deleting it',async()=>{
    const api=fake();
    TestBed.configureTestingModule({imports:[VaultComponent],providers:[{provide:Api,useValue:api}]});
    const fixture=TestBed.createComponent(VaultComponent);const c=fixture.componentInstance;await c.load();
    c.askDeleteApp();await c.confirmRun();
    expect(api.calls.some(x=>x.startsWith('DELETE'))).toBe(false);
    c.confirm.update(v=>v&&{...v,typed:'billing'});await c.confirmRun();
    expect(api.calls).toContain('DELETE /api/v1/admin/vault/apps/billing?confirm=billing');
  });
});
