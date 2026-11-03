import { TestBed } from '@angular/core/testing';
import { Api } from './api';
import { ApprovalsComponent } from './approvals';
import { HealthComponent } from './health';
import { VaultStore } from './vault-store';

const change = {id:7,app:'billing',environment:'prod',operation:'put',kind:'key',name:'db.password',summary:'Set key db.password',requestedBy:'admin:alice@x',createdAt:1,status:'pending',decidedBy:null,decidedAt:null,note:null};
describe('security screens',()=>{
  it('approves a pending change and refreshes the waiting list',async()=>{
    const calls:string[]=[]; let pending=[change];
    const api={get:async(path:string)=>{calls.push('GET '+path);return {items:pending};},send:async(m:string,path:string)=>{calls.push(m+' '+path);pending=[];return {status:'applied'};}};
    TestBed.configureTestingModule({imports:[ApprovalsComponent],providers:[{provide:Api,useValue:api}]});
    const fixture=TestBed.createComponent(ApprovalsComponent);await fixture.componentInstance.load();fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Set key db.password');
    await fixture.componentInstance.decide(change as never,'approve');fixture.detectChanges();
    expect(calls).toContain('POST /api/v1/admin/vault/changes/7/approve');
    expect(fixture.nativeElement.textContent).toContain('Nothing waiting');
    expect(TestBed.inject(VaultStore).badges().approvals).toBe(0);
  });
  it('turns a health finding into navigation to the place that fixes it',async()=>{
    const finding={severity:'medium',kind:'token-unrestricted',title:'Token works from any IP',detail:'…',app:'billing',environment:'prod',action:'tokens'};
    const api={get:async()=>({items:[finding],counts:{high:0,medium:1,low:0,pendingApprovals:2}})};
    TestBed.configureTestingModule({imports:[HealthComponent],providers:[{provide:Api,useValue:api}]});
    const fixture=TestBed.createComponent(HealthComponent);await fixture.componentInstance.load();fixture.detectChanges();
    const store=TestBed.inject(VaultStore);
    expect(store.badges()).toEqual({health:1,approvals:2});
    fixture.componentInstance.open(finding as never);
    expect(store.view()).toBe('vault');
    expect(store.requestedApp()).toEqual({id:'billing',env:'prod',item:undefined,tab:'tokens'});
  });
});
