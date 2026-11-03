import { TestBed } from '@angular/core/testing';
import { Api } from './api';
import { SetupComponent } from './setup';

describe('first-time setup',()=>{
  it('requires the license, sends the setup key, and submits the chosen sign-in',async()=>{
    const calls:{method:string;path:string;key?:string;body?:unknown}[]=[];
    const api={
      setup:async(method:string,path:string,key?:string,body?:unknown)=>{
        calls.push({method,path,key,body});
        if(path==='status')return {required:true,licenseId:'Apache-2.0',licenseAccepted:false,keyFile:'/k/secrets/setup.key',portal:{configured:false,url:'',clientId:'',fixed:false},local:{enabled:false,admins:0,users:0},database:{engine:'SQLite',url:'sqlite:///k/data/keystone.db',fixed:false}};
        if(path==='finish')return {restart:false};
        return {};
      },
      setupText:async()=>'Apache License\n\nVersion 2.0',
    };
    TestBed.configureTestingModule({imports:[SetupComponent],providers:[{provide:Api,useValue:api}]});
    const fixture=TestBed.createComponent(SetupComponent);const c=fixture.componentInstance;
    await c.ngOnInit();fixture.detectChanges();
    const continueButton=()=>fixture.nativeElement.querySelector('.actions .primary') as HTMLButtonElement;
    expect(fixture.nativeElement.textContent).toContain('Apache License');
    expect(continueButton().disabled).toBe(true);
    c.accepted.set(true);fixture.detectChanges();
    expect(continueButton().disabled).toBe(false);
    c.step.set('key');c.key.set(' abc-123 ');
    await c.continueKey();
    expect(calls.filter(x=>x.path==='verify'||x.path==='license').map(x=>[x.path,x.key])).toEqual([['verify','abc-123'],['license','abc-123']]);
    expect(c.step()).toBe('signin');
    c.adminEmail.set('ops@example.com');c.adminName.set('Ops');c.adminPassword.set('short');c.adminConfirm.set('short');
    expect(c.signInReady()).toBe(false);
    c.adminPassword.set('Correct-Horse-42');c.adminConfirm.set('Correct-Horse-42');
    expect(c.signInReady()).toBe(true);
    let reloaded=false;c.reload=()=>{reloaded=true;};
    await c.finish();
    const finish=calls.find(x=>x.path==='finish')!;
    expect(finish.body).toEqual({portal:null,admin:{email:'ops@example.com',name:'Ops',password:'Correct-Horse-42'},databaseUrl:null});
    expect(reloaded).toBe(true);
  });
});
