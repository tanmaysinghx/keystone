// Portal's native two-proof onboarding flow. Run while Keystone is stopped.
// Keeps the verifier in memory; only an authenticated Portal admin can approve.
import { createServer } from 'node:http';
import { randomBytes, createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
const issuer = process.argv[2];
if (!issuer || new URL(issuer).protocol !== 'https:' || new URL(issuer).origin !== issuer) throw Error('Pass the HTTPS Portal issuer origin.');
const appUrl = 'http://localhost:8090';
const verifier = randomBytes(48).toString('base64url');
const challenge = createHash('sha256').update(verifier).digest('base64url');
let requestId, redeemInFlight = false;
const server = createServer(async (req,res) => {
  res.setHeader('cache-control','no-store');res.setHeader('referrer-policy','no-referrer');res.setHeader('content-type','text/html; charset=utf-8');
  const url = new URL(req.url,appUrl);
  if (req.method!=='GET' || url.pathname!=='/api/setup/portal-callback' || url.searchParams.get('request_id')!==requestId) {res.writeHead(404);res.end('Onboarding callback only.');return;}
  if (url.searchParams.has('error')) {res.writeHead(400);res.end('Portal did not approve the connection.');return;}
  const code=url.searchParams.get('code');
  if(!code || redeemInFlight){res.writeHead(400);res.end('Missing or already processing callback.');return;}
  redeemInFlight=true;
  try {
    const response=await fetch(`${issuer}/api/external/connect/requests/${requestId}/redeem`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({code,codeVerifier:verifier}),signal:AbortSignal.timeout(10000),redirect:'error'});
    if(!response.ok)throw Error('Portal could not redeem the connection.');
    const result=await response.json();const credentials=result.credentials;
    if(credentials?.issuerUrl!==issuer || !credentials?.oidc?.clientId || credentials.oidc.confidential)throw Error('Unexpected registration details.');
    const envFile=new URL('../.env',import.meta.url);let env=await readFile(envFile,'utf8').catch(()=> '');
    for(const [key,value] of Object.entries({PORTAL_URL:issuer,PORTAL_CLIENT_ID:credentials.oidc.clientId})){
      if(/[\r\n]/.test(value))throw Error('Invalid configuration value');
      const re=new RegExp(`^${key}=.*$`,'m');env=re.test(env)?env.replace(re,`${key}=${value}`):`${env}\n${key}=${value}\n`;
    }
    await writeFile(envFile,env,{mode:0o600});
    res.end('<!doctype html><title>Keystone connected</title><h1>Keystone is connected to Portal SSO.</h1><p>You can close this tab. Start Keystone, then open http://localhost:8090 to sign in.</p>');
    console.log('Portal connection saved. Public client:',credentials.oidc.clientId);
    clearTimeout(expiry);server.close();
  } catch {redeemInFlight=false;res.writeHead(502);res.end('Connection could not be completed. Return to the Portal approval page and use Continue to obtain a fresh code.');}
});
await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(8090,'localhost',resolve);});
let expiry;
try {
  const discovery=await fetch(`${issuer}/.well-known/openid-configuration`,{signal:AbortSignal.timeout(10000),redirect:'error'}).then(r=>r.json());
  if(discovery.issuer!==issuer)throw Error('Issuer mismatch');
  const response=await fetch(`${issuer}/api/external/connect/requests`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({manifest:{product:'keystone',name:'Keystone',description:'Keystone Vault: encrypted secrets and configuration for Portal applications, plus service health.',appUrl,clientId:'keystone',redirectUris:[appUrl],scopes:['openid','profile','email'],confidential:false,externalAuth:false,externalRegistration:false},callbackUri:`${appUrl}/api/setup/portal-callback`,codeChallenge:challenge,codeChallengeMethod:'S256'}),signal:AbortSignal.timeout(10000),redirect:'error'});
  if(!response.ok)throw Error(`Portal connection request returned HTTP ${response.status}`);
  const result=await response.json();requestId=result.requestId;
  if(!requestId || new URL(result.approvalUrl).origin!==issuer)throw Error('Unexpected approval response');
  console.log('Approve this concrete registration in Portal SSO:',result.approvalUrl);
  console.log('App: Keystone; local URL: http://localhost:8090; public PKCE client; no password API; ROLE_ADMIN enforced by Keystone.');
  expiry=setTimeout(()=>{console.log('Onboarding listener timed out. Run connect-portal again if needed.');server.close();},30*60*1000);
} catch(error){server.close();throw error;}
process.on('SIGINT',()=>{clearTimeout(expiry);server.close();});
