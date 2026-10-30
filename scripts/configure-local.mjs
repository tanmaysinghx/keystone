// Link local Keystone and portfolio without printing the shared credential.
import { randomBytes } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
const keystone = new URL('../.env', import.meta.url);
const portfolio = new URL('../../selfie-portfolio/.env.local', import.meta.url);
let back = await readFile(keystone,'utf8').catch(()=> '');
let front = await readFile(portfolio,'utf8').catch(()=> '');
const existingBack=back.match(/^KEYSTONE_SERVICE_KEY=(.+)$/m)?.[1];
const existingFront=front.match(/^KEYSTONE_SERVICE_KEY=(.+)$/m)?.[1];
if(existingBack && existingFront && existingBack!==existingFront)throw Error('Existing service keys differ. Resolve them manually; no settings were changed.');
const key=existingBack||existingFront||randomBytes(32).toString('hex');
if(!existingBack)back+='\nKEYSTONE_SERVICE_KEY='+key+'\n';
if(!existingFront)front+='\nKEYSTONE_SERVICE_KEY='+key+'\n';
if(!/^KEYSTONE_URL=/m.test(front))front+='KEYSTONE_URL=http://127.0.0.1:8090\n';
await writeFile(keystone,back,{mode:0o600});await writeFile(portfolio,front,{mode:0o600});
console.log('Local service connection configured. Credentials were saved only to git-ignored environment files.');
