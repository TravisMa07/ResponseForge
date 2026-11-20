'use strict';
// Original loader vectors; no vendor code, Docker, downloads or services.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {spawnSync}=require('node:child_process');
const bootstrap=fs.readFileSync(path.resolve(__dirname,'../../tools/wazuh-image/bootstrap.cjs'),'utf8');
function run(input){return spawnSync(process.execPath,['-e',bootstrap],{input,timeout:5000,maxBuffer:1048576});}
for(const input of ['', '{}\n', '{broken}\n', '{}\n{}\n', 'x'.repeat(2097153)]) {
  const result=run(input);assert.equal(result.status,1);assert.equal(JSON.parse(result.stdout).passed,false);
}
const names=['runner/wazuh-tls/qualify.cjs','runner/wazuh-image/qualify.cjs','deploy/wazuh/tls-client/source.lock.json','deploy/wazuh/packaged-client/source.lock.json','deploy/wazuh/image-qualification/source.lock.json','bundle/upstream-server-api-client.ts','bundle/server-api-client.ts','bundle/cookie.ts','bundle/LICENSE','original/server-api-client.js',...['trusted.pem','other.pem','good.pem','good.key','untrusted.pem','untrusted.key','wrongname.pem','wrongname.key'].map(n=>'materials/'+n)];
const files=Object.fromEntries(names.map(n=>[n,Buffer.from('original data').toString('base64')]));
// Original harmless module, only testing fixed-name staging/frame/identity delivery.
files['runner/wazuh-image/qualify.cjs']=Buffer.from(`exports.run=async(root,session,digest,generator)=>{const fs=require('node:fs'),assert=require('node:assert/strict');assert.equal(fs.statSync(root).mode&511,448);assert.equal(session.nonce,'original-test');assert.equal(generator,'original-test');assert(/^[a-f0-9]{64}$/.test(digest));fs.rmSync(root,{recursive:true});console.log(JSON.stringify({passed:true,qualified:false}));};`).toString('base64');
const value={schema_version:'1.0',files,session:{nonce:'original-test'},material_generator:'original-test'};
let result=run(JSON.stringify(value)+'\n');assert.equal(result.status,0,String(result.stderr));assert.equal(JSON.parse(result.stdout).qualified,false);
for(const key of ['../outside','unknown.cjs']) {
  const changed=structuredClone(value);delete changed.files['bundle/LICENSE'];changed.files[key]='';
  result=run(JSON.stringify(changed)+'\n');assert.equal(result.status,1);assert.equal(JSON.parse(result.stdout).passed,false);
}
const changed=structuredClone(value);changed.files['bundle/LICENSE']='!invalid';
result=run(JSON.stringify(changed)+'\n');assert.equal(result.status,1);assert.equal(JSON.parse(result.stdout).passed,false);
console.log('9 original bootstrap vectors passed; qualified:false; no Docker');
