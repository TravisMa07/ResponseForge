#!/usr/bin/env node
'use strict';
// Host-only original certificate preparation; no Docker or shipped-code execution.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {execFileSync}=require('node:child_process');
const {snapshot,trustedDirectory,createFixtureMaterials}=require('../wazuh-tls/qualify.cjs');
const hash=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
function prepare() {
  const args=process.argv.slice(2);assert.deepEqual(args.filter((_,i)=>i%2===0),['--bundle','--output']);
  const bundle=path.resolve(args[1]),output=path.resolve(args[3]);
  trustedDirectory(bundle,true);trustedDirectory(path.dirname(output));assert(!fs.existsSync(output),'New private output required');
  const repository=path.resolve(__dirname,'../..');
  const policy=JSON.parse(snapshot(path.join(repository,'deploy/wazuh/image-qualification/source.lock.json'),32768));
  const files={};
  const sources={'runner/wazuh-tls/qualify.cjs':'tools/wazuh-tls/qualify.cjs','runner/wazuh-image/qualify.cjs':'tools/wazuh-image/qualify.cjs','deploy/wazuh/tls-client/source.lock.json':'deploy/wazuh/tls-client/source.lock.json','deploy/wazuh/packaged-client/source.lock.json':'deploy/wazuh/packaged-client/source.lock.json','deploy/wazuh/image-qualification/source.lock.json':'deploy/wazuh/image-qualification/source.lock.json'};
  for(const [name,file] of Object.entries(sources))files[name]=snapshot(path.join(repository,file),524288);
  for(const [name,expected] of Object.entries(policy.source_hashes)) {
    const relative=name==='original/server-api-client.js'?'root/usr/share/wazuh-dashboard/plugins/wazuhCore/server/services/server-api-client.js':name.slice(7);
    const bytes=snapshot(path.join(bundle,relative),65536);assert.equal(hash(bytes),expected);files[name]=bytes;
  }
  fs.mkdirSync(output,{mode:0o700});trustedDirectory(output,true);
  const materials=path.join(output,'materials');fs.mkdirSync(materials,{mode:0o700});
  createFixtureMaterials(materials);
  for(const name of ['trusted.pem','other.pem','good.pem','good.key','untrusted.pem','untrusted.key','wrongname.pem','wrongname.key']) files['materials/'+name]=snapshot(path.join(materials,name),16384);
  const value={schema_version:'1.0',files:Object.fromEntries(Object.entries(files).map(([name,bytes])=>[name,bytes.toString('base64')])),material_generator:execFileSync('openssl',['version'],{encoding:'utf8',timeout:5000}).trim()};
  const raw=Buffer.from(JSON.stringify(value)+'\n');assert(raw.length<=2097152);
  fs.writeFileSync(path.join(output,'fixture.json'),raw,{mode:0o600,flag:'wx'});
  process.stdout.write(JSON.stringify({prepared:true,docker_used:false,fixture_sha256:hash(raw)})+'\n');
}
if(require.main===module){try{prepare();}catch{process.stderr.write('Private image fixture preparation refused; no Docker operation performed.\n');process.exitCode=1;}}
module.exports={prepare};
