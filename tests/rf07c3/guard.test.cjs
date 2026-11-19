'use strict';
// Original owned modules prove the manifest guard without vendor/endpoint execution.
const fs=require('node:fs'), path=require('node:path'), assert=require('node:assert/strict');
const {spawnSync}=require('node:child_process');
const root=path.resolve(process.argv[2]);fs.mkdirSync(root,{mode:0o700});
const guard=path.resolve('tools/wazuh-tls/qualify.cjs');
const safe=path.join(root,'safe.cjs'),outside=path.join(root,'outside.cjs'),sentinel=path.join(root,'executed');
fs.writeFileSync(safe,'module.exports=17;',{mode:0o600});
fs.writeFileSync(outside,`require('node:fs').writeFileSync(${JSON.stringify(sentinel)},'executed');module.exports=29;`,{mode:0o600});
const data=path.join(root,'outside.json');fs.writeFileSync(data,'{"value":29}',{mode:0o600});
const nested=path.join(root,'nested.cjs');fs.writeFileSync(nested,`module.exports=require(${JSON.stringify(outside)});`,{mode:0o600});
const alias=path.join(root,'alias.cjs');fs.symlinkSync(outside,alias);
let checks=0;
for(const [name,request,allowed,success] of [
  ['builtin','node:fs',[],true],['owned',safe,[safe],true],['outside',outside,[safe],false],
  ['transitive',nested,[nested],false],['linked-outside',alias,[safe],false],['json-outside',data,[safe],false],
]) {
  const code=`const assert=require('node:assert/strict');const denied=require(${JSON.stringify(guard)}).installModuleGuard(${JSON.stringify(allowed)});${success?`require(${JSON.stringify(request)});assert.equal(denied(),0);`:`assert.throws(()=>require(${JSON.stringify(request)}),/outside verified artifact/);assert.equal(denied(),1);`}`;
  const result=spawnSync(process.execPath,['-e',code],{encoding:'utf8',timeout:5000});
  assert.equal(result.status,0,name+': '+result.stderr);assert(!fs.existsSync(sentinel));checks++;
}
console.log('PASS: '+checks+' original module-guard vectors; no outside module executed');
