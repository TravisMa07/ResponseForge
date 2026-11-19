'use strict';
// Opt-in setup refusal checks; no fixture here is transport/runtime proof.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const {spawnSync} = require('node:child_process');
const args = process.argv.slice(2);
assert.deepEqual(args.filter((_,i)=>i%2===0), ['--node24','--bundle','--platform-source','--state-root']);
const [otherNode,bundle,source,root] = [args[1],args[3],args[5],args[7]].map(p=>path.resolve(p));
fs.mkdirSync(root,{mode:0o700});
const script=path.resolve('tools/wazuh-platform/qualify.cjs');
const policy=JSON.parse(fs.readFileSync('deploy/wazuh/platform-client/source.lock.json'));
let checks=0;
function refuse(name, {node=process.execPath, input=source, env=process.env, existing=false}={}) {
  const state=path.join(root,'check-'+name);
  if(existing) {fs.mkdirSync(state,{mode:0o700});fs.writeFileSync(path.join(state,'retained'),'unchanged',{mode:0o600});}
  const result=spawnSync(node,[script,'--bundle',bundle,'--state-dir',state,'--platform-source',input],{env,encoding:'utf8',timeout:20000});
  assert.equal(result.status,1,name+' must refuse setup');
  assert(!result.stdout.includes('"passed":true'),name+' cannot claim TLS success');
  if(existing) assert.deepEqual(fs.readdirSync(state),['retained']);
  else assert(!fs.existsSync(state),name+' must refuse before state/compilation');
  checks++;
}
refuse('wrong-node',{node:otherNode});
for(const change of ['preset','manifest','symlink','hardlink']) {
  const copy=path.join(root,'source-'+change);fs.cpSync(source,copy,{recursive:true});
  const target=path.join(copy,change==='manifest'?'package.json':'node_preset.js');
  if(change==='symlink'||change==='hardlink') {
    fs.unlinkSync(target);
    if(change==='symlink') fs.symlinkSync(path.join(source,'node_preset.js'),target);
    else {const origin=path.join(root,'hardlink-origin');fs.writeFileSync(origin,fs.readFileSync(path.join(source,'node_preset.js')),{mode:0o600});fs.linkSync(origin,target);}
  } else fs.appendFileSync(target,'\n// unreviewed input');
  refuse('wrong-'+change,{input:copy});
}
refuse('existing-state',{existing:true});
const sentinel=path.join(root,'executed-untrusted-dependency');
for(const mode of ['wrong-version','ambient-escape']) {
  const fake=path.join(root,mode);fs.mkdirSync(fake,{mode:0o700});fs.mkdirSync(path.join(fake,'node_modules'),{mode:0o700});
  const names=mode==='wrong-version'?Object.keys(policy.compiler_versions):['axios'];
  for(const name of names) {
    const dir=path.join(fake,'node_modules',name);fs.mkdirSync(dir,{recursive:true,mode:0o700});
    fs.writeFileSync(path.join(dir,'package.json'),JSON.stringify({name,version:mode==='wrong-version'&&name==='axios'?'0.0.0':policy.compiler_versions[name],main:'index.js'}),{mode:0o600});
    fs.writeFileSync(path.join(dir,'index.js'),`require('fs').writeFileSync(${JSON.stringify(sentinel)},'executed'); throw new Error('Untrusted dependency executed');`,{mode:0o600});
  }
  refuse(mode,{env:{...process.env,NODE_PATH:path.join(fake,'node_modules')+path.delimiter+process.env.NODE_PATH}});
  assert(!fs.existsSync(sentinel),'Unverified dependency must not execute');
}
const parserRoot=path.join(root,'ambient-parser');
const parserDir=path.join(parserRoot,'node_modules/@yarnpkg/lockfile');
fs.mkdirSync(parserDir,{recursive:true,mode:0o700});fs.chmodSync(parserRoot,0o700);
fs.copyFileSync('tools/wazuh-platform/yarn/package.json',path.join(parserRoot,'package.json'));
fs.writeFileSync(path.join(parserRoot,'package-lock.json'),'{}',{mode:0o600});
fs.writeFileSync(path.join(parserDir,'package.json'),JSON.stringify({name:'@yarnpkg/lockfile',version:'1.1.0',main:'index.js'}),{mode:0o600});
fs.writeFileSync(path.join(parserDir,'index.js'),`require('fs').writeFileSync(${JSON.stringify(sentinel)},'executed');`,{mode:0o600});
refuse('ambient-parser-escape',{env:{...process.env,NODE_PATH:path.join(parserRoot,'node_modules')+path.delimiter+process.env.NODE_PATH}});
assert(!fs.existsSync(sentinel),'Unverified parser must not execute');
console.log('PASS: '+checks+' real CLI setup refusals; no unverified preset/dependency executed');
