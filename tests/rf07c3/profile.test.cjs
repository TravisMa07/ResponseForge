'use strict';
// Opt-in prepared-artifact checks; setup failures are separate from TLS refusals.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {spawnSync}=require('node:child_process');
const args=process.argv.slice(2);
assert.deepEqual(args.filter((_,i)=>i%2===0),['--node24','--bundle','--state-root']);
const [otherNode,bundle,root]=[args[1],args[3],args[5]].map(p=>path.resolve(p));
fs.mkdirSync(root,{mode:0o700});const script=path.resolve('tools/wazuh-packaged/qualify.cjs');
const policy=JSON.parse(fs.readFileSync('deploy/wazuh/packaged-client/source.lock.json'));
let checks=0;
function refuse(name,input=bundle,node=process.execPath,existing=false) {
  const state=path.join(root,'state-'+name);
  if(existing){fs.mkdirSync(state,{mode:0o700});fs.writeFileSync(path.join(state,'retained'),'unchanged',{mode:0o600});}
  const r=spawnSync(node,[script,'--bundle',input,'--state-dir',state],{encoding:'utf8',timeout:20000});
  assert.equal(r.status,1,name+' must refuse');assert(!r.stdout.includes('"passed":true'));
  if(existing) assert.deepEqual(fs.readdirSync(state),['retained']);else assert(!fs.existsSync(state));checks++;
}
refuse('wrong-node',bundle,otherNode);refuse('existing-state',bundle,process.execPath,true);
for(const change of ['client','dependency','patch','source','context','linked']) {
  const copy=path.join(root,'bundle-'+change);fs.cpSync(bundle,copy,{recursive:true});
  const target=path.join(copy,change==='client'?'root/'+policy.compiled_patch.client_path:
    change==='dependency'?'root/'+policy.compiled_patch.axios_entry:
    change==='patch'?'patched/server-api-client.js':change==='source'?'upstream-server-api-client.ts':
    change==='context'?'build-context/Dockerfile':'root/'+policy.compiled_patch.cookie_path);
  if(change==='linked'){fs.unlinkSync(target);fs.symlinkSync(path.join(bundle,'root',policy.compiled_patch.cookie_path),target);}
  else fs.appendFileSync(target,change==='context'?'RUN unreviewed-command\n':'\n/* unreviewed input */');
  refuse(change,copy);
}
const sentinel=path.join(root,'ambient-executed'),fake=path.join(root,'ambient/node_modules/axios');fs.mkdirSync(fake,{recursive:true,mode:0o700});
fs.writeFileSync(path.join(fake,'package.json'),'{"name":"axios","version":"1.18.1","main":"index.js"}',{mode:0o600});
fs.writeFileSync(path.join(fake,'index.js'),`require('fs').writeFileSync(${JSON.stringify(sentinel)},'executed');throw new Error('Ambient module executed');`,{mode:0o600});
const optional=path.join(path.dirname(fake),'supports-color');fs.mkdirSync(optional,{mode:0o700});
fs.writeFileSync(path.join(optional,'index.js'),`require('fs').writeFileSync(${JSON.stringify(sentinel)},'executed');module.exports={};`,{mode:0o600});
const state=path.join(root,'state-ambient');
const r=spawnSync(process.execPath,[script,'--bundle',bundle,'--state-dir',state],{env:{...process.env,NODE_PATH:path.dirname(fake)},encoding:'utf8',timeout:60000});
assert.equal(r.status,0,'Real artifact must ignore ambient lookalike: '+r.stderr);
assert(!fs.existsSync(sentinel));const report=JSON.parse(fs.readFileSync(path.join(state,'report.json')));assert.equal(report.passed,true);
for(const value of Object.values(report.scenarios)) if(value.result){assert.equal(value.result.module_guard,true);assert.equal(value.result.outside_module_resolutions,0);}
checks++;
console.log('PASS: '+checks+' real artifact profile checks, including13 TLS scenarios with hostile ambient package');
