#!/usr/bin/env node
'use strict';
// Actual packaged JS/dependencies; no TypeScript/Babel, image build or image execution.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const {main, trustedDirectory, snapshot} = require('../wazuh-tls/qualify.cjs');
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
let createdState = null;

async function qualify() {
  const args = process.argv.slice(2);
  assert.deepEqual(args.filter((_,i)=>i%2===0), ['--bundle','--state-dir']);
  const bundle = path.resolve(args[1]), state = path.resolve(args[3]);
  const policyFile = path.join(__dirname,'../../deploy/wazuh/packaged-client/source.lock.json');
  const policyBytes = snapshot(policyFile,262144), policy=JSON.parse(policyBytes);
  assert.equal(process.version,policy.node_version,'Pinned fixture Node required');
  trustedDirectory(bundle,true);
  const buffers = {};
  for(const member of policy.files) {
    const bytes=snapshot(path.join(bundle,'root',member.path),member.size);
    assert.equal(bytes.length,member.size,'Packaged artifact size mismatch');
    assert.equal(hash(bytes),member.sha256,'Packaged artifact hash mismatch');
    buffers[member.path]=bytes;
  }
  const patched=snapshot(path.join(bundle,'patched/server-api-client.js'),65536);
  assert.equal(hash(patched),policy.compiled_patch.patched_sha256,'Reviewed compiled correction required');
  assert(!patched.includes(Buffer.from('sourceMappingURL=')),'Stale modified source map refused');
  const dockerfile=snapshot(path.join(bundle,'build-context/Dockerfile'),8192);
  const expected='FROM wazuh/wazuh-dashboard@'+policy.image_digest+'\nCOPY --chown=1000:1000 --chmod=0644 server-api-client.js /'+policy.compiled_patch.client_path+'\n';
  assert.equal(dockerfile.toString('utf8'),expected,'Only reviewed context instructions allowed');
  assert.equal(hash(snapshot(path.join(bundle,'build-context/server-api-client.js'),65536)),hash(patched));
  const manifest=JSON.parse(snapshot(path.join(bundle,'manifest.json'),262144));
  for(const flag of ['ready','runtime_qualified','image_built','image_executed','full_plugin_build'])
    assert.equal(manifest[flag],false,'Unqualified image gate must remain false');
  const sourcePolicy=JSON.parse(snapshot(path.join(__dirname,'../../deploy/wazuh/tls-client/source.lock.json'),8192));
  for(const member of sourcePolicy.members) assert.equal(hash(snapshot(path.join(bundle,member.name),32768)),member.sha256);
  assert.equal(hash(snapshot(path.join(bundle,'server-api-client.ts'),32768)),sourcePolicy.patched_sha256);
  const original=buffers[policy.compiled_patch.client_path], cookie=buffers[policy.compiled_patch.cookie_path];
  const packages=policy.closure.packages.map(p=>{
    const file=p.root+'/package.json';
    const data=JSON.parse(buffers[file]);
    assert.equal(data.name,p.name);assert.equal(data.version,p.version);
    return {name:data.name,version:data.version,root:p.root,package_json_sha256:hash(buffers[file])};
  });
  const verifiedRoot=path.join(state,'verified-packaged-root');
  const runtimeRoot=path.join(verifiedRoot,'usr/share/wazuh-dashboard');
  const allowed=policy.files.map(m=>path.join(verifiedRoot,m.path));
  const profile={
    nodeVersion:policy.node_version,axiosVersion:packages.find(p=>p.name==='axios').version,parentAxiosMetadataOnly:true,
    compilerName:'packaged-javascript-no-compilation',compilerVersion:'not-applicable',
    claim:'actual shipped client/dependency TLS component on Darwin fixture Node; no image execution',
    argv:args,axiosEntry:path.join(verifiedRoot,policy.compiled_patch.axios_entry),allowedModules:allowed,nodePath:'',
    async createCompiler(privateState) {
      createdState=privateState;
      fs.mkdirSync(verifiedRoot,{mode:0o700});
      for(const [name,bytes] of Object.entries(buffers)) {
        const file=path.join(verifiedRoot,name);
        fs.mkdirSync(path.dirname(file),{recursive:true,mode:0o700});
        fs.writeFileSync(file,bytes,{mode:0o600,flag:'wx'});
      }
      fs.symlinkSync(path.join(runtimeRoot,'node_modules'),path.join(state,'node_modules'),'dir');
      return {metadata:{
        image_digest:policy.image_digest,config_digest:policy.config_digest,
        payload_sha256:policy.blobs[0].sha256,payload_diff_id:policy.blobs[0].diff_id,
        selected_files:policy.files.length,selected_packages:packages,
        packaged_original_sha256:hash(original),packaged_cookie_sha256:hash(cookie),packaged_corrected_sha256:hash(patched),
        packaged_policy_sha256:hash(policyBytes),wrapper_sha256:hash(snapshot(__filename,65536)),
        node_executable_sha256:hash(snapshot(process.execPath,134217728)),
        selected_tree_sha256:hash(Buffer.from(JSON.stringify(policy.files))),
        build_context_dockerfile_sha256:hash(dockerfile),module_resolution_guard:true,
        image_built:false,image_executed:false,bundled_linux_node_verified:false,source_map_removed:true,
        parent_artifact_execution:false,artifact_execution_only_in_guarded_children:true,
      },async compile(_source,filename) {
        return (filename==='cookie.ts'?cookie:filename==='upstream-server-api-client.ts'?original:patched).toString('utf8');
      }};
    },
  };
  await main(profile);
}

module.exports={qualify};
if(require.main===module) qualify().catch(error=>{
  if(createdState) {
    try {
      trustedDirectory(createdState,true);
      assert(!fs.existsSync(path.join(createdState,'report.json')));
      fs.writeFileSync(path.join(createdState,'setup-failure.json'),JSON.stringify({passed:false,phase:'setup-or-artifact-load',diagnostic:String(error.message).slice(0,8192)})+'\n',{mode:0o600,flag:'wx'});
    } catch {}
  }
  process.stderr.write('RF-07C3 artifact qualification failed; setup/load failures are not TLS refusal evidence.\n');
  process.exitCode=1;
});
