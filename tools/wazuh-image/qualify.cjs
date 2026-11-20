'use strict';
// Runs only inside the approved isolated image; no Docker socket or manager startup.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {main,snapshot}=require('../wazuh-tls/qualify.cjs');
const hash=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
async function run(root,session,inputSha,generator) {
  assert.equal(process.platform,'linux');assert.equal(process.arch,'arm64');
  assert.equal(process.getuid(),1000);assert.equal(process.getgid(),1000);
  assert(/^[0-9a-f]{32}$/.test(session.run_id)&&/^[0-9a-f]{64}$/.test(session.nonce)&&/^sha256:[0-9a-f]{64}$/.test(session.image_id));
  const policyPath=path.join(root,'deploy/wazuh/image-qualification/source.lock.json');
  const policy=JSON.parse(snapshot(policyPath,32768));
  const packaged=JSON.parse(snapshot(path.join(root,'deploy/wazuh/packaged-client/source.lock.json'),262144));
  assert.equal(fs.realpathSync(process.execPath),policy.node_path,'Only primary bundled executable allowed');
  assert.equal(hash(snapshot(process.execPath,134217728)),policy.node_sha256,'Bundled executable mismatch');
  assert.equal(hash(snapshot(policy.node_license_path,262144)),policy.node_license_sha256);
  const selected={};
  for(const member of packaged.files) {
    const filename='/'+member.path,bytes=snapshot(filename,member.size===29637?65536:member.size);
    assert.equal(hash(bytes),filename===policy.client_path?policy.client_sha256:member.sha256,'Installed file mismatch');
    selected[filename]=bytes;
  }
  const original=snapshot(path.join(root,'original/server-api-client.js'),65536);
  assert.equal(hash(original),packaged.compiled_patch.original_sha256);
  const corrected=selected[policy.client_path],cookie=selected['/'+packaged.compiled_patch.cookie_path];
  const materials=['trusted.pem','other.pem','good.pem','good.key','untrusted.pem','untrusted.key','wrongname.pem','wrongname.key'];
  const state=path.join(root,'state');
  const allowed=Object.keys(selected);
  let emitted=false;
  try {
    await main({nodeVersion:process.version,axiosVersion:'1.18.1',parentAxiosMetadataOnly:true,
      compilerName:'installed-image-javascript-no-compilation',compilerVersion:'not-applicable',
      claim:'derived image primary Linux Node and installed client TLS fixture only',
      argv:['--bundle',path.join(root,'bundle'),'--state-dir',state],
      axiosEntry:'/'+packaged.compiled_patch.axios_entry,allowedModules:allowed,nodePath:'',
      correctedModule:policy.client_path,opensslVersion:'Node OpenSSL '+process.versions.openssl,
      async prepareMaterials(destination) {
        for(const name of materials) fs.writeFileSync(path.join(destination,name),snapshot(path.join(root,'materials',name),16384),{mode:0o600,flag:'wx'});
      },
      async createCompiler() {
        fs.symlinkSync('/usr/share/wazuh-dashboard/node_modules',path.join(state,'node_modules'),'dir');
        return {metadata:{qualification_run_id:session.run_id,qualification_nonce:session.nonce,
          fixture_input_sha256:inputSha,image_id:session.image_id,node_executable_sha256:policy.node_sha256,
          node_license_sha256:policy.node_license_sha256,platform:process.platform,architecture:process.arch,
          uid:process.getuid(),gid:process.getgid(),installed_corrected_module:policy.client_path,
          packaged_corrected_sha256:hash(corrected),selected_files:Object.keys(selected).length,
          module_resolution_guard:true,parent_artifact_execution:false,dashboard_started:false,manager_started:false,
          bundled_linux_node_verified:true,wrapper_sha256:hash(snapshot(__filename,65536)),
          fixture_material_generator:generator,image_executed:true},
          async compile(_bytes,name){return(name==='cookie.ts'?cookie:name==='upstream-server-api-client.ts'?original:corrected).toString('utf8');}};
      },
      async onReport(report){emitted=true;process.stdout.write(JSON.stringify(report)+'\n');},
    });
  } catch(error) {
    if(!emitted&&fs.existsSync(path.join(state,'report.json'))){process.stdout.write(fs.readFileSync(path.join(state,'report.json')));emitted=true;}
    process.exitCode=1;
    if(!emitted)throw error;
  }
}
module.exports={run};
