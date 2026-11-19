#!/usr/bin/env node
'use strict';
// Original synthetic TLS fixtures; no Wazuh manager, plugin-build or endpoint claim.
const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const http = require('node:http');
const crypto = require('node:crypto');
const {execFileSync, spawn} = require('node:child_process');
const assert = require('node:assert/strict');
const hash = value => crypto.createHash('sha256').update(value).digest('hex');

function trustedDirectory(dir, privateLeaf=false) {
  const absolute = path.resolve(dir);
  assert.equal(fs.realpathSync(absolute),absolute,'Symlink directory ancestry refused');
  for (let current=absolute;;current=path.dirname(current)) {
    const stat=fs.lstatSync(current);
    const stickyRoot=stat.uid===0 && (stat.mode & 0o1000);
    assert(stat.isDirectory() && [0,process.getuid()].includes(stat.uid) && (!(stat.mode & 0o022) || stickyRoot),'Replaceable directory ancestry');
    if (current===absolute && privateLeaf) assert(stat.uid===process.getuid() && !(stat.mode & 0o077),'Private directory required');
    if (current===path.dirname(current)) break;
  }
}
function snapshot(file, limit) {
  trustedDirectory(path.dirname(file));
  const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  try {
    const before=fs.fstatSync(fd,{bigint:true});
    assert(before.isFile() && before.nlink===1n && [0n,BigInt(process.getuid())].includes(before.uid) && !(before.mode & 0o022n) && before.size>0n && before.size<=BigInt(limit),'Unsafe source leaf');
    const raw=Buffer.alloc(Number(before.size)+1);
    let length=0, got;
    while ((got=fs.readSync(fd,raw,length,raw.length-length,null))>0) length+=got;
    const after=fs.fstatSync(fd,{bigint:true});
    for (const key of ['dev','ino','size','mtimeNs','ctimeNs','nlink','mode','uid']) assert.equal(before[key],after[key],'Source changed during read');
    assert.equal(length,Number(before.size),'Source read size mismatch');
    return raw.subarray(0,length);
  } finally {fs.closeSync(fd);}
}

async function child(config) {
  // Dependencies and the complete compiled class must load before refusal is evidence.
  const axios = require('axios');
  const {ServerAPIClient} = require(config.module);
  const host = {url: config.url, port: config.port, username: 'synthetic-user', password: 'synthetic-password'};
  const client = new ServerAPIClient({warn() {}}, {get: async () => host, isEnabledAuthWithRunAs: () => false}, {});
  const scoped = client.asScoped({}, {headers: {cookie: 'other=1; wz-token=synthetic-cookie-token; end=2'}});
  const results = {loaded: true, axios: axios.VERSION};
  for (const method of ['authenticate', 'request']) {
    try {
      const value = method === 'authenticate' ? await scoped.authenticate('synthetic') :
        await scoped.request('GET', '/synthetic', {headers: {Authorization: 'forged', 'X-Untrusted': 'drop'}}, {apiHostID: 'synthetic', token: 'forged-option'});
      results[method] = {success: true, valid: method === 'authenticate' ? value === 'synthetic-auth-token' : value.data.ok === true};
    } catch (error) {
      results[method] = {success: false, code: error.code || null, status: error.response?.status || null,
        policy: error.message === 'Verified HTTPS manager API URL required'};
    }
  }
  process.stdout.write(JSON.stringify(results));
}

function runChild(config, env) {
  return new Promise((resolve, reject) => {
    const proc = spawn(process.execPath, [__filename, '--child', JSON.stringify(config)], {env, stdio: ['ignore', 'pipe', 'pipe']});
    let out = '', err = '';
    const timeout = setTimeout(() => { proc.kill(); reject(new Error('Fixture child timeout')); }, 15000);
    proc.stdout.on('data', data => {out += data; if (out.length > 65536) proc.kill();});
    proc.stderr.on('data', data => {err += data; if (err.length > 65536) proc.kill();});
    proc.on('error', reject);
    proc.on('close', code => {
      clearTimeout(timeout);
      if (code !== 0) return reject(new Error('Fixture child setup/execution failed (not security refusal)'));
      try {resolve(JSON.parse(out));} catch {reject(new Error('Invalid child evidence'));}
    });
  });
}

function certs(dir) {
  const run = args => execFileSync('openssl', args, {stdio: 'ignore', timeout: 20000});
  for (const name of ['trusted', 'other']) {
    fs.writeFileSync(path.join(dir, `${name}.cnf`), `[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n[dn]\nCN=RF07C Original Synthetic ${name} CA\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n`);
    run(['req','-x509','-newkey','rsa:2048','-nodes','-sha256','-days','2','-config',path.join(dir,`${name}.cnf`),'-keyout',path.join(dir,`${name}.key`),'-out',path.join(dir,`${name}.pem`)]);
  }
  for (const [name, ca, san] of [['good','trusted','IP:127.0.0.1'],['untrusted','other','IP:127.0.0.1'],['wrongname','trusted','DNS:wrong.synthetic.invalid']]) {
    fs.writeFileSync(path.join(dir,`${name}.ext`),`basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=${san}\n`);
    run(['req','-newkey','rsa:2048','-nodes','-subj','/CN=Original Synthetic Fixture','-keyout',path.join(dir,`${name}.key`),'-out',path.join(dir,`${name}.csr`)]);
    run(['x509','-req','-in',path.join(dir,`${name}.csr`),'-CA',path.join(dir,`${ca}.pem`),'-CAkey',path.join(dir,`${ca}.key`),'-CAcreateserial','-days','2','-sha256','-extfile',path.join(dir,`${name}.ext`),'-out',path.join(dir,`${name}.pem`)]);
  }
  for (const name of fs.readdirSync(dir)) fs.chmodSync(path.join(dir,name), 0o600);
}

async function main() {
  assert.equal(process.version, 'v24.21.0', 'Pinned component Node version required');
  const args = process.argv.slice(2);
  assert.deepEqual(args.filter((_, i) => i % 2 === 0), ['--bundle','--state-dir']);
  const bundle = path.resolve(args[1]), state = path.resolve(args[3]);
  trustedDirectory(path.dirname(state));
  assert(!fs.existsSync(state), 'State must be a new private directory');
  trustedDirectory(bundle,true);
  const lock = JSON.parse(fs.readFileSync(path.join(__dirname,'../../deploy/wazuh/tls-client/source.lock.json')));
  const buffers={};
  for (const member of lock.members) {
    const raw=snapshot(path.join(bundle,member.name),member.size);
    assert.equal(raw.length,member.size,'Source size mismatch');
    assert.equal(hash(raw),member.sha256,'Source hash mismatch');
    buffers[member.name]=raw;
  }
  const patched = snapshot(path.join(bundle,'server-api-client.ts'),32768);
  buffers['server-api-client.ts']=patched;
  assert.equal(hash(patched),lock.patched_sha256,'Patched source hash mismatch');
  const ts = require('typescript');
  const axios = require('axios');
  assert.equal(ts.version,'5.5.2'); assert.equal(axios.VERSION,'1.17.0');
  fs.mkdirSync(state,{mode:0o700,recursive:false});
  trustedDirectory(state,true);
  const materials = path.join(state,'materials'); fs.mkdirSync(materials,{mode:0o700});
  certs(materials);
  const modules = {};
  for (const [kind, filename] of [['original','upstream-server-api-client.ts'],['corrected','server-api-client.ts']]) {
    const dir = path.join(state,kind); fs.mkdirSync(dir,{mode:0o700});
    for (const [input, output] of [[filename,'server-api-client.js'],['cookie.ts','cookie.js']]) {
      const result = ts.transpileModule(buffers[input].toString('utf8'), {fileName:input, reportDiagnostics:true, compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022,esModuleInterop:true}});
      assert.equal((result.diagnostics || []).filter(d => d.category === ts.DiagnosticCategory.Error).length,0,'Transpile failure');
      fs.writeFileSync(path.join(dir,output),result.outputText,{mode:0o600});
    }
    modules[kind] = path.join(dir,'server-api-client.js');
  }
  const servers = [], counters = {}, records = {};
  async function listen(name, tlsName, redirect) {
    counters[name] = {auth:0, request:0, badIdentity:0};
    const handler = (req,res) => {
      const auth = req.url.startsWith('/security/user/authenticate');
      counters[name][auth?'auth':'request']++;
      const expected = auth ? 'Basic ' + Buffer.from('synthetic-user:synthetic-password').toString('base64') : 'Bearer synthetic-cookie-token';
      if (req.headers.authorization !== expected || req.headers['x-untrusted']) counters[name].badIdentity++;
      if (redirect) {res.writeHead(302,{Location:redirect()});res.end();return;}
      res.setHeader('Content-Type','application/json');
      res.end(JSON.stringify(auth ? {data:{token:'synthetic-auth-token'}} : {ok:true}));
    };
    const server = tlsName ? https.createServer({key:fs.readFileSync(path.join(materials,tlsName+'.key')),cert:fs.readFileSync(path.join(materials,tlsName+'.pem'))},handler) : http.createServer(handler);
    server.on('tlsClientError',()=>{}); servers.push(server);
    await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
    return server.address().port;
  }
  const baseEnv = {...process.env};
  for (const key of ['HTTPS_PROXY','HTTP_PROXY','ALL_PROXY','https_proxy','http_proxy','all_proxy','NO_PROXY','no_proxy','NODE_EXTRA_CA_CERTS','NODE_TLS_REJECT_UNAUTHORIZED','NODE_OPTIONS','NODE_USE_ENV_PROXY']) delete baseEnv[key];
  const report = {schema_version:'1.0',claim:'complete-transpiled-ServerAPIClient synthetic native TLS component only',revision:lock.revision,source_sha256:lock.members[0].sha256,patched_sha256:lock.patched_sha256,cookie_sha256:lock.members[1].sha256,node:process.version,openssl:execFileSync('openssl',['version'],{encoding:'utf8'}).trim(),axios:axios.VERSION,typescript:ts.version,harness_sha256:hash(fs.readFileSync(__filename)),compiled_sha256:Object.fromEntries(Object.entries(modules).map(([name,file])=>[name,hash(fs.readFileSync(file))])),cookie_compiled_sha256:hash(fs.readFileSync(path.join(state,'corrected/cookie.js'))),semantic_typecheck:false,full_plugin_build:false,manager_runtime:false,scenarios:records};
  try {
    const good = await listen('good','good');
    const bad = await listen('untrusted','untrusted');
    const wrong = await listen('wrongname','wrongname');
    const plain = await listen('plain',null);
    const proxy = await listen('proxy',null);
    const redirectHTTPS = await listen('redirectHTTPS','good',()=>`https://127.0.0.1:${good}/redirect-target`);
    const redirectHTTP = await listen('redirectHTTP','good',()=>`http://127.0.0.1:${plain}/redirect-target`);
    async function check(name, port, env, expectation, url='https://127.0.0.1', module=modules.corrected) {
      const before = structuredClone(counters);
      const result = await runChild({module,url,port},{...baseEnv,...env});
      assert.equal(result.loaded,true); assert.equal(result.axios,'1.17.0');
      const delta = Object.fromEntries(Object.entries(counters).map(([key,value])=>[key,Object.fromEntries(Object.entries(value).map(([k,v])=>[k,v-before[key][k]]))]));
      records[name] = {result,delta};
      for (const method of ['authenticate','request']) assert.equal(result[method].success,expectation==='success',`${name}: ${method}`);
      if (expectation === 'success') {
        assert(result.authenticate.valid && result.request.valid,`${name}: application response`);
        assert.equal(delta.good.auth,1); assert.equal(delta.good.request,1); assert.equal(delta.good.badIdentity,0);
      } else if (expectation === 'refuse') {
        const policyCases=['plain_HTTP','URL_credentials','URL_control'];
        for (const method of ['authenticate','request']) {
          if (policyCases.includes(name)) assert.equal(result[method].policy,true,`${name}: expected URL policy refusal`);
          else assert.equal(result[method].code,name==='wrong_SAN'?'ERR_TLS_CERT_ALTNAME_INVALID':'UNABLE_TO_VERIFY_LEAF_SIGNATURE',`${name}: expected native TLS refusal`);
        }
        for (const value of Object.values(delta)) assert.equal(value.auth+value.request,0,`${name}: refusal before HTTP`);
      } else if (expectation === 'redirect') {
        assert.equal(delta.good.auth+delta.good.request+delta.plain.auth+delta.plain.request,0,'Redirect target received HTTP');
        assert.equal(result.authenticate.status,302); assert.equal(result.request.status,302);
      }
      return result;
    }
    const trusted = {NODE_EXTRA_CA_CERTS:path.join(materials,'trusted.pem')};
    // Baseline must actually load and exchange credentials, exposing the original defect.
    const beforeRed = structuredClone(counters.untrusted);
    const baseline = await runChild({module:modules.original,url:'https://127.0.0.1',port:bad},baseEnv);
    assert(baseline.loaded && baseline.authenticate.success && baseline.request.success,'Original defect not reproduced');
    assert.equal(counters.untrusted.auth-beforeRed.auth,1); assert.equal(counters.untrusted.request-beforeRed.request,1);
    records.original_insecure_baseline = {loaded:true,secure_assertion:'FAIL: untrusted certificate accepted',authHTTP:1,requestHTTP:1};
    await check('trusted_CA_matching_SAN',good,trusted,'success');
    await check('missing_CA',good,{},'refuse');
    await check('different_CA',good,{NODE_EXTRA_CA_CERTS:path.join(materials,'other.pem')},'refuse');
    await check('untrusted_chain',bad,trusted,'refuse');
    await check('wrong_SAN',wrong,trusted,'refuse');
    await check('environment_TLS_zero',bad,{...trusted,NODE_TLS_REJECT_UNAUTHORIZED:'0'},'refuse');
    await check('plain_HTTP',plain,trusted,'refuse','http://127.0.0.1');
    await check('URL_credentials',good,trusted,'refuse','https://embedded:password@127.0.0.1');
    await check('URL_control',good,trusted,'refuse','https://127.0.0.1\n');
    await check('HTTPS_redirect',redirectHTTPS,trusted,'redirect');
    await check('HTTP_redirect',redirectHTTP,trusted,'redirect');
    await check('hostile_proxy',good,{...trusted,HTTPS_PROXY:`http://127.0.0.1:${proxy}`,HTTP_PROXY:`http://127.0.0.1:${proxy}`,ALL_PROXY:`http://127.0.0.1:${proxy}`,NO_PROXY:'',NODE_USE_ENV_PROXY:'1'},'success');
    assert.equal(counters.proxy.auth+counters.proxy.request,0,'Proxy received credentials');
    report.passed = true;
    fs.writeFileSync(path.join(state,'report.json'),JSON.stringify(report,null,2)+'\n',{mode:0o600});
    process.stdout.write(JSON.stringify({passed:true,scenarios:Object.keys(records).length,report:path.join(state,'report.json')})+'\n');
  } catch (error) {
    report.passed = false; report.failure = error.message;
    fs.writeFileSync(path.join(state,'report.json'),JSON.stringify(report,null,2)+'\n',{mode:0o600});
    throw error;
  } finally {
    await Promise.all(servers.map(server => new Promise(resolve => {server.closeAllConnections();server.close(resolve);} )));
  }
}

(async()=>{
  if (process.argv[2] === '--child') await child(JSON.parse(process.argv[3]));
  else await main();
})().catch(error=>{process.stderr.write('RF-07C component qualification failed; setup failures are not TLS refusal evidence. ' + error.message + '\n');process.exitCode=1;});
