#!/usr/bin/env node
'use strict';
// Executes reviewed private upstream presets, never arbitrary caller-selected code.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {createRequire} = require('node:module');
const assert = require('node:assert/strict');
const {main, trustedDirectory, snapshot} = require('../wazuh-tls/qualify.cjs');
const {auditClosure, installedPackages} = require('./audit.cjs');
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

let createdState = null;

async function qualify() {
  const args = process.argv.slice(2);
  assert.deepEqual(args.filter((_, i) => i % 2 === 0), ['--bundle', '--state-dir', '--platform-source']);
  const source = path.resolve(args[5]);
  const policy = JSON.parse(fs.readFileSync(path.join(__dirname, '../../deploy/wazuh/platform-client/source.lock.json')));
  assert.equal(process.version, policy.node_version, 'Pinned platform Node required');
  trustedDirectory(source, true);
  const buffers = {};
  for (const member of policy.members) {
    const bytes = snapshot(path.join(source, member.name), member.size);
    assert.equal(bytes.length, member.size, 'Platform source size mismatch');
    assert.equal(hash(bytes), member.sha256, 'Platform source identity mismatch');
    buffers[member.name] = bytes;
  }
  const expectedManifest = snapshot(path.join(__dirname, 'package.json'), 32768);
  assert.equal(hash(snapshot(path.join(source, 'package.json'), 32768)), hash(expectedManifest), 'Reviewed minimum manifest required');
  const toolchain = path.dirname(path.dirname(path.dirname(fs.realpathSync(require.resolve('axios/package.json')))));
  trustedDirectory(toolchain, true);
  const anchored = createRequire(path.join(toolchain,'package.json'));
  const moduleRoot = fs.realpathSync(path.join(toolchain,'node_modules')) + path.sep;
  const versions = {}, dependencyPaths = {};
  for (const [name, expected] of Object.entries(policy.compiler_versions)) {
    const packageFile = fs.realpathSync(anchored.resolve(name + '/package.json'));
    const entry = fs.realpathSync(anchored.resolve(name));
    assert(packageFile.startsWith(moduleRoot) && entry.startsWith(moduleRoot), 'Dependency outside audited toolchain');
    const bytes = snapshot(packageFile, 1048576);
    const actual = JSON.parse(bytes);
    assert.equal(actual.version, expected, 'Platform dependency version mismatch: ' + name);
    versions[name] = actual.version;
    dependencyPaths[name] = {entry:path.relative(toolchain,entry), package_json:path.relative(toolchain,packageFile), package_json_sha256:hash(bytes)};
  }
  const inventory = installedPackages(toolchain);
  const installedLock = snapshot(path.join(toolchain, 'yarn.lock'), 1048576);
  assert.equal(hash(installedLock), hash(buffers['yarn.lock']), 'Original root lock changed during install');
  const audit = auditClosure(buffers['yarn.lock'], JSON.parse(buffers['platform-package.json']), JSON.parse(expectedManifest),
    JSON.parse(snapshot(path.join(toolchain, 'node_modules/.yarn-integrity'), 1048576)), inventory);
  const babel = require(anchored.resolve('@babel/core'));
  assert.equal(babel.version, policy.compiler_versions['@babel/core']);
  await main({
    nodeVersion: policy.node_version, axiosVersion: policy.compiler_versions.axios,
    compilerName: 'upstream-osd-babel-node-preset', compilerVersion: babel.version,
    axiosEntry: fs.realpathSync(anchored.resolve('axios')),
    argv: args.slice(0,4),
    async createCompiler(state) {
      createdState = state;
      // Controlled private link makes emitted modules and presets resolve only this audited tree.
      fs.symlinkSync(path.join(toolchain,'node_modules'), path.join(state,'node_modules'), 'dir');
      const presets = path.join(state, 'verified-presets');
      fs.mkdirSync(presets, {mode: 0o700});
      for (const name of ['node_preset.js', 'common_preset.js', 'LICENSE.txt', 'NOTICE.txt'])
        fs.writeFileSync(path.join(presets, name), buffers[name], {mode: 0o600});
      const preset = path.join(presets, 'node_preset.js');
      const options = {babelrc: false, configFile: false, sourceMaps: 'inline', presets: [preset]};
      return {metadata: {
        node_executable_sha256: hash(snapshot(process.execPath, 134217728)),
        platform_revision: policy.revision, selected_dependencies: versions, selected_dependency_paths: dependencyPaths, closure_audit: audit,
        platform_source_sha256: Object.fromEntries(policy.members.map(m => [m.name, m.sha256])),
        platform_policy_sha256: hash(fs.readFileSync(path.join(__dirname, '../../deploy/wazuh/platform-client/source.lock.json'))),
        wrapper_sha256: hash(fs.readFileSync(__filename)), audit_sha256: hash(fs.readFileSync(path.join(__dirname,'audit.cjs'))),
        minimum_manifest_sha256: hash(expectedManifest),
        bootstrap_lock_sha256: hash(snapshot(path.join(__dirname, 'yarn/package-lock.json'), 32768)),
        compiler_options: {babelrc: false, configFile: false, sourceMaps: 'inline', preset: 'verified upstream node_preset.js', preset_target_node: 14},
        minimum_toolchain_only: true, deployed_resolution_verified: false,
        node_global_environment_proxy_supported: false,
      }, async compile(bytes, filename) {
        const result = await babel.transformAsync(bytes.toString('utf8'), {...options, filename});
        assert(result && typeof result.code === 'string', 'Babel emission unavailable');
        return result.code;
      }};
    },
  });
}

module.exports = {qualify};

if (require.main === module) qualify().catch(error => {
  // Setup/compiler failures are distinct from the asserted TLS refusal scenarios.
  const args = process.argv.slice(2), index = args.indexOf('--state-dir');
  if (index >= 0 && createdState) {
    try {
      const state = path.resolve(args[index + 1]);
      assert.equal(state, createdState); trustedDirectory(state, true);
      assert(!fs.existsSync(path.join(state, 'report.json')), 'Native failure already recorded');
      fs.writeFileSync(path.join(state, 'setup-failure.json'), JSON.stringify({passed: false, phase: 'setup-or-compiler', diagnostic: String(error.message).slice(0,8192)}) + '\n', {mode: 0o600, flag: 'wx'});
    } catch {}
  }
  process.stderr.write('RF-07C2 qualification failed; setup/compiler failure is not TLS refusal evidence.\n');
  process.exitCode = 1;
});
