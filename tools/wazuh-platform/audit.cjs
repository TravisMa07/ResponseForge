'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {createRequire} = require('node:module');
const {snapshot, trustedDirectory} = require('../wazuh-tls/qualify.cjs');
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

function verifiedParser() {
  const packageFile = fs.realpathSync(require.resolve('@yarnpkg/lockfile/package.json'));
  const root = path.dirname(path.dirname(path.dirname(path.dirname(packageFile))));
  trustedDirectory(root, true);
  const anchored = createRequire(path.join(root, 'package.json'));
  const entry = fs.realpathSync(anchored.resolve('@yarnpkg/lockfile'));
  assert(entry.startsWith(fs.realpathSync(path.join(root,'node_modules')) + path.sep), 'Parser outside bootstrap tree');
  for (const name of ['package.json','package-lock.json'])
    assert.equal(hash(snapshot(path.join(root,name),32768)), hash(snapshot(path.join(__dirname,'yarn',name),32768)), 'Actual bootstrap metadata differs from reviewed lock');
  const packageBytes = snapshot(packageFile,32768);
  const metadata = JSON.parse(packageBytes);
  assert.equal(metadata.name, '@yarnpkg/lockfile');
  assert.equal(metadata.version, '1.1.0');
  const original = JSON.parse(snapshot(path.join(__dirname,'yarn/package-lock.json'),32768));
  const installed = JSON.parse(snapshot(path.join(root,'node_modules/.package-lock.json'),32768));
  const expected = original.packages['node_modules/@yarnpkg/lockfile'];
  const actual = installed.packages['node_modules/@yarnpkg/lockfile'];
  for (const key of ['version','resolved','integrity']) assert.equal(actual[key], expected[key], 'Installed parser artifact differs');
  const identity = {version:metadata.version, entry:path.relative(root,entry),
    entry_sha256:hash(snapshot(entry,2097152)), package_json_sha256:hash(packageBytes),
    actual_bootstrap_lock_sha256:hash(snapshot(path.join(root,'package-lock.json'),32768))};
  return {parser:require(entry), identity};
}

function auditClosure(rootLock, original, minimum, integrity, installed) {
  const verified = verifiedParser();
  const parsed = verified.parser.parse(rootLock.toString('utf8'));
  assert(installed.length > 0, 'Missing installed dependency inventory');
  assert.equal(parsed.type, 'success', 'Original Yarn lock must parse completely');
  assert.deepEqual(integrity.linkedModules, [], 'Linked dependency modules refused');
  assert(integrity.flags.includes('ignoreScripts'), 'Lifecycle scripts must have been disabled');
  assert.deepEqual([...integrity.topLevelPatterns].sort(), Object.entries(minimum.dependencies).map(([n,r])=>n+'@'+r).sort());
  const entries = Object.entries(integrity.lockfileEntries);
  assert(entries.length > 0, 'Missing actual closure');
  const permitted = new Set();
  for (const [selector, resolved] of entries) {
    const entry = parsed.object[selector];
    assert(entry && entry.resolved === resolved && typeof entry.integrity === 'string' && /^sha(?:1|512)-[A-Za-z0-9+/]+=*$/.test(entry.integrity), 'Unreviewed closure selector/artifact: ' + selector);
    permitted.add(selector.slice(0, selector.lastIndexOf('@')) + '@' + entry.version);
  }
  for (const item of installed) assert(permitted.has(item.name+'@'+item.version), 'Installed package outside reviewed closure');
  for (const [pattern, version] of Object.entries(minimum.resolutions))
    assert.equal(original.resolutions[pattern], version, 'Changed root resolution');
  for (const [pattern, version] of Object.entries(original.resolutions)) {
    assert(pattern.startsWith('**/'), 'Unsupported original resolution shape');
    const remainder = pattern.slice(3);
    const pieces = remainder.split('/');
    const name = remainder.startsWith('@') ? pieces.slice(0,2).join('/') : pieces[0];
    // Conservatively retain nested rules whenever their parent package is present.
    if (installed.some(item=>item.name === name)) assert.equal(minimum.resolutions[pattern], version, 'Omitted applicable root resolution: ' + pattern);
  }
  return {selectors: entries.length, installed_packages: installed.length, parser:verified.identity,
    integrity_algorithms: Object.fromEntries(['sha1','sha512'].map(algorithm=>[algorithm, entries.filter(([selector])=>parsed.object[selector].integrity.startsWith(algorithm+'-')).length])),
    closure_sha256: hash(Buffer.from(JSON.stringify(entries.sort(([a],[b])=>a.localeCompare(b))))),
    installed_metadata_sha256: hash(Buffer.from(JSON.stringify(installed.sort((a,b)=>a.relative.localeCompare(b.relative))))),
    original_lock_selectors_and_artifacts_verified: true, applicable_root_resolutions_verified: true};
}

function installedPackages(root) {
  trustedDirectory(root, true);
  const result = [];
  function visit(modules) {
    trustedDirectory(modules);
    for (const name of fs.readdirSync(modules).sort()) {
      if (name.startsWith('.')) continue;
      const candidate = path.join(modules,name);
      const info = fs.lstatSync(candidate);
      assert(info.isDirectory() && !info.isSymbolicLink(), 'Linked package directory refused');
      if (name.startsWith('@')) {
        for (const leaf of fs.readdirSync(candidate).sort()) read(path.join(candidate,leaf));
      } else read(candidate);
    }
  }
  function read(dir) {
    trustedDirectory(dir);
    const bytes = snapshot(path.join(dir,'package.json'), 1048576);
    const value = JSON.parse(bytes);
    assert(typeof value.name === 'string' && typeof value.version === 'string');
    result.push({name:value.name, version:value.version, relative:path.relative(root,dir), package_json_sha256:hash(bytes)});
    if (fs.existsSync(path.join(dir,'node_modules'))) visit(path.join(dir,'node_modules'));
  }
  visit(path.join(root,'node_modules'));
  return result;
}

module.exports = {auditClosure, installedPackages};
