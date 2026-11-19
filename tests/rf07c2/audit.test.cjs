'use strict';
// Original synthetic Yarn metadata vectors, not vendor artifact/build evidence.
const assert = require('node:assert/strict');
const {auditClosure} = require('../../tools/wazuh-platform/audit.cjs');
const original = {resolutions: {'**/foo': '^1.0.0'}};
const minimum = {dependencies: {foo: '^1.0.0'}, resolutions: {'**/foo': '^1.0.0'}};
const url = 'https://registry.yarnpkg.com/foo/-/foo-1.0.0.tgz#original';
const lock = Buffer.from(`foo@^1.0.0:\n  version "1.0.0"\n  resolved "${url}"\n  integrity sha512-b3JpZ2luYWw=\n`);
const integrity = {linkedModules: [], flags: ['ignoreScripts'], topLevelPatterns: ['foo@^1.0.0'], lockfileEntries: {'foo@^1.0.0': url}};
const installed = [{name: 'foo', version: '1.0.0', relative: 'node_modules/foo', package_json_sha256: 'synthetic'}];
assert.equal(auditClosure(lock, original, minimum, integrity, installed).selectors, 1);
for (const [name, mutate] of [
  ['changed resolved URL', x=>{x.integrity.lockfileEntries['foo@^1.0.0']='https://unexpected.invalid/archive';}],
  ['unknown selector', x=>{x.integrity.lockfileEntries['evil@1']='https://unexpected.invalid/archive';}],
  ['linked module', x=>{x.integrity.linkedModules=['outside'];}],
  ['scripts not disabled', x=>{x.integrity.flags=[];}],
  ['different direct dependency', x=>{x.integrity.topLevelPatterns=['other@1'];}],
  ['missing resolution', x=>{x.minimum.resolutions={};}],
  ['changed resolution', x=>{x.minimum.resolutions['**/foo']='^2';}],
  ['unreviewed package version', x=>{x.installed[0].version='2.0.0';}],
  ['missing lock integrity', x=>{x.lock=Buffer.from(`foo@^1.0.0:\n  version "1.0.0"\n  resolved "${url}"\n`);}],
  ['missing installed inventory', x=>{x.installed=[];}],
  ['missing selected closure', x=>{x.integrity.lockfileEntries={};}],
]) {
  const vector={lock, original:structuredClone(original), minimum:structuredClone(minimum), integrity:structuredClone(integrity), installed:structuredClone(installed)};
  mutate(vector);
  assert.throws(()=>auditClosure(vector.lock,vector.original,vector.minimum,vector.integrity,vector.installed), undefined, name);
}
console.log('PASS: 12 original synthetic dependency-audit vectors');
