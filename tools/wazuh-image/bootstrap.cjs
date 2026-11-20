'use strict';
// Fixed Node -e loader. Stdin is one bounded JSON frame, never interpolated code.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const codeNames=['runner/wazuh-tls/qualify.cjs','runner/wazuh-image/qualify.cjs','deploy/wazuh/tls-client/source.lock.json','deploy/wazuh/packaged-client/source.lock.json','deploy/wazuh/image-qualification/source.lock.json'];
const sourceNames=['bundle/upstream-server-api-client.ts','bundle/server-api-client.ts','bundle/cookie.ts','bundle/LICENSE','original/server-api-client.js'];
const materials=['trusted.pem','other.pem','good.pem','good.key','untrusted.pem','untrusted.key','wrongname.pem','wrongname.key'].map(n=>'materials/'+n);
const allowed=new Set([...codeNames,...sourceNames,...materials]);
let chunks=[],total=0,started=false;
function failure() {process.stdout.write(JSON.stringify({schema_version:'1.0',passed:false,phase:'setup-or-image-fixture'})+'\n');process.exitCode=1;process.stdin.destroy();}
async function launch(raw) {
  const input=JSON.parse(raw.toString('utf8'));
  if(input.schema_version!=='1.0'||!input.files||Object.keys(input.files).length!==allowed.size||!input.session)throw new Error('Invalid input');
  const root=fs.mkdtempSync('/tmp/rf07c4-');let decoded=0;
  for(const [name,encoded] of Object.entries(input.files)) {
    if(!allowed.has(name)||typeof encoded!=='string'||encoded.length>1048576)throw new Error('Unknown/large input');
    const bytes=Buffer.from(encoded,'base64');decoded+=bytes.length;
    if(bytes.toString('base64')!==encoded||decoded>1048576)throw new Error('Invalid input encoding');
    const destination=path.join(root,name);fs.mkdirSync(path.dirname(destination),{recursive:true,mode:0o700});
    fs.writeFileSync(destination,bytes,{mode:0o600,flag:'wx'});
  }
  const digest=crypto.createHash('sha256').update(raw).digest('hex');
  await require(path.join(root,'runner/wazuh-image/qualify.cjs')).run(root,input.session,digest,input.material_generator);
  process.stdin.destroy();
}
process.stdin.on('data',chunk=>{
  if(started)return;
  total+=chunk.length;if(total>2097152){started=true;failure();return;}
  chunks.push(chunk);const joined=Buffer.concat(chunks),end=joined.indexOf(10);
  if(end>=0){started=true;process.stdin.pause();process.stdin.unref?.();
    if(end!==joined.length-1){failure();return;}
    launch(joined).catch(failure);
  }
});
process.stdin.on('end',()=>{if(!started){started=true;failure();}});
process.stdin.on('error',()=>{if(!started){started=true;failure();}});
