import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,rmSync,symlinkSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {completeRuntimeInventory} from '../scripts/frontend_build.mjs';

function fixture(callback) {
  const root=mkdtempSync(join(tmpdir(),'xssi-final-web-'));
  try {
    const distribution=join(root,'runtime');mkdirSync(distribution);
    writeFileSync(join(distribution,'main.js'),'compiled fixture');
    writeFileSync(join(distribution,'style.css'),'copied authored asset');
    const metadata=join(root,'receipt.json');
    const modules=[{path:'source.js',sha256:'a'.repeat(64),files:['main.js'],imports:[]}];
    writeFileSync(metadata,JSON.stringify({format_version:1,distribution:'dist',modules,outputs:[]}));
    callback({root,distribution,metadata,modules});
  } finally {rmSync(root,{recursive:true,force:true});}
}

test('final distribution includes copied assets and retains rendered module evidence',()=>fixture(options=>{
  completeRuntimeInventory(options);
  const receipt=JSON.parse(readFileSync(options.metadata));
  assert.deepEqual(receipt.modules,options.modules);
  assert.equal(receipt.distribution,'runtime');
  assert.deepEqual(receipt.outputs.map(item=>item.path),['main.js','style.css']);
}));

test('lost rendered code and linked assets leave the original receipt unchanged',()=>fixture(options=>{
  const original=readFileSync(options.metadata);
  rmSync(join(options.distribution,'main.js'));
  assert.throws(()=>completeRuntimeInventory(options),/lost a rendered/);
  assert.deepEqual(readFileSync(options.metadata),original);
  writeFileSync(join(options.distribution,'main.js'),'compiled fixture');
  symlinkSync('main.js',join(options.distribution,'linked.js'));
  assert.throws(()=>completeRuntimeInventory(options),/uncontrolled/);
  assert.deepEqual(readFileSync(options.metadata),original);
}));

test('completion cannot rewrite an external target through a linked receipt',()=>fixture(options=>{
  const other=join(options.root,'other.json');
  const original=readFileSync(options.metadata);writeFileSync(other,original);
  rmSync(options.metadata);symlinkSync(other,options.metadata);
  assert.throws(()=>completeRuntimeInventory(options));
  assert.deepEqual(readFileSync(other),original);
}));
