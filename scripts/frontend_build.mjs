// Record modules that the actual bundler rendered into the final Web outputs.
import {createHash} from 'node:crypto';
import {constants,openSync,closeSync,fstatSync,ftruncateSync,writeSync,fsyncSync,existsSync,readFileSync,realpathSync,writeFileSync,readdirSync,lstatSync} from 'node:fs';
import {dirname,isAbsolute,join,relative,sep} from 'node:path';
import {createRequire} from 'node:module';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const encodeReceipt = receipt => {
  const bytes=Buffer.from(JSON.stringify(receipt,null,2)+'\n');
  if (bytes.length>32*1024*1024) throw new Error('Rendered runtime inventory exceeds its byte bound');
  return bytes;
};

function distributionFiles(distribution) {
  const outputs=[];
  const walk = directory => {
    for (const item of readdirSync(directory,{withFileTypes:true})) {
      const path=join(directory,item.name);
      if (item.isDirectory()) walk(path);
      else {
        const metadata=lstatSync(path);
        if (!item.isFile() || metadata.nlink !== 1 || metadata.size>32*1024*1024 || outputs.length>=16384) throw new Error('Final Web output contains an uncontrolled object');
        outputs.push({path:relative(distribution,path).split(sep).join('/'),sha256:sha(readFileSync(path))});
      }
    }
  };
  if (!lstatSync(distribution).isDirectory()) throw new Error('Final Web distribution must be a physical directory');
  walk(distribution);
  return outputs.sort((a,b)=>a.path.localeCompare(b.path));
}

export function completeRuntimeInventory({metadata,root,distribution}) {
  if (![metadata,root,distribution].every(isAbsolute)) throw new Error('Runtime completion paths must be absolute');
  root=realpathSync(root);
  const path=relative(root,distribution).split(sep).join('/');
  if (!path || path.startsWith('../') || isAbsolute(path)) throw new Error('Final distribution is outside its source workspace');
  const named=lstatSync(metadata);
  const descriptor=openSync(metadata,constants.O_RDWR|(constants.O_NOFOLLOW??0)|(constants.O_NONBLOCK??0));
  try {
    const opened=fstatSync(descriptor);
    if (!opened.isFile() || opened.nlink!==1 || opened.size>32*1024*1024 || opened.dev!==named.dev || opened.ino!==named.ino) throw new Error('Rendered inventory must be a bounded physical file');
    const receipt=JSON.parse(readFileSync(descriptor,'utf8'));
    if (receipt.format_version!==1 || !Array.isArray(receipt.modules) || !receipt.modules.length) throw new Error('Actual rendered module evidence is unavailable');
    receipt.distribution=path;
    receipt.outputs=distributionFiles(distribution);
    const names=new Set(receipt.outputs.map(item=>item.path));
    if (receipt.modules.some(item=>!Array.isArray(item.files) || item.files.some(name=>!names.has(name)))) throw new Error('Final distribution lost a rendered code output');
    const bytes=encodeReceipt(receipt);
    const current=lstatSync(metadata);
    if (current.dev!==opened.dev || current.ino!==opened.ino || current.size!==opened.size || current.mtimeMs!==opened.mtimeMs || current.ctimeMs!==opened.ctimeMs) throw new Error('Rendered inventory changed during runtime completion');
    ftruncateSync(descriptor,0);
    for (let offset=0;offset<bytes.length;) offset+=writeSync(descriptor,bytes,offset,bytes.length-offset,offset);
    fsyncSync(descriptor);
  } finally {closeSync(descriptor);}
}

export function runtimeInventory({output,root}) {
  if (!isAbsolute(output) || !isAbsolute(root)) throw new Error('Runtime inventory paths must be absolute');
  root = realpathSync(root);
  let distribution;
  let receipt;
  return {
    name: 'xssi-runtime-inventory',
    apply: 'build',
    configResolved(config) { distribution = isAbsolute(config.build.outDir) ? config.build.outDir : join(config.root,config.build.outDir); },
    async generateBundle(_options,bundle) {
      const rendered = new Map();
      const outputs = [];
      for (const item of Object.values(bundle)) {
        const bytes = item.type === 'chunk' ? Buffer.from(item.code) : Buffer.from(item.source);
        outputs.push({path:item.fileName,sha256:sha(bytes)});
        if (item.type !== 'chunk') continue;
        for (const [id,information] of Object.entries(item.modules)) {
          if (!information.renderedLength) continue;
          if (!rendered.has(id)) rendered.set(id,{files:[],code:new Set()});
          const record=rendered.get(id);
          record.files.push(item.fileName);
          if (typeof information.code === 'string' && information.code) record.code.add(information.code);
        }
      }
      const modules = [];
      for (const [id,record] of rendered) {
        const files=record.files;
        const info = this.getModuleInfo(id);
        if (!info) {
          const require = createRequire(join(root,'package.json'));
          const providerEntry = require.resolve('rolldown');
          const provider = await import(providerEntry);
          if (id !== provider.RUNTIME_MODULE_ID || !record.code.size) {
            throw new Error('Rendered module has no supported actual bundler provider: '+JSON.stringify(id));
          }
          const code=[...record.code].join('\n');
          modules.push({id,path:null,code,sha256:sha(Buffer.from(code)),files:files.sort(),imports:[],
            generated_runtime:{provider:'rolldown',version:provider.VERSION,module:id}});
          continue;
        }
        const clean = id.split('?')[0];
        if (!clean.startsWith('\0') && isAbsolute(clean) && existsSync(clean)) {
          const physical = realpathSync(clean);
          const path = relative(root,physical).split(sep).join('/');
          if (path.startsWith('../') || isAbsolute(path)) throw new Error('Rendered module is outside the exact build workspace');
          modules.push({id,path,sha256:sha(readFileSync(physical)),files:files.sort(),
            imports:[...info.importedIds,...info.dynamicallyImportedIds].filter(child=>rendered.has(child)).sort()});
        } else {
          // The actual generated helper code is build-input evidence. Its
          // provider must be explicitly declared by the caller, never inferred
          // from all development dependencies in a lockfile.
          if (typeof info.code !== 'string' || !info.code) throw new Error('Rendered virtual helper has no captured implementation');
          modules.push({id,path:null,sha256:sha(Buffer.from(info.code)),code:info.code,
            files:files.sort(),imports:[...info.importedIds,...info.dynamicallyImportedIds].filter(child=>rendered.has(child)).sort()});
        }
      }
      // Local absolute IDs are converted to numeric references before the
      // receipt leaves this build process.
      modules.sort((a,b)=>a.id.localeCompare(b.id));
      const ids = new Map(modules.map((item,index)=>[item.id,index]));
      for (const item of modules) {
        item.imports = item.imports.map(id=>ids.get(id));
        if (item.path === null) item.virtual_id = item.id;
        delete item.id;
      }
      receipt = {format_version:1,distribution:relative(root,distribution).split(sep).join('/'),
        modules,outputs:outputs.sort((a,b)=>a.path.localeCompare(b.path))};
    },
    writeBundle() {
      if (!receipt) throw new Error('Actual rendered runtime inventory is unavailable');
      receipt.outputs=distributionFiles(distribution);
      if (!existsSync(dirname(output))) throw new Error('Explicit inventory destination does not exist');
      writeFileSync(output,encodeReceipt(receipt),{flag:'wx',mode:0o600});
    },
  };
}
