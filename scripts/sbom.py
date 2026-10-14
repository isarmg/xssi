"""Generate and validate the actual locked server/helper dependency inventories."""
import json
import os
from pathlib import Path
import re
import queue
import signal
import stat
import subprocess
import sys
import threading
import time
import tomllib
import package
from release_manifest import bounded
from sbom_normalization import normalize, selected_metadata
from cargo_selection import tree_command, selection_from_tree

TARGET='x86_64-unknown-linux-gnu'
ROOT=Path(__file__).resolve().parents[1]


def run(command,cwd,environment,maximum=32*1024*1024,timeout=1800):
    return _run(command,cwd,environment,maximum,timeout)


def run_to_file(command,cwd,environment,destination,maximum=2*1024*1024*1024,timeout=600):
    """Stream a bounded child output into one exclusively created physical file."""
    return _run(command,cwd,environment,maximum,timeout,Path(destination))


def _run(command,cwd,environment,maximum,timeout,destination=None):
    if type(maximum)is not int or maximum<0 or type(timeout)not in (int,float) or not 0<timeout<=1800:
        raise ValueError('dependency tool bounds are invalid')
    job=None
    options={'start_new_session':True}
    if os.name=='nt':
        from windows_job import DependencyJob
        job=DependencyJob()
        options={'creationflags':subprocess.CREATE_NEW_PROCESS_GROUP|0x00000004}  # CREATE_SUSPENDED
    child=None
    stopped=threading.Event()
    chunks=queue.Queue(maxsize=8)
    reader=None
    result=bytearray();deadline=time.monotonic()+timeout
    total=0;output=None;created=None;complete=False

    def send(value):
        while not stopped.is_set():
            try:
                chunks.put(value,timeout=.05)
                return
            except queue.Full:
                continue

    def read_output():
        try:
            while not stopped.is_set():
                value=child.stdout.read(16384)
                if not value:break
                send(('data',value))
            send(('eof',None))
        except OSError:
            send(('error',None))

    try:
        if destination is not None:
            from release_sbom import physical_directory
            destination=destination.absolute()
            physical_directory(destination.parent)
            output=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_BINARY',0),0o600)
            created=os.fstat(output)
        child=subprocess.Popen(command,cwd=cwd,env=environment,stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE,bufsize=0,**options)
        if job is not None:job.assign_and_resume(child.pid)
        reader=threading.Thread(target=read_output,name='xssi-dependency-output',daemon=True)
        reader.start()
        while True:
            remaining=deadline-time.monotonic()
            if remaining<=0:raise TimeoutError('dependency tool exceeded its time bound')
            try:
                kind,value=chunks.get(timeout=min(.1,remaining))
            except queue.Empty:
                continue
            if kind=='eof':break
            if kind=='error':raise ValueError('dependency tool output could not be read')
            if total+len(value)>maximum:raise ValueError('dependency tool output exceeds its bound')
            total+=len(value)
            if output is None:result.extend(value)
            else:
                view=memoryview(value)
                while view:
                    written=os.write(output,view)
                    if written<=0:raise OSError('dependency output write did not progress')
                    view=view[written:]
        try:
            status=child.wait(timeout=max(.001,deadline-time.monotonic()))
        except subprocess.TimeoutExpired:
            raise TimeoutError('dependency tool exceeded its time bound') from None
        if status:
            captured=bytes(result) if destination is None else None
            # Audit details arrive on stdout. Keep bounded output for callers, but
            # only print public advisory identifiers, never arbitrary tool output.
            advisories=sorted(set(re.findall(rb'\bRUSTSEC-[0-9]{4}-[0-9]{4}\b',result)))
            if advisories:
                identifiers=', '.join(value.decode('ascii') for value in advisories[:64])
                suffix=' (additional IDs omitted)' if len(advisories)>64 else ''
                print(f'dependency tool failed (status {status}); RustSec advisories: {identifiers}{suffix}',file=sys.stderr)
            raise subprocess.CalledProcessError(status,command,output=captured)
        if output is not None:
            os.fsync(output)
            current=os.fstat(output);named=destination.lstat()
            if not stat.S_ISREG(named.st_mode) or getattr(named,'st_file_attributes',0)&0x400 or current.st_nlink!=1 or current.st_size!=total or (created.st_dev,created.st_ino)!=(current.st_dev,current.st_ino) or (current.st_dev,current.st_ino)!=(named.st_dev,named.st_ino):
                raise ValueError('dependency output no longer names its created file')
        complete=True
        return bytes(result) if destination is None else total
    finally:
        stopped.set()
        try:
            if job is not None:
                job.close()
            elif child is not None:
                try:os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass
        finally:
            try:
                if child is not None:
                    if child.poll() is None:child.kill()
                    child.wait()
                    if reader is not None:
                        reader.join(timeout=5)
                    child.stdout.close()
                    if reader is not None and reader.is_alive():
                        raise RuntimeError('dependency output reader did not stop after child-tree cleanup')
            finally:
                if output is not None:
                    os.close(output)
                    if not complete:
                        from release_sbom import physical_directory
                        physical_directory(destination.parent)
                        try:named=destination.lstat()
                        except FileNotFoundError:pass
                        else:
                            if not stat.S_ISREG(named.st_mode) or (named.st_dev,named.st_ino)!=(created.st_dev,created.st_ino):
                                raise RuntimeError('failed dependency output was replaced; preserve the unknown file')
                            destination.unlink()


def tools(environment):
    for command,version in [('cyclonedx','0.5.9'),('audit','0.22.2')]:
        actual=run(['cargo',command,'--version'],ROOT,environment,4096).decode().strip().split()
        if not actual or actual[-1]!=version:raise ValueError('release dependency tool version differs from the pinned gate')


def vendor(source,environment):
    directory=source/'xssi-vendor';directory.mkdir(mode=0o700)
    command=['cargo','vendor','--locked','--versioned-dirs','--manifest-path',str(source/'Cargo.toml'),str(directory)]
    configuration=run(command,source,environment)
    if not configuration.strip():raise ValueError('Cargo vendor did not produce a source replacement')
    controls=source/'.cargo';controls.mkdir(exist_ok=True)
    (controls/'config.toml').write_bytes(configuration)
    return directory


def inventory(source,manifest,root_name,features,environment,stage,label,local_sources,
              *,target=TARGET,default_features=True,all_features=False):
    if not re.fullmatch(r'[a-zA-Z0-9_-]+',label) or not re.fullmatch(r'[a-zA-Z0-9_.-]+',target):
        raise ValueError('invalid inventory label or target')
    lock=bounded(source/'Cargo.lock',8*1024*1024)
    options=[] if default_features else ['--no-default-features']
    if all_features:options.append('--all-features')
    elif features:options.extend(['--features',features if isinstance(features,str) else ','.join(features)])
    metadata=package.loads(run(['cargo','metadata','--frozen','--format-version','1','--manifest-path',str(manifest),'--filter-platform',target,*options],source,environment))
    tree=run(tree_command(manifest,root_name,target,features or (),default_features=default_features,
                          all_features=all_features),source,environment).decode('utf-8')
    selection=selection_from_tree(metadata,tree,root_name)
    (source/'xssi-cargo-full-metadata.json').write_text(json.dumps(metadata),encoding='utf-8')
    (source/'xssi-cargo-selection.json').write_text(json.dumps(selection),encoding='utf-8')
    (source/'xssi-cargo-tree.txt').write_text(tree,encoding='utf-8')
    metadata=selected_metadata(metadata,selection)
    run(['cargo','cyclonedx','--manifest-path',str(manifest),'--format','json','--spec-version','1.5','--override-filename','xssi-release.cdx','--all','--target',target,*options,'--quiet'],source,environment)
    if bounded(source/'Cargo.lock',8*1024*1024)!=lock:raise ValueError('SBOM tool changed the locked dependency graph')
    raw=package.loads(bounded(manifest.parent/'xssi-release.cdx.json',8*1024*1024))
    revisions={}
    for item in metadata['packages']:
        if item['source'] is None:
            path=Path(item['manifest_path']).resolve()
            matches=[revision for prefix,revision in local_sources if path.is_relative_to(prefix.resolve())]
            if len(matches)!=1 or not re.fullmatch(r'[0-9a-f]{40}',matches[0]):raise ValueError('unbound local package in the resolved release graph')
            revisions[item['id']]=matches[0]
    bom=normalize(raw,metadata,root_name,revisions,[str(prefix) for prefix,_ in local_sources])
    destination=stage/'share'/f'{label}-sbom.cdx.json'
    destination.write_text(json.dumps(bom,sort_keys=True,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    metadata_path=source/'xssi-cargo-metadata.json';metadata_path.write_text(json.dumps(metadata),encoding='utf-8')
    lock_packages=tomllib.loads(lock.decode('utf-8'))['package'];checksums=[]
    for item in metadata['packages']:
        if item['source'] is None:continue
        matches=[record for record in lock_packages if (record['name'],record['version'],record.get('source'))
                 ==(item['name'],item['version'],item['source'])]
        if len(matches)!=1:raise ValueError('selected dependency has no unique immutable Cargo lock source')
        checksums.append({key:item[key] for key in ('id','name','version','source')}|
                         {'checksum':matches[0].get('checksum')})
    (source/'xssi-cargo-source-checksums.json').write_text(json.dumps({'format_version':1,'packages':checksums}),encoding='utf-8')
    from upstream_licenses import prepare
    prepare(source,metadata,set(selection['ids']),environment)
    notices=stage/'share'/f'THIRD_PARTY_{label.upper()}_LICENSES.txt'
    run(['node',str(ROOT/'scripts/generate-third-party-notices.mjs'),str(metadata_path),str(source/'xssi-vendor'),str(source),str(notices),root_name,str(destination)],source,environment)
    if not bounded(notices,16*1024*1024).strip():raise ValueError('release dependency notices are empty')
    destination.chmod(0o644);notices.chmod(0o644)
    return destination


def produce_runtime_cargo_bom(source,manifest,root_name,stage,label,local_sources,
                              *,target,features=(),default_features=True,environment=None):
    """Inventory an exported release source workspace; never alter a checkout.

    The caller supplies the exact target/features used for its actual build and
    local source revisions. Vendoring happens only in this private export.
    """
    source=Path(source).resolve(strict=True)
    if (source/'.git').exists():
        raise ValueError('runtime inventory requires a private exported build workspace')
    environment=dict(os.environ if environment is None else environment)
    tools(environment)
    if not (source/'xssi-vendor').is_dir():vendor(source,environment)
    environment['CARGO_NET_OFFLINE']='true'
    destination=inventory(source,Path(manifest),root_name,features,environment,Path(stage),
                          label,local_sources,target=target,default_features=default_features)
    run(['cargo','audit','--deny','yanked','--file',str(source/'Cargo.lock')],source,environment)
    return destination
