#!/usr/bin/env python3
"""Build a standalone tool delivery from this exact clean source revision."""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile
import tempfile
import tomllib

sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import release_manifest
import release_sbom
import sbom
import sqlite_receipt

ROOT=Path(__file__).resolve().parents[1]
TARGET='x86_64-unknown-linux-gnu'
RUNTIME_MODULES=('package.py','material_store.py','writer_control.py','unit_validation.py',
                 'install.py','upgrade.py','maintenance.py','release_manifest.py','release_sbom.py')


def environment():
    result={key:value for key,value in os.environ.items()
            if not any(part in key.upper() for part in ('TOKEN','PASSWORD','SECRET','SIGNING','PRIVATE_KEY'))}
    for key in ('SQLITE3_LIB_DIR','SQLITE3_INCLUDE_DIR','LIBSQLITE3_SYS_USE_PKG_CONFIG',
                'SQLCIPHER_LIB_DIR','SQLCIPHER_INCLUDE_DIR','RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS'):
        result.pop(key,None)
    result['TZ']='UTC'
    return result


def git(*arguments):
    return sbom.run(['git','-C',str(ROOT),*arguments],ROOT,environment(),maximum=4*1024*1024,timeout=120).decode().strip()


def source_identity(revision,version):
    release_manifest.identity('xssi',version,revision,TARGET)
    if git('rev-parse','HEAD')!=revision or git('status','--porcelain','--untracked-files=all'):
        raise ValueError('tool release requires the exact clean source revision')
    if git('rev-parse','refs/tags/v'+version+'^{commit}')!=revision:
        raise ValueError('tool release tag differs from its source revision')
    actual=tomllib.loads(release_manifest.bounded(ROOT/'Cargo.toml',1024*1024).decode())
    if actual['package']['name']!='xssi' or actual['package']['version']!=version:
        raise ValueError('tool release version differs from the source package')


def export_source(revision,source,archive):
    source.mkdir(mode=0o700)
    git('archive','--format=tar','--output',str(archive),revision)
    count=0;total=0
    with tarfile.open(archive) as contents:
        for item in contents:
            count+=1;total+=item.size
            name=PurePosixPath(item.name)
            if count>200000 or total>release_sbom.MAX_BYTES or item.size<0 or name.is_absolute() or '..' in name.parts or not(item.isfile() or item.isdir()):
                raise ValueError('tool source export contains uncontrolled paths or exceeds its bound')
            contents.extract(item,source,filter='data')
    archive.unlink()


def copy(source,destination,mode):
    raw=release_manifest.bounded(source,release_sbom.MAX_BYTES)
    destination.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
    descriptor=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(descriptor,'wb') as out:
        out.write(raw);out.flush();os.fsync(out.fileno());os.fchmod(out.fileno(),mode)


def copy_compiler_artifact(messages,source,target,destination,version,package_id):
    """Seal one freshly compiled intermediate before treating it as delivery."""
    source=release_sbom.physical_directory(source)
    target=release_sbom.physical_directory(target)
    package=tomllib.loads(release_manifest.bounded(source/'Cargo.toml',1024*1024).decode('utf-8'))['package']
    if package.get('name')!='xssi' or package.get('version')!=version:
        raise ValueError('compiler source package version differs')
    information=target.lstat()
    if information.st_uid!=os.geteuid() or stat.S_IMODE(information.st_mode)!=0o700:
        raise ValueError('compiler output target is not its producer-owned private directory')
    expected=target/TARGET/'release/setup'
    artifacts=[];finished=False
    for line in messages.decode('utf-8').splitlines():
        if len(line)>1024*1024:raise ValueError('compiler artifact message exceeds its bound')
        value=json.loads(line)
        if value.get('reason')=='build-finished':
            if finished or value.get('success') is not True:raise ValueError('compiler build completion differs')
            finished=True
        if value.get('reason')=='compiler-artifact' and value.get('executable') is not None:
            artifacts.append(value)
    if not finished or len(artifacts)!=1:raise ValueError('compiler did not report exactly one actual helper artifact')
    artifact=artifacts[0];profile=artifact.get('profile',{});binary=artifact.get('target',{})
    if (not isinstance(package_id,str) or not package_id.startswith('path+'+source.as_uri()+'#')
            or artifact.get('package_id')!=package_id
            or Path(artifact.get('manifest_path',''))!=source/'Cargo.toml'
            or binary.get('name')!='setup' or binary.get('kind')!=['bin']
            or binary.get('crate_types')!=['bin'] or Path(binary.get('src_path',''))!=source/'src/main.rs'
            or profile.get('test') is not False or profile.get('debug_assertions') is not False
            or profile.get('opt_level')!='3' or artifact.get('fresh') is not False
            or artifact.get('executable')!=str(expected) or artifact.get('filenames')!=[str(expected)]):
        raise ValueError('compiler helper identity, profile, target or fresh source differs')
    release_sbom.physical_directory(expected.parent)
    named=expected.lstat()
    descriptor=os.open(expected,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    output=None;created=None;complete=False
    try:
        before=os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=os.geteuid()
                or not before.st_mode&0o111 or before.st_mode&0o022 or before.st_nlink not in (1,2)
                or before.st_size>release_sbom.MAX_BYTES
                or release_sbom.identity(before)!=release_sbom.identity(named)):
            raise ValueError('fresh compiler artifact is not a bounded controlled regular binary')
        destination=Path(destination);destination.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
        release_sbom.physical_directory(destination.parent)
        output=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o755)
        created=os.fstat(output);total=0
        while chunk:=os.read(descriptor,min(65536,release_sbom.MAX_BYTES+1-total)):
            total+=len(chunk)
            if total>release_sbom.MAX_BYTES:raise ValueError('compiler artifact exceeds its byte bound')
            remaining=memoryview(chunk)
            while remaining:
                written=os.write(output,remaining)
                if written<=0:raise OSError('compiler artifact copy did not progress')
                remaining=remaining[written:]
        if (total!=before.st_size or release_sbom.identity(before)!=release_sbom.identity(os.fstat(descriptor))
                or release_sbom.identity(named)!=release_sbom.identity(expected.lstat())):
            raise ValueError('compiler artifact changed while being sealed')
        release_sbom.physical_directory(expected.parent)
        os.fchmod(output,0o755);os.fsync(output)
        if os.fstat(output).st_nlink!=1:raise ValueError('sealed compiler artifact has more than one link')
        release_sbom.digest(destination)
        complete=True
        return {'package':'xssi','version':version,'bin':'setup','profile':'release','target':TARGET,'fresh':False}
    finally:
        os.close(descriptor)
        if output is not None:
            os.close(output)
            if not complete:
                named_destination=destination.lstat()
                if (named_destination.st_dev,named_destination.st_ino)!=(created.st_dev,created.st_ino):
                    raise RuntimeError('failed compiler output was replaced; preserve it')
                destination.unlink()


def stage(output,revision,version):
    source_identity(revision,version)
    output=Path(output).absolute()
    release_sbom.physical_directory(output.parent)
    output.mkdir(mode=0o755)
    (output/'share').mkdir(mode=0o755)
    env=environment()
    for command,expected in [(['rustc','--version'],'rustc 1.99.0'),(['node','--version'],'v26.7.0')]:
        actual=sbom.run(command,ROOT,env,maximum=4096,timeout=120).decode().strip()
        if not(actual==expected or actual.startswith(expected+' ')):
            raise ValueError('tool release build toolchain differs from its pinned identity')
    with tempfile.TemporaryDirectory(prefix='xssi-release-source-') as temporary:
        private=Path(temporary).resolve(strict=True);source=private/'source'
        export_source(revision,source,private/'source.tar')
        graph=sbom.produce_runtime_cargo_bom(source,source/'Cargo.toml','xssi',output,'xssi',
            [(source,revision)],target=TARGET,environment=env)
        env['CARGO_NET_OFFLINE']='true'
        target=private/'target';target.mkdir(mode=0o700)
        env['CARGO_TARGET_DIR']=str(target)
        messages=sbom.run(['cargo','build','--frozen','--release','--target',TARGET,'--bin','setup','--message-format=json-render-diagnostics'],source,env,maximum=8*1024*1024,timeout=1800)
        package_id=release_sbom.load(source/'xssi-cargo-selection.json')['root']
        compiler=copy_compiler_artifact(messages,source,target,output/'libexec/setup',version,package_id)
        for name in ('install.sh','maintenance.sh','upgrade.sh'):copy(source/name,output/name,0o755)
        for name in RUNTIME_MODULES:copy(source/'scripts'/name,output/'libexec'/name,0o644)
        copy(source/'Cargo.lock',output/'share/Cargo.lock',0o644)
        copy(source/'README.md',output/'share/README.md',0o644)
        copy(source/'docs/releases'/(version+'.md'),output/'share/releases'/(version+'.md'),0o644)
        copy(source/'LICENSE-APACHE',output/'share/licenses/XSSI-LICENSE-APACHE',0o644)
        prerequisites={'format_version':1,'target':TARGET,'requires':['Linux x86_64 GNU','Python >=3.12','Bash','systemd'],
                       'conditional_requires':{'XCOS TLS configuration validation':['OpenSSL']}}
        (output/'share/runtime-prerequisites.json').write_text(json.dumps(prerequisites,sort_keys=True,indent=2)+'\n')
        (output/'share/runtime-prerequisites.json').chmod(0o644)
        external=output/'share/external-components.json'
        external.write_text(json.dumps({'format_version':1,'runtime_roots':[],'components':[]})+'\n');external.chmod(0o644)
        native=sqlite_receipt.record(source,output,'xssi','libexec/setup')
        sqlite_receipt.merge(output,[native],[(graph,'libexec/setup')])
        report=sbom.run([str(output/'libexec/setup'),'--version'],output,env,maximum=4096,timeout=10)
        if report!=('setup '+version+'\n').encode():raise ValueError('actual compiled helper reports another release version')
        provenance={'format_version':1,'product':'xssi','version':version,'source_revision':revision,'target':TARGET,
                    'toolchain':{'rust':'1.99.0','node':'26.7.0','cargo_cyclonedx':'0.5.9','cargo_audit':'0.22.2'},
                    'compiler_artifact':compiler,
                    'helper_sha256':release_sbom.digest(output/'libexec/setup')}
        (output/'share/build-provenance.json').write_text(json.dumps(provenance,sort_keys=True,indent=2)+'\n')
        (output/'share/build-provenance.json').chmod(0o644)
        for directory,subdirectories,_ in os.walk(output):
            Path(directory).chmod(0o755)
            for name in subdirectories:(Path(directory)/name).chmod(0o755)
        release_sbom.finalize(output,[graph],external,'xssi',version,revision,TARGET)
        release_manifest.finalize(output,'xssi',version,revision,TARGET)
        release_manifest.verify(output)
    source_identity(revision,version)
    return output


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--source-revision',required=True)
    parser.add_argument('--version',required=True)
    args=parser.parse_args();stage(args.output,args.source_revision,args.version)


if __name__=='__main__':main()
