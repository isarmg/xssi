#!/usr/bin/env python3
"""Build a standalone tool delivery from this exact clean source revision."""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
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
        private=Path(temporary);source=private/'source'
        export_source(revision,source,private/'source.tar')
        graph=sbom.produce_runtime_cargo_bom(source,source/'Cargo.toml','xssi',output,'xssi',
            [(source,revision)],target=TARGET,environment=env)
        env['CARGO_NET_OFFLINE']='true'
        target=Path(env.get('CARGO_TARGET_DIR',str(private/'target'))).absolute()
        env['CARGO_TARGET_DIR']=str(target)
        sbom.run(['cargo','build','--frozen','--release','--target',TARGET,'--bin','setup'],source,env,maximum=4*1024*1024,timeout=1800)
        copy(target/TARGET/'release/setup',output/'libexec/setup',0o755)
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
