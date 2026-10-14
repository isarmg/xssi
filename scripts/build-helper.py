#!/usr/bin/env python3
"""Build one product helper from the exact clean product source snapshot."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import package
import release_sbom
import sbom
import sqlite_receipt

ROOT=Path(__file__).resolve().parents[1]
TARGET='x86_64-unknown-linux-gnu'
PRODUCTS={'xcos','xczs','xocs','xscs','xsos','xszs'}

def git(root,*args):
    return subprocess.check_output(['git','-C',str(root),*args],text=True).strip()

def source_digest(root):
    digest=hashlib.sha256();total=0;count=0
    for current,directories,files in os.walk(root,followlinks=False):
        directories[:]=[name for name in directories if name not in ('.git','node_modules','target') and Path(current)/name!=root/'web/runtime-dist']
        directories.sort();files.sort()
        for name in directories+files:
            path=Path(current)/name
            if path.is_symlink():raise ValueError('immutable source cannot contain symbolic links')
            count+=1
            if count>200000:raise ValueError('source entry count exceeds its bound')
            relative=path.relative_to(root).as_posix()
            digest.update(relative.encode()+b'\0')
            if path.is_file():
                value=package.bytes_regular(path,package.MAX_FILE_BYTES)
                total+=len(value)
                if total>package.MAX_TOTAL_BYTES:raise ValueError('source snapshot exceeds its byte bound')
                digest.update(hashlib.sha256(value).digest())
            elif not path.is_dir():raise ValueError('source contains a special file')
    return digest.hexdigest()

def packages(lock):
    return {(p['name'],p['version'],p.get('source','')):p.get('checksum') for p in lock['package']}

def build_environment():
    environment={key:value for key,value in os.environ.items()
                 if not any(part in key.upper() for part in ('TOKEN','PASSWORD','SECRET','SIGNING','PRIVATE_KEY'))}
    for variable in ('XSSI_BUILD_METADATA_DIR','XSSI_BUILD_RECEIPT_DIR','XSSI_BUILD_SOURCE_REVISION',
                     'XSSI_IDENTITY_FILE','XSSI_SCHEMA_FILE',
                     'SQLITE3_LIB_DIR','SQLITE3_INCLUDE_DIR','LIBSQLITE3_SYS_USE_PKG_CONFIG',
                     'SQLCIPHER_LIB_DIR','SQLCIPHER_INCLUDE_DIR'):
        environment.pop(variable,None)
    environment['TZ']='UTC'
    return environment

def verify_resolution(before,after):
    if packages(before)!=packages(after):raise ValueError('immutable helper dependency graph changed')

def ensure_external_receipt(stage):
    """Create the producer's empty receipt once; preserve validated contributions."""
    stage=release_sbom.physical_directory(stage)
    directory=release_sbom.physical_directory(stage/'share')
    path=directory/'external-components.json'
    try:
        descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o644)
    except FileExistsError:
        pass
    else:
        with os.fdopen(descriptor,'wb') as output:
            if os.name=='nt':path.chmod(0o644)
            else:os.fchmod(output.fileno(),0o644)
            output.write(b'{"format_version":1,"runtime_roots":[],"components":[]}\n')
            output.flush();os.fsync(output.fileno())
    data=release_sbom.load(path)
    release_sbom.fields(data,['format_version','runtime_roots','components'])
    if type(data['format_version'])is not int or data['format_version']!=1:
        raise ValueError('external inventory has a different current format')

    def collection(value,*,nonempty=False):
        if not isinstance(value,list) or len(value)>release_sbom.MAX_FILES or (nonempty and not value):
            raise ValueError('external inventory collection is invalid or exceeds its bound')
        return value

    inventory={}
    def bound_files(values,*,nonempty=True):
        seen=set()
        for item in collection(values,nonempty=nonempty):
            release_sbom.fields(item,['path','sha256','archive_entry'])
            name=release_sbom.relative(item['path']);release_sbom.sha(item['sha256'])
            entry=item['archive_entry']
            if entry is not None:release_sbom.relative(entry)
            key=(name,entry)
            if key in seen:raise ValueError('external inventory repeats a file binding')
            seen.add(key)
            if name not in inventory:inventory[name]=release_sbom.digest(stage/name)
            release_sbom.verify_file(item,stage,inventory)

    refs=set()
    for binding in collection(data['runtime_roots']):
        release_sbom.fields(binding,['ref','files'])
        ref=release_sbom.text(binding['ref'])
        if ref in refs:raise ValueError('external inventory repeats a runtime root')
        refs.add(ref);bound_files(binding['files'])
    for item in collection(data['components']):
        release_sbom.fields(item,['ref','type','name','version','source','licenses','delivery','files','dependencies'],['embedding'])
        ref=release_sbom.text(item['ref'])
        if ref in refs:raise ValueError('external inventory repeats a component identity')
        refs.add(ref)
        release_sbom.text(item['name']);release_sbom.text(item['version'])
        delivery=item['delivery']
        if delivery not in ('file','embedded','platform') or item['type'] not in ('application','library','data'):
            raise ValueError('external inventory component identity or delivery is invalid')
        release_sbom.source(item['source'],delivery=='platform')
        children=[release_sbom.text(value) for value in collection(item['dependencies'])]
        if len(set(children))!=len(children):raise ValueError('external inventory repeats a dependency')
        licenses=collection(item['licenses'],nonempty=delivery!='platform')
        for license_ in licenses:
            release_sbom.fields(license_,['name','path','sha256'])
            release_sbom.text(license_['name'])
            name=release_sbom.relative(license_['path']);expected=release_sbom.sha(license_['sha256'])
            if release_sbom.digest(stage/name)!=expected or (stage/name).stat().st_size==0:
                raise ValueError('external inventory upstream license differs from its receipt')
        if delivery=='platform':
            if collection(item['files']) or 'embedding'in item:
                raise ValueError('platform prerequisite cannot claim delivered files')
            continue
        bound_files(item['files'])
        if 'embedding'in item or (delivery=='embedded' and any(value['archive_entry']is None for value in item['files'])):
            if delivery!='embedded':raise ValueError('build inputs require embedded delivery')
            embed=item.get('embedding')
            release_sbom.fields(embed,['kind','source_files','target_files'],['input_root'])
            if embed['kind']not in ('static-link','compiled-resource') or embed.get('input_root','build')not in ('stage','build'):
                raise ValueError('external inventory embedding is invalid')
            for value in collection(embed['source_files'],nonempty=True):
                release_sbom.fields(value,['path','sha256'])
                name=release_sbom.relative(value['path']);expected=release_sbom.sha(value['sha256'])
                if embed.get('input_root')=='stage' and release_sbom.digest(stage/name)!=expected:
                    raise ValueError('retained embedded input differs from its receipt')
            if embed['target_files']!=item['files']:
                raise ValueError('external inventory embedding target differs')
    release_sbom.physical_directory(directory)
    return path

def build(args):
    if args.product not in PRODUCTS:raise ValueError('unsupported product')
    helper_revision=git(ROOT,'rev-parse','HEAD')
    if git(ROOT,'status','--porcelain','--untracked-files=all'):
        raise ValueError('formal helper requires a clean immutable tool source')
    tool_digest=source_digest(ROOT)
    source=args.source_root.resolve(strict=True)
    checkout=(source/'.git').exists()
    if checkout:
        if git(source,'status','--porcelain','--untracked-files=normal'):
            raise ValueError('formal helper requires a clean immutable product source')
        revision=git(source,'rev-parse','HEAD')
    else:
        # The controlled product packager created this git-archive snapshot
        # after independently checking its source tag and commit identity.
        revision=os.environ.get('XSSI_SOURCE_REVISION','')
    identity=package.loads(args.identity.read_bytes())
    if identity.get('product')!=args.product or identity.get('source_revision')!=revision or identity.get('target')!=TARGET:
        raise ValueError('helper source snapshot differs from declared product identity')
    before=tomllib.loads((ROOT/'Cargo.lock').read_text())
    contract=package.loads(package.bytes_regular(args.stage/'share/contracts/install.json'))
    if contract.get('contract_version')!=1 or contract.get('identity')!=identity:
        raise ValueError('generated current definitions differ from product release identity')
    with tempfile.TemporaryDirectory(prefix='xssi-helper-build-') as temporary:
        private=Path(temporary);snapshot=private/'product';snapshot.mkdir()
        if checkout:
            archive=private/'source.tar'
            with archive.open('wb') as output:
                subprocess.run(['git','-C',str(source),'archive','--format=tar',revision],stdout=output,check=True)
            with tarfile.open(archive) as tar:
                members=tar.getmembers()
                if len(members)>200000:raise ValueError('product source entry count exceeds its bound')
                for member in members:
                    path=Path(member.name)
                    if path.is_absolute() or '..' in path.parts or not (member.isdir() or member.isfile()):
                        raise ValueError('immutable product source contains unsupported paths or links')
                tar.extractall(snapshot,filter='data')
        else:
            before_source=source_digest(source)
            def ignored(current,names):
                return [name for name in names if name in ('.git','node_modules','target') or Path(current)/name==source/'web/runtime-dist']
            shutil.copytree(source,snapshot,dirs_exist_ok=True,ignore=ignored)
            if source_digest(snapshot)!=before_source:raise ValueError('private source copy differs')
        helper=private/'helper';helper.mkdir()
        for name in ('Cargo.toml','Cargo.lock','rust-toolchain.toml'):shutil.copyfile(ROOT/name,helper/name)
        shutil.copytree(ROOT/'src',helper/'src')
        product_path=snapshot/('crates/server' if args.product in ('xscs','xsos','xszs') else '')
        (helper/'scripts').mkdir()
        shutil.copyfile(ROOT/'scripts/install-contract.schema.json',helper/'scripts/install-contract.schema.json')
        environment=build_environment()
        target=Path(environment.get('CARGO_TARGET_DIR',str(ROOT/'target'))).absolute()
        environment['CARGO_TARGET_DIR']=str(target)
        sbom.tools(environment)
        sbom.vendor(helper,environment)
        isolated_cargo=private/'cargo-home';isolated_cargo.mkdir(mode=0o700)
        environment['CARGO_HOME']=str(isolated_cargo)
        environment['CARGO_NET_OFFLINE']='true'
        subprocess.run(['cargo','build','--manifest-path',str(helper/'Cargo.toml'),'--locked','--release','--target',TARGET,'--bin','setup'],cwd=helper,check=True,env=environment)
        verify_resolution(before,tomllib.loads((helper/'Cargo.lock').read_text()))
        if checkout:
            if git(source,'rev-parse','HEAD')!=revision or git(source,'status','--porcelain','--untracked-files=normal'):
                raise ValueError('product source changed during helper build')
        elif source_digest(source)!=before_source:
            raise ValueError('archive source changed during helper build')
        (args.stage/'libexec').mkdir(parents=True,exist_ok=True)
        shutil.copyfile(target/TARGET/'release/setup',args.stage/'libexec/setup');(args.stage/'libexec/setup').chmod(0o755)
        (args.stage/'share').mkdir(parents=True,exist_ok=True)
        shutil.copyfile(helper/'Cargo.lock',args.stage/'share/setup-Cargo.lock')
        local_sources=[(helper,helper_revision)]
        sbom.inventory(helper,helper/'Cargo.toml','xssi',None,environment,args.stage,'setup',local_sources)
        product_environment=build_environment()
        sbom.vendor(snapshot,product_environment)
        product_environment['CARGO_HOME']=str(isolated_cargo)
        product_environment['CARGO_NET_OFFLINE']='true'
        sbom.inventory(snapshot,product_path/'Cargo.toml',args.product,None,product_environment,args.stage,'server',[(snapshot,revision)])
        for manifest in (helper/'Cargo.lock',snapshot/'Cargo.lock'):
            subprocess.run(['cargo','audit','--deny','yanked','--file',str(manifest)],cwd=ROOT,check=True,env=build_environment())
        ensure_external_receipt(args.stage)
        native=[sqlite_receipt.record(helper,args.stage,'setup','libexec/setup'),sqlite_receipt.record(snapshot,args.stage,'server',f'bin/{args.product}')]
        sqlite_receipt.merge(args.stage,native,[(args.stage/'share/setup-sbom.cdx.json','libexec/setup'),(args.stage/'share/server-sbom.cdx.json',f'bin/{args.product}')])
        licenses=args.stage/'share/licenses';licenses.mkdir(exist_ok=True)
        shutil.copyfile(ROOT/'LICENSE-APACHE',licenses/'XSSI-LICENSE-APACHE')
        if (git(ROOT,'rev-parse','HEAD')!=helper_revision or git(ROOT,'status','--porcelain','--untracked-files=all')
            or source_digest(ROOT)!=tool_digest):
            raise ValueError('tool source changed during the source-bound release build')

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--product',required=True);parser.add_argument('--source-root',type=Path,required=True)
    parser.add_argument('--identity',type=Path,required=True);parser.add_argument('--stage',type=Path,required=True)
    build(parser.parse_args())
