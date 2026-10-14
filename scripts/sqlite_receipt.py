"""Retain the actual bundled SQLite amalgamation and its upstream notice."""
import json
from pathlib import Path
import re
import shutil
import tomllib
import package
import release_sbom as sbom
from release_manifest import bounded


def sha(path):
    return sbom.digest(path)


def record(source,stage,label,target=None,*,files=None,inventory_relative="share"):
    source=Path(source).resolve(strict=True);stage=Path(stage).resolve(strict=True)
    sbom.relative(inventory_relative)
    if not re.fullmatch("[a-zA-Z0-9_-]+",label):raise ValueError("SQLite inventory label is invalid")
    if files is None:
        target=sbom.relative(target)
        files=[{"path":target,"sha256":sha(stage/target),"archive_entry":None}]
    elif target is not None or not isinstance(files,list) or not files:
        raise ValueError("SQLite needs an unambiguous actual runtime file binding")
    for item in files:
        sbom.fields(item,["path","sha256","archive_entry"])
        sbom.relative(item["path"]);sbom.sha(item["sha256"])
        if item["archive_entry"] is not None:sbom.relative(item["archive_entry"])
    metadata=package.loads(bounded(source/'xssi-cargo-metadata.json',32*1024*1024))
    selected=[item for item in metadata['packages'] if item['name']=='libsqlite3-sys']
    if len(selected)!=1:raise ValueError('bundled SQLite must resolve to exactly one source')
    selected=selected[0]
    nodes=[node for node in metadata['resolve']['nodes'] if node['id']==selected['id']]
    if len(nodes)!=1 or 'bundled' not in nodes[0]['features'] or any('sqlcipher' in value for value in nodes[0]['features']):
        raise ValueError('native SQLite receipt requires the actual bundled amalgamation build')
    lock=tomllib.loads(bounded(source/'Cargo.lock',8*1024*1024).decode())
    packages=[item for item in lock['package'] if item['name']=='libsqlite3-sys' and item['version']==selected['version'] and item.get('source')==selected['source']]
    if len(packages)!=1 or not re.fullmatch('[0-9a-f]{64}',packages[0].get('checksum','')):
        raise ValueError('SQLite wrapper archive is not checksum-bound')
    origin=Path(selected['manifest_path']).parent
    if not origin.is_relative_to(source/'xssi-vendor'):
        raise ValueError('SQLite receipt requires the actual private vendored build source')
    checksums=package.loads(bounded(origin/'.cargo-checksum.json',1024*1024))
    if checksums['package']!=packages[0]['checksum']:
        raise ValueError('SQLite vendor source archive checksum differs')
    c=origin/'sqlite3/sqlite3.c';header=origin/'sqlite3/sqlite3.h'
    for path in (c,header):
        if checksums['files'].get(path.relative_to(origin).as_posix())!=sha(path):
            raise ValueError('SQLite build input differs from its verified vendor source')
    header_text=bounded(header,2*1024*1024).decode()
    versions=re.findall(r'^#define SQLITE_VERSION\s+"([^"\n]+)"$',header_text,re.M)
    if len(versions)!=1 or not re.fullmatch(r'\d+\.\d+\.\d+',versions[0]):
        raise ValueError('SQLite upstream version is missing from its actual header')
    first=header_text.split('*************************************************************************',1)[0]
    if not first.startswith('/*\n') or 'The author disclaims copyright to this source code.' not in first:
        raise ValueError('SQLite upstream public-domain notice is missing')
    notice=first+'*/\n'
    vcs=package.loads(bounded(origin/'.cargo_vcs_info.json',1024*1024))
    revision=vcs['git']['sha1'];prefix=vcs['path_in_vcs']
    if not re.fullmatch('[0-9a-f]{40}',revision) or prefix!='libsqlite3-sys':
        raise ValueError('SQLite upstream source revision is not bound')
    directory=stage/inventory_relative/'build-inputs'/f'{label}-sqlite';directory.mkdir(parents=True)
    inputs=[]
    for path in (c,header):
        destination=directory/path.name;shutil.copyfile(path,destination);destination.chmod(0o644)
        if sha(destination)!=sha(path):raise ValueError('retained SQLite input changed')
        inputs.append({'path':destination.relative_to(stage).as_posix(),'sha256':sha(destination)})
    evidence={'crate':{'name':'libsqlite3-sys','version':selected['version'],'archive_sha256':packages[0]['checksum']},
              'upstream_revision':revision,'sqlite_version':versions[0],'inputs':inputs}
    evidence_path=directory/'source.json';evidence_path.write_text(json.dumps(evidence,sort_keys=True,indent=2)+'\n');evidence_path.chmod(0o644)
    inputs.append({'path':evidence_path.relative_to(stage).as_posix(),'sha256':sha(evidence_path)})
    license_path=stage/inventory_relative/'licenses'/f'SQLite-{versions[0]}-COPYRIGHT.txt';license_path.parent.mkdir(parents=True,exist_ok=True)
    if license_path.exists() and bounded(license_path,1024*1024).decode()!=notice:
        raise ValueError('SQLite upstream notice conflicts with an existing component')
    license_path.write_text(notice);license_path.chmod(0o644)
    return {'ref':f'urn:sarmg:third-party:sqlite:{versions[0]}:{sha(c)}','type':'library','name':'SQLite','version':versions[0],
            'source':{'url':f'https://raw.githubusercontent.com/rusqlite/rusqlite/{revision}/libsqlite3-sys/sqlite3/sqlite3.c','sha256':sha(c)},
            'licenses':[{'name':'SQLite public-domain dedication','path':license_path.relative_to(stage).as_posix(),'sha256':sha(license_path)}],
            'delivery':'embedded','files':files,'dependencies':[],
            'embedding':{'kind':'static-link','input_root':'stage','source_files':inputs,'target_files':files}}


def merge(stage,components,boms):
    path=stage/'share/external-components.json'
    data=package.loads(bounded(path,32*1024*1024))
    if set(data)!= {'format_version','runtime_roots','components'} or type(data['format_version'])is not int or data['format_version']!=1:
        raise ValueError('external component receipt is missing or has a different format')
    for bom,target in boms:
        root=package.loads(bounded(bom,32*1024*1024))['metadata']['component']['bom-ref']
        binding={'ref':root,'files':[{'path':target,'sha256':sha(stage/target),'archive_entry':None}]}
        existing=[item for item in data['runtime_roots'] if item['ref']==root]
        if existing and existing!=[binding]:raise ValueError('runtime root binding conflicts with actual executable')
        if not existing:data['runtime_roots'].append(binding)
    for component in components:
        existing=[item for item in data['components'] if item['ref']==component['ref']]
        if len(existing)>1:raise ValueError('native component repeats')
        if not existing:data['components'].append(component)
        else:
            item=existing[0]
            for key in ('type','name','version','source','licenses','delivery','dependencies'):
                if item[key]!=component[key]:raise ValueError('native SQLite sources or licenses conflict')
            for value in component['files']:
                if value not in item['files']:item['files'].append(value)
            for value in component['embedding']['source_files']:
                if value not in item['embedding']['source_files']:item['embedding']['source_files'].append(value)
            item['embedding']['target_files']=item['files']
    path.write_text(json.dumps(data,sort_keys=True,indent=2)+'\n');path.chmod(0o644)
