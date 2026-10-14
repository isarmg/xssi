#!/usr/bin/env python3
"""Bind actual MSI runtime streams to reviewed WiX inputs and upstream license."""
import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

import native_package
import release_sbom as sbom
from gradle_sbom import bytes_regular

REVISION='73c897383236ddbbbc6ba257634013c1269ceec2'
SOURCE_SHA='5526afbd49ad947b60e0c8af6a33a1ac996b8a334ca9ec372800f4dd940f0b29'
PACKAGES={
    'wixtoolset.sdk':'029c37c6490a810f61bcd375dd661ace04c328640a9dadaef1e7149bc14ff0f6',
    'wixtoolset.ui.wixext':'e92c4ddac5d17f5360291ab856c676e19fd92af14daffb5d5d4b8e1e9c716b47',
    'wixtoolset.util.wixext':'541168d58c299dd8d62e92ea1877489756cfa73a27fd6ec855cd6341c8447562'}
SOURCE_URL='https://codeload.github.com/wixtoolset/wix/tar.gz/'+REVISION


def fetch(url,maximum):
    with urllib.request.urlopen(url,timeout=30) as source:value=source.read(maximum+1)
    if len(value)>maximum:raise ValueError('WiX upstream material exceeds its bound')
    return value


def upstream_inputs(cache,inputs,download,packages):
    notices=[];sources=[];runtime_origins={}
    if len(packages)!=len(set(packages)) or 'wixtoolset.sdk' not in packages or not set(packages)<=PACKAGES.keys():
        raise ValueError('review the actual selected WiX build dependency set')
    inputs.mkdir(parents=True,exist_ok=False)
    for name in packages:
        expected=PACKAGES[name]
        package=Path(cache)/name/'4.0.6';archive=package/(name+'.4.0.6.nupkg')
        raw=bytes_regular(archive,32*1024*1024)
        if len(raw)>32*1024*1024 or hashlib.sha256(raw).hexdigest()!=expected:
            raise ValueError('actual restored WiX package differs from its reviewed upstream input')
        with zipfile.ZipFile(io.BytesIO(raw)) as entries:
            for entry in entries.infolist():
                relative=sbom.relative(entry.filename) if not entry.is_dir() else None
                if relative is not None and entry.file_size>32*1024*1024:
                    raise ValueError('restored WiX package exceeds its file bound')
                if relative is not None and Path(relative).suffix.lower() in ('.dll','.exe','.wixlib','.props','.targets'):
                    actual=package/relative
                    if actual.is_symlink() or not actual.is_file() or sbom.digest(actual)!=hashlib.sha256(entries.read(entry)).hexdigest():
                        raise ValueError('actual WiX build assembly differs from its reviewed package')
            nuspec=[entry for entry in entries.namelist() if entry.endswith('.nuspec')]
            if len(nuspec)!=1:raise ValueError('WiX upstream package metadata is ambiguous')
            metadata=ET.fromstring(entries.read(nuspec[0]))
            def element(name):
                values=[item for item in metadata.iter() if item.tag.rsplit('}',1)[-1]==name]
                if len(values)!=1:raise ValueError('WiX upstream metadata omits its exact '+name)
                return values[0]
            if element('version').text!='4.0.6' or element('license').get('type')!='expression' or element('license').text!='MS-RL' or element('repository').get('commit')!=REVISION:
                raise ValueError('WiX origin/license differs from its reviewed release')
            notices.append(element('id').text+' 4.0.6\n'+element('copyright').text+'\n')
            # WiX 4 serializes its fixed extension .wixlib resource as a ZIP
            # within the reviewed assembly. Its upstream WixOutput reader uses
            # ZipArchive. Read only the two actual selected runtime providers,
            # never borrow arbitrary build-only SDK assemblies as runtime.
            assembly={'wixtoolset.ui.wixext':'wixext4/WixToolset.UI.wixext.dll',
                      'wixtoolset.util.wixext':'wixext4/WixToolset.Util.wixext.dll'}.get(name)
            if assembly:
                value=entries.read(assembly)
                with zipfile.ZipFile(io.BytesIO(value)) as library:
                    infos=library.infolist()
                    if len(infos)>128 or len({item.filename for item in infos})!=len(infos) or 'wix-ir.json' not in library.namelist():
                        raise ValueError('actual WiX runtime library resource is ambiguous')
                    for item in infos:
                        if item.is_dir() or item.filename=='wix-ir.json':continue
                        path=sbom.relative(item.filename)
                        if not path.startswith('wix-ir/') or item.file_size>8*1024*1024:
                            raise ValueError('actual WiX runtime resource differs from its bounded library')
                        contents=library.read(item)
                        digest=hashlib.sha256(contents).hexdigest()
                        runtime_origins.setdefault(digest,[]).append({'package':name,'package_sha256':expected,
                            'assembly':assembly,'assembly_sha256':hashlib.sha256(value).hexdigest(),
                            'resource_entry':path,'sha256':digest,'size':len(contents)})
        destination=inputs/archive.name;destination.write_bytes(raw)
        sources.append({'path':'wix/'+destination.name,'sha256':expected})
    raw=download(SOURCE_URL,64*1024*1024)
    if hashlib.sha256(raw).hexdigest()!=SOURCE_SHA:
        raise ValueError('WiX corresponding source differs from its exact upstream revision')
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        entry=archive.getmember('wix-'+REVISION+'/LICENSE.TXT')
        if not entry.isfile() or entry.size>1024*1024:raise ValueError('WiX upstream license is invalid')
        license_=archive.extractfile(entry).read()
    if not license_.strip():raise ValueError('WiX upstream license text is empty')
    return sources,license_,'\n'.join(notices).encode(),runtime_origins


def stage_runtime(payload,bootstrap_msi,build_input_root,*,cache,owned_inputs=(),packages=tuple(PACKAGES),download=fetch):
    """Run after the first build, then rebuild with these exact inventory files."""
    payload=Path(payload).resolve(strict=True);build_input_root=Path(build_input_root).resolve(strict=True)
    owned={sbom.digest(Path(path)) for path in owned_inputs}
    with tempfile.TemporaryDirectory(prefix='xssi-wix-runtime-') as temporary:
        extracted,streams=native_package.msi_payload(Path(bootstrap_msi).resolve(strict=True),Path(temporary),include_embedded=True)
        runtime=[]
        for name,record in sorted(streams.items()):
            destination=payload/name;destination.parent.mkdir(parents=True,exist_ok=True)
            if destination.exists():
                if destination.is_symlink() or sbom.digest(destination)!=record['sha256']:
                    raise ValueError('existing owned MSI binary differs from the actual bootstrap stream')
            else:shutil.copyfile(extracted/name,destination)
            if record['sha256'] not in owned:
                runtime.append({'path':name,'sha256':record['sha256'],'archive_entry':None})
        if not runtime:return []
        sources,license_,notices,origins=upstream_inputs(cache,build_input_root/'wix',download,packages)
        matched=[]
        for item in runtime:
            candidates=origins.get(item['sha256'],[])
            if not candidates:
                raise ValueError('MSI binary stream has no exact reviewed WiX runtime resource origin')
            matched.append({'target':item,'origins':candidates})
        authority=build_input_root/'wix/runtime-origins.json'
        authority.write_text(json.dumps({'format_version':1,'streams':matched},sort_keys=True,indent=2)+'\n')
        sources.append({'path':'wix/runtime-origins.json','sha256':sbom.digest(authority)})
    share=payload/'share';share.mkdir(exist_ok=True)
    license_path=share/'THIRD_PARTY_WIX_LICENSE.txt';license_path.write_bytes(license_)
    notice_path=share/'THIRD_PARTY_WIX_COPYRIGHTS.txt';notice_path.write_bytes(notices)
    for path in (license_path,notice_path):path.chmod(0o644)
    return [{'ref':'pkg:generic/wixtoolset-runtime@4.0.6','type':'library','name':'WiX Toolset runtime','version':'4.0.6',
        'source':{'url':SOURCE_URL,'sha256':SOURCE_SHA},'licenses':[
            {'name':'MS-RL','path':license_path.relative_to(payload).as_posix(),'sha256':sbom.digest(license_path)},
            {'name':'Upstream copyright notices','path':notice_path.relative_to(payload).as_posix(),'sha256':sbom.digest(notice_path)}],
        'delivery':'embedded','files':runtime,'dependencies':[],
        'embedding':{'kind':'compiled-resource','source_files':sources,'target_files':runtime}}]
