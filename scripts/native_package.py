#!/usr/bin/env python3
"""Verify final native installer files with mature platform extraction tools."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

sys.path.insert(0,str(Path(__file__).resolve().parent))
import release_sbom as sbom
from sbom import run as bounded_dependency_tool, run_to_file as bounded_dependency_file


def run(command):
    environment={key:value for key,value in os.environ.items()
                 if not any(part in key.upper() for part in ('TOKEN','SECRET','SIGNING','PASSWORD','PRIVATE_KEY'))}
    environment['TZ']='UTC'
    try:
        return bounded_dependency_tool(command,Path.cwd(),environment,maximum=sbom.MAX_JSON,timeout=600)
    except subprocess.CalledProcessError:
        raise ValueError('native platform extractor failed') from None


def tool(name):
    value=shutil.which(name)
    if not value:raise ValueError('required mature native extractor is unavailable: '+name)
    return str(Path(value).absolute())


def inspect(root):
    result={};queue=[Path(root)]
    while queue:
        directory=queue.pop()
        for path in directory.iterdir():
            info=path.lstat();name=path.relative_to(root).as_posix()
            if stat.S_ISDIR(info.st_mode):queue.append(path)
            elif stat.S_ISLNK(info.st_mode):
                target=os.readlink(path)
                try:sbom.package_link_target(root,name)
                except OSError as error:raise ValueError('native installer alias has no delivered referent') from error
                result[name]={'kind':'symlink','sha256':hashlib.sha256(target.encode()).hexdigest(),'target':target}
            elif stat.S_ISREG(info.st_mode) and info.st_nlink==1:
                result[name]={'kind':'file','sha256':sbom.digest(path),'size':info.st_size,'mode':stat.S_IMODE(info.st_mode)}
            else:raise ValueError('native installer contains an uncontrolled payload object')
            if len(result)+len(queue)>16384:raise ValueError('native installer payload exceeds its inventory bound')
    return result


def inner_inventory(document):
    if document.get('bomFormat')!='CycloneDX' or document.get('specVersion')!='1.5':
        raise ValueError('native installer has no actual current inner SBOM')
    metadata=document['metadata'];properties={item['name']:item['value'] for item in metadata.get('properties',[])}
    if len(properties)!=len(metadata.get('properties',[])):raise ValueError('native SBOM metadata is ambiguous')
    exclusions=json.loads(properties['inventory-self-exclusion'])
    outputs=[sbom.relative(value) for value in exclusions if value.endswith('/release-sbom.cdx.json')]
    if len(outputs)!=1:raise ValueError('native SBOM does not declare one exact inventory path')
    files={}
    for item in document.get('components',[]):
        if item.get('type')!='file':continue
        name=sbom.relative(item['name']);hashes=[value['content'] for value in item.get('hashes',[]) if value['alg']=='SHA-256']
        if name in files or len(hashes)!=1:raise ValueError('native SBOM repeats or omits a file digest')
        props={value['name']:value['value'] for value in item.get('properties',[])}
        if len(props)!=len(item.get('properties',[])):raise ValueError('native file attributes are ambiguous')
        try:
            size=int(props['file-size']);mode=int(props['file-mode']);scope=props['file-mode-scope']
        except (KeyError,TypeError,ValueError) as error:raise ValueError('native inventory omits its actual file attributes') from error
        script_names={'installer-scripts/postinstall.sh','installer-scripts/preremove.sh','installer-scripts/postremove.sh'}
        if size<0 or mode<0 or mode>0o7777 or scope not in ('installed-posix','build-host','installer-script'):
            raise ValueError('native inventory file attributes are invalid')
        if scope=='installer-script':
            if name not in script_names or 'windows' in properties['target']:
                raise ValueError('native inventory script scope is outside its exact declaration')
        elif scope!=('build-host' if 'windows' in properties['target'] else 'installed-posix'):
            raise ValueError('native file mode scope differs from the actual release target')
        record={'sha256':sbom.sha(hashes[0]),'kind':'symlink' if props.get('file-kind')=='symbolic-link' else 'file'}
        if record['kind']=='file':
            record['size']=size
            if scope=='installed-posix':record['mode']=mode
            elif scope=='installer-script':record['script_mode']=mode
        if record['kind']=='symlink':record['target']=props['link-target']
        files[name]=record
    if not files:raise ValueError('native SBOM file inventory is empty')
    return files,outputs[0]


def msi_payload(artifact,private,*,include_embedded=False):
    # WiX reads tables and cabinet/Binary streams without executing installation
    # actions; the decompiled names supply the actual installation file mapping.
    private=Path(private);private.mkdir(parents=True,exist_ok=True)
    private=private.resolve(strict=True)
    extraction=private/'extracted';extraction.mkdir()
    document=private/'installer.wxs'
    run([tool('wix'),'msi','decompile','-x',str(extraction),'-o',str(document),str(artifact)])
    tree=ET.parse(document).getroot()
    def tag(item):return item.tag.rsplit('}',1)[-1]
    directories={};parents={child:parent for parent in tree.iter() for child in parent}
    for item in tree.iter():
        if tag(item)=='Directory':
            parent=parents.get(item);parent_id=parent.get('Id') if parent is not None and tag(parent) in ('Directory','StandardDirectory','DirectoryRef') else None
            directories[item.get('Id')]=(parent_id,item.get('Name'))
    def directory_path(identity):
        parts=[];seen=set()
        while identity!='INSTALLFOLDER':
            if identity in seen or identity not in directories:raise ValueError('MSI payload is outside the current installation directory')
            seen.add(identity);identity,name=directories[identity]
            if name and name!='.':parts.append(name.split('|')[-1])
        return '/'.join(reversed(parts))
    payload=private/'payload';payload.mkdir();embedded={}
    for item in tree.iter():
        kind=tag(item)
        if kind not in ('File','Binary'):continue
        identifier=sbom.relative(item.get('Id',''))
        if '/' in identifier:raise ValueError('MSI stream identity is not a single filename')
        if kind=='File':
            # WiX 4.0.6 uses the logical BaseSourcePath "SourceDir" in WXS,
            # while -x physically extracts compressed File rows under File/.
            # Bind its exact mapping; never search for a similarly named file.
            if item.get('Source','').replace('\\','/')!='SourceDir/File/'+identifier:
                raise ValueError('MSI compressed file source differs from the exact WiX extraction layout')
            source=extraction/'File'/identifier
        else:
            source=Path(item.get('SourceFile',''))
            if not source.is_absolute() or source!=extraction/'Binary'/identifier:
                raise ValueError('MSI Binary stream differs from the exact WiX extraction layout')
        sbom.physical_directory(source.parent)
        if source.is_symlink() or not source.is_file() or not source.is_relative_to(extraction):
            raise ValueError('MSI extractor file leaves its controlled extraction directory')
        if kind=='Binary':
            name='installer-binaries/'+sbom.relative(item.get('Id',''))
            if name in embedded:raise ValueError('MSI repeats an embedded binary stream')
            embedded[name]={'sha256':sbom.digest(source),'size':source.stat().st_size,
                            'mode':stat.S_IMODE(source.stat().st_mode)}
            if include_embedded:
                target=payload/name;target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(source,target)
            continue
        parent=parents[item];directory_id=None
        while tag(parent) not in ('Directory','DirectoryRef','StandardDirectory'):
            if tag(parent)=='Component' and parent.get('Directory'):
                directory_id=parent.get('Directory');break
            if parent not in parents:raise ValueError('MSI file has no installation directory')
            parent=parents[parent]
        prefix=directory_path(directory_id or parent.get('Id'));name=item.get('Name')
        if not name:raise ValueError('MSI file has no exact installation filename')
        relative=sbom.relative((prefix+'/' if prefix else '')+name.split('|')[-1])
        target=payload/relative
        target.parent.mkdir(parents=True,exist_ok=True)
        if target.exists():raise ValueError('MSI repeats an installation filename')
        shutil.copyfile(source,target)
    return payload,embedded


def materialize(stage,artifact,inner_bom,format):
    stage=Path(stage).resolve(strict=True)
    artifact=Path(artifact).resolve(strict=True);inner_bom=Path(inner_bom).resolve(strict=True)
    if not artifact.is_relative_to(stage) or not inner_bom.is_relative_to(stage):
        raise ValueError('native package evidence must stay within the final release')
    artifact_digest=sbom.digest(artifact);bom_digest=sbom.digest(inner_bom)
    document=sbom.load(inner_bom);expected,bom_path=inner_inventory(document)
    with tempfile.TemporaryDirectory(prefix='xssi-native-package-') as temporary:
        private=Path(temporary).resolve(strict=True);payload=private/'payload';embedded={}
        if format=='deb':
            component=document['metadata']['component']
            expected_version=component['version'].replace('-rc.','~rc')
            for field,value in (('Package',component['name']),('Version',expected_version)):
                if run([tool('dpkg-deb'),'--field',str(artifact),field]).decode().strip()!=value:
                    raise ValueError('native DEB identity differs from its exact payload inventory')
            run([tool('dpkg-deb'),'--extract',str(artifact),str(payload)])
            control=private/'control'
            run([tool('dpkg-deb'),'--control',str(artifact),str(control)])
            embedded={
                'DEBIAN/'+name:{key:value[key] for key in ('sha256','size','mode')}
                for name,value in inspect(control).items()
            }
            for original,destination in [('DEBIAN/postinst','installer-scripts/postinstall.sh'),
                                         ('DEBIAN/prerm','installer-scripts/preremove.sh'),
                                         ('DEBIAN/postrm','installer-scripts/postremove.sh')]:
                if destination in expected and original in embedded:
                    embedded[destination]=embedded.pop(original)
        elif format=='rpm':
            component=document['metadata']['component']
            if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',component['version']):
                raise ValueError('native RPM requires its exact current numeric package version')
            for field,value in (('NAME',component['name']),('VERSION',component['version'])):
                actual_identity=run([tool('rpm'),'--query','--package','--queryformat','%{'+field+'}',str(artifact)]).decode().strip()
                if actual_identity!=value:raise ValueError('native RPM identity differs from its exact payload inventory')
            archive=private/'payload.cpio'
            # rpm2cpio only emits the existing package payload; bsdtar handles the
            # mature cpio format and safe pathname policy, not a custom parser.
            command=[tool('rpm2cpio'),str(artifact)]
            environment={key:value for key,value in os.environ.items() if not any(part in key.upper() for part in ('TOKEN','SECRET','SIGNING','PASSWORD','PRIVATE_KEY'))}
            bounded_dependency_file(command,Path.cwd(),environment,archive,
                                    maximum=2*1024*1024*1024,timeout=600)
            payload.mkdir();run([tool('bsdtar'),'-xf',str(archive),'-C',str(payload)])
            script_tags={'POSTIN':'installer-scripts/postinstall.sh','PREUN':'installer-scripts/preremove.sh','POSTUN':'installer-scripts/postremove.sh'}
            available=set(run([tool('rpm'),'--querytags']).decode().splitlines())
            required={*script_tags,*[name+'PROG' for name in script_tags],*[name+'FLAGS' for name in script_tags]}
            if not required<=available:raise ValueError('RPM inspection tool cannot verify the declared executable scripts')
            for tag in available & {'PREIN','POSTIN','PREUN','POSTUN','PRETRANS','POSTTRANS','PREUNTRANS','POSTUNTRANS','VERIFYSCRIPT','TRIGGERSCRIPTS','FILETRIGGERSCRIPTS','TRANSFILETRIGGERSCRIPTS'}:
                value=run([tool('rpm'),'--query','--package','--queryformat','%{'+tag+'}',str(artifact)])
                if value in (b'(none)',b''):continue
                if tag not in script_tags or script_tags[tag] not in expected:
                    raise ValueError('RPM contains an undeclared executable script')
                programs=run([tool('rpm'),'--query','--package','--queryformat','[%{'+tag+'PROG}\\n]',str(artifact)]).decode().splitlines()
                flags=run([tool('rpm'),'--query','--package','--queryformat','%{'+tag+'FLAGS}',str(artifact)]).decode().strip()
                if programs!=['/bin/sh'] or flags not in ('0','(none)'):
                    raise ValueError('RPM script interpreter or flags differ from the declared shell source')
                embedded[script_tags[tag]]={'sha256':hashlib.sha256(value).hexdigest(),'size':len(value),'mode':None}
        elif format=='pkg':
            expanded=private/'expanded';run([tool('pkgutil'),'--expand-full',str(artifact),str(expanded)])
            candidates=[path for path in expanded.rglob('Payload') if path.is_dir() and not path.is_symlink()]
            if len(candidates)!=1:raise ValueError('native PKG must have one exact product payload')
            payload=candidates[0]
            package_info=ET.parse(payload.parent/'PackageInfo').getroot()
            component=document['metadata']['component']
            if package_info.get('identifier')!='org.sarmg.'+component['name'] or package_info.get('version')!=component['version'].split('-rc.')[0]:
                raise ValueError('native PKG identity differs from its exact payload inventory')
            scripts=payload.parent/'Scripts'
            other_scripts=[path for path in expanded.rglob('Scripts') if path.is_dir() and path!=scripts]
            if other_scripts:raise ValueError('native PKG contains executable scripts outside its exact component')
            if scripts.exists():
                embedded={'installer-scripts/macos/'+name:{key:value[key] for key in ('sha256','size','mode')}
                          for name,value in inspect(scripts).items()}
        elif format=='msi':
            payload,embedded=msi_payload(artifact,private)
            import msi_policy
            policy_path=payload/msi_policy.POLICY
            material=payload/'share/msi-authoring.wxs'
            if msi_policy.POLICY not in expected or 'share/msi-authoring.wxs' not in expected:
                raise ValueError('MSI is missing its current source installation policy')
            policy=sbom.load(policy_path)
            if sbom.digest(policy_path)!=expected[msi_policy.POLICY]['sha256'] or sbom.digest(material)!=policy['source_sha256'] or sbom.digest(material)!=expected['share/msi-authoring.wxs']['sha256']:
                raise ValueError('MSI installation policy or source material differs from its actual inner inventory')
            component=document['metadata']['component']
            if policy['package']['Name']!=component['name'] or policy['package']['Version']!=component['version'].split('-rc.')[0]:
                raise ValueError('MSI source policy differs from the actual product software version')
            derived=msi_policy.create(material,private/'policy-source',policy['package']['Version'],policy['source_revision'])
            if policy!=derived:raise ValueError('MSI policy changed the retained source installation semantics')
            tables_path=private/'msi-tables.json'
            run([tool('powershell.exe'),'-NoProfile','-NonInteractive','-File',str(Path(__file__).with_name('msi_tables.ps1')),
                 '-Artifact',str(artifact),'-Output',str(tables_path)])
            properties={item['name']:item['value'] for item in document['metadata']['properties']}
            msi_policy.validate(policy,sbom.load(tables_path),properties)
        else:raise ValueError('native installer format is unsupported')
        actual=inspect(payload)
        prefixes=('installer-binaries/','DEBIAN/','installer-scripts/') if format=='deb' else ('installer-binaries/','installer-scripts/')
        owned_embedded={name:record for name,record in expected.items() if name.startswith(prefixes)}
        if not owned_embedded.keys()<=embedded.keys():raise ValueError('native installer omitted an owned embedded binary')
        installed={name:record for name,record in expected.items() if name not in owned_embedded}
        if set(actual)!=set(installed)|{bom_path}:raise ValueError('final native installer file set differs from its inner inventory')
        if actual[bom_path]['kind']!='file' or actual[bom_path]['sha256']!=bom_digest:
            raise ValueError('final native installer changed or omitted its inner SBOM')
        for name,record in installed.items():
            if any(actual[name].get(key)!=value for key,value in record.items()):raise ValueError('final native installer payload differs from its inner inventory')
        for name,record in owned_embedded.items():
            if record['kind']!='file' or any(embedded[name].get(key)!=value for key,value in record.items() if key not in ('kind','script_mode')):
                raise ValueError('final native installer changed an owned embedded binary')
            if 'script_mode' in record and format in ('deb','pkg') and embedded[name]['mode']!=record['script_mode']:
                raise ValueError('final DEB changed its actual executable script permission')
        # Other native installer streams require explicit upstream provenance in
        # the inner SBOM, rather than being silently treated as build-only tools.
        # DEB control metadata is generated by dpkg; only declared scripts and
        # explicit controls are compared here. Unknown executable scripts remain
        # forbidden, while passive generated checksums may be recorded as data.
        extras=set(embedded)-set(owned_embedded)
        if format!='deb' or not extras<= {'DEBIAN/control','DEBIAN/md5sums','DEBIAN/conffiles'}:
            if extras:raise ValueError('native installer contains unrecorded runtime binary streams')
        passive={name:embedded.pop(name) for name in sorted(extras)}
        receipt={'format_version':1,'artifact':{'path':artifact.relative_to(stage).as_posix(),'sha256':artifact_digest,'size':artifact.stat().st_size,'format':format},
                 'inner_bom':{'path':inner_bom.relative_to(stage).as_posix(),'sha256':bom_digest},
                 'installed_files':[{'path':name,**{key:actual[name][key] for key in ('sha256','size','mode')}} for name in sorted(actual) if actual[name]['kind']=='file'],
                 'installed_symlinks':[{'path':name,**{key:actual[name][key] for key in ('target','sha256')}} for name in sorted(actual) if actual[name]['kind']=='symlink'],
                 'embedded_files':[{'path':name,**{key:record[key] for key in ('sha256','size','mode')}} for name,record in sorted(embedded.items())]}
        if passive:receipt['package_metadata']=[{'path':name,**{key:record[key] for key in ('sha256','size','mode')}} for name,record in passive.items()]
    if sbom.digest(artifact)!=artifact_digest or sbom.digest(inner_bom)!=bom_digest:
        raise ValueError('native package authority changed during extraction')
    folder=stage/'share';folder.mkdir(exist_ok=True)
    destination=folder/(artifact.name+'.native-receipt.json')
    with destination.open('x') as output:json.dump(receipt,output,sort_keys=True,indent=2);output.write('\n')
    destination.chmod(0o644)
    return destination


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('stage','artifact','inner-bom'):parser.add_argument('--'+name,required=True,type=Path)
    parser.add_argument('--format',required=True,choices=('deb','rpm','pkg','msi'))
    args=parser.parse_args();print(materialize(args.stage,args.artifact,args.inner_bom,args.format))


if __name__=='__main__':main()
