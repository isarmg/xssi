#!/usr/bin/env python3
"""Exercise the pinned real producer and license gates using private fixtures."""
import copy
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import tomllib

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
import sbom
from sbom_normalization import normalize


def rejected(action):
    try:action()
    except (ValueError,subprocess.CalledProcessError):return
    raise AssertionError('invalid dependency inventory was accepted')


def verify():
    environment={key:value for key,value in os.environ.items()
                 if not any(part in key.upper() for part in ('TOKEN','PASSWORD','SECRET','SIGNING','PRIVATE_KEY'))}
    for variable in ('XSSI_IDENTITY_FILE','XSSI_SCHEMA_FILE'):
        environment.pop(variable,None)
    sbom.tools(environment)
    versions=[record['version'] for record in tomllib.loads((ROOT/'Cargo.lock').read_text())['package'] if record['name']=='serde']
    if len(versions)!=1:raise ValueError('fixture must use the unique locked serde version')
    with tempfile.TemporaryDirectory(prefix='xssi-sbom-producer-') as temporary:
        private=Path(temporary);source=private/'fixture';library=private/'library';stage=private/'stage'
        (stage/'share').mkdir(parents=True)
        for directory,name in ((source,'xssi_fixture'),(library,'xssi_fixture_library')):
            (directory/'src').mkdir(parents=True)
            (directory/'src/lib.rs').write_text('pub fn fixture() {}\n')
            dependencies=f'serde={{version="={versions[0]}",features=["derive"]}}\n'
            if directory==source:dependencies+='xssi_fixture_library={path="../library"}\ncommon={path="common"}\nfnv="=1.0.7"\nbytecount="=0.6.9"\ncrc-catalog="=2.5.0"\n'
            (directory/'Cargo.toml').write_text(f'[package]\nname="{name}"\nversion="1.0.0"\nedition="2024"\nlicense="Apache-2.0"\ndescription="Actual Unicode metadata: \u0456"\n[dependencies]\n'+dependencies,encoding='utf-8')
        with (source/'Cargo.toml').open('a') as file:
            file.write('\n[workspace]\nmembers=["common","mobile","android-only"]\nresolver="3"\n')
        for name,declaration in (
            ('common','[features]\nandroid=["dep:android-only"]\n[dependencies]\nandroid-only={path="../android-only",optional=true}\n'),
            ('mobile','[dependencies]\ncommon={path="../common",features=["android"]}\n'),
            ('android-only',''),
        ):
            directory=source/name;(directory/'src').mkdir(parents=True)
            (directory/'src/lib.rs').write_text('pub fn fixture() {}\n')
            (directory/'Cargo.toml').write_text(f'[package]\nname="{name}"\nversion="1.0.0"\nedition="2024"\nlicense="Apache-2.0"\n'+declaration)
        (source/'rust-toolchain.toml').write_bytes((ROOT/'rust-toolchain.toml').read_bytes())
        cargo_home=private/'cargo-home';cargo_home.mkdir(mode=0o700)
        environment['CARGO_HOME']=str(cargo_home);environment['TZ']='UTC'
        sbom.run(['cargo','generate-lockfile'],source,environment)
        sbom.vendor(source,environment)
        environment['CARGO_NET_OFFLINE']='true'
        sbom.inventory(source,source/'Cargo.toml','xssi_fixture',None,environment,stage,'server',[(source,'1'*40),(library,'2'*40)])
        metadata=json.loads((source/'xssi-cargo-metadata.json').read_text(encoding='utf-8'))
        full_metadata=json.loads((source/'xssi-cargo-full-metadata.json').read_text(encoding='utf-8'))
        common=next(item for item in full_metadata['packages'] if item['name']=='common')
        android=next(item for item in full_metadata['packages'] if item['name']=='android-only')
        full_common=next(item for item in full_metadata['resolve']['nodes'] if item['id']==common['id'])
        if not any(item['pkg']==android['id'] for item in full_common['deps']):
            raise AssertionError('real workspace fixture did not reproduce metadata feature union')
        if any(item['name'] in ('android-only','mobile') for item in metadata['packages']):
            raise AssertionError('selected runtime metadata retained another workspace member feature')
        raw=json.loads((source/'xssi-release.cdx.json').read_text(encoding='utf-8'))
        encoded=(stage/'share/server-sbom.cdx.json').read_bytes()
        if '\u0456' not in encoded.decode('utf-8'):
            raise AssertionError('actual Unicode Cargo metadata did not survive UTF-8 serialization')
        revisions={record['id']:('1'*40 if record['name']=='xssi_fixture' else '2'*40) for record in metadata['packages'] if record['source'] is None}
        def normalized(value):return normalize(value,metadata,'xssi_fixture',revisions,[str(source),str(library)])
        normalized(raw)
        fnv=next(record for record in metadata['packages'] if record['name']=='fnv')
        if fnv['version']!='1.0.7' or fnv['license']!='Apache-2.0 / MIT':
            raise AssertionError('producer did not use the reviewed original fnv metadata')
        fnv_component=next(record for record in normalized(raw)['components'] if record['name']=='fnv')
        fnv_licenses=fnv_component.get('licenses')
        original_name=fnv_licenses==[{'license':{'name':'Apache-2.0 / MIT'}}]
        reviewed_expression=(isinstance(fnv_licenses,list) and len(fnv_licenses)==1
            and set(fnv_licenses[0])=={'expression'}
            and fnv_licenses[0]['expression'].split()==['Apache-2.0','OR','MIT'])
        if not original_name and not reviewed_expression:
            raise AssertionError('fnv SBOM changed its source declaration or emitted invalid SPDX')
        notice=(stage/'share/THIRD_PARTY_SERVER_LICENSES.txt').read_text(encoding='utf-8')
        if 'fnv 1.0.7\n  Declared license: Apache-2.0 / MIT\n  Resolved SPDX expression: Apache-2.0' not in notice:
            raise AssertionError('notice omitted fnv original declaration or reviewed interpretation')
        fnv_directory=Path(fnv['manifest_path']).parent
        for name in ('LICENSE-APACHE','LICENSE-MIT'):
            if (fnv_directory/name).read_text(encoding='utf-8').rstrip() not in notice:
                raise AssertionError('notice omitted a complete original fnv license')
        for name in ('bytecount','crc-catalog'):
            record=next(item for item in metadata['packages'] if item['name']==name)
            directory=Path(record['manifest_path']).parent
            originals=(list((directory/'LICENSES').iterdir()) if name=='crc-catalog'
                       else [directory/'LICENSE.MIT',directory/'LICENSE.Apache2'])
            if any(path.read_text(encoding='utf-8').rstrip() not in notice for path in originals):
                raise AssertionError('notice omitted a complete original bytecount/CRC license')
        if len(raw['components'])<5:raise AssertionError('producer fixture did not include transitive registry dependencies')
        disconnected=copy.deepcopy(raw)
        next(node for node in disconnected['dependencies'] if node['ref']==raw['metadata']['component']['bom-ref'])['dependsOn']=[]
        rejected(lambda:normalized(disconnected))
        path=copy.deepcopy(raw);path['metadata']['component']['purl']+='#%252Fprivate%252Fbuild'
        rejected(lambda:normalized(path))
        notices=ROOT/'scripts/generate-third-party-notices.mjs'
        def licensing(meta_path,output):
            # Capture diagnostics from these expected negative cases.
            result=subprocess.run(['node',str(notices),str(meta_path),str(source/'xssi-vendor'),str(source),str(output),'xssi_fixture',str(stage/'share/server-sbom.cdx.json')],
                                  cwd=source,env=environment,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
            if result.returncode==0 or output.exists():raise AssertionError('invalid upstream license was accepted')
        crc=next(item for item in metadata['packages'] if item['name']=='crc-catalog')
        crc_licenses=Path(crc['manifest_path']).parent/'LICENSES'
        unexpected=crc_licenses/'UNREVIEWED.txt'
        try:
            unexpected.write_text('Unknown license structure\n')
            licensing(source/'xssi-cargo-metadata.json',stage/'share/unknown-license-structure.txt')
        finally:unexpected.unlink()
        preserved=crc_licenses.with_name('original-license-directory');crc_licenses.rename(preserved)
        try:
            crc_licenses.symlink_to(preserved.name,target_is_directory=True)
            licensing(source/'xssi-cargo-metadata.json',stage/'share/aliased-license-directory.txt')
        finally:
            if crc_licenses.is_symlink():crc_licenses.unlink()
            preserved.rename(crc_licenses)
        checksum=fnv_directory/'.cargo-checksum.json';checksum_bytes=checksum.read_bytes()
        try:
            altered=json.loads(checksum_bytes);altered['package']='0'*64
            checksum.write_text(json.dumps(altered))
            licensing(source/'xssi-cargo-metadata.json',stage/'share/unreviewed-fnv-archive.txt')
        finally:checksum.write_bytes(checksum_bytes)
        license_path=fnv_directory/'LICENSE-MIT';license_bytes=license_path.read_bytes()
        try:
            license_path.write_bytes(license_bytes+b'altered\n')
            licensing(source/'xssi-cargo-metadata.json',stage/'share/altered-fnv-license.txt')
        finally:license_path.write_bytes(license_bytes)
        serde=next(record for record in metadata['packages'] if record['name']=='serde')
        directory=Path(serde['manifest_path']).parent
        originals={path:path.read_bytes() for path in directory.iterdir() if path.name.startswith('LICENSE')}
        if not originals:raise AssertionError('real serde source has no license texts')
        try:
            for path in originals:path.unlink()
            licensing(source/'xssi-cargo-metadata.json',stage/'share/missing-license.txt')
        finally:
            for path,value in originals.items():path.write_bytes(value)
        unsupported=copy.deepcopy(metadata)
        next(record for record in unsupported['packages'] if record['name']=='serde')['license']='GPL-3.0-only'
        negative=source/'unsupported-license.json';negative.write_text(json.dumps(unsupported))
        licensing(negative,stage/'share/unsupported-license.txt')
        print(f"Real CycloneDX producer verified: {len(normalized(raw)['components'])} runtime dependency components, source bindings, graph edges, private paths and upstream license gates.")


def verify_own_inventory():
    """The small regression fixture cannot replace this actual tool graph."""
    environment={key:value for key,value in os.environ.items()
                 if not any(part in key.upper() for part in ('TOKEN','PASSWORD','SECRET','SIGNING','PRIVATE_KEY'))}
    revision=sbom.run(['git','rev-parse','HEAD'],ROOT,environment,maximum=4096).decode('ascii').strip()
    if sbom.run(['git','status','--porcelain'],ROOT,environment,maximum=4096):
        raise ValueError('actual tool inventory requires its clean committed source')
    publisher=runpy.run_path(str(ROOT/'scripts/stage-release.py'),run_name='xssi_inventory_export')
    with tempfile.TemporaryDirectory(prefix='xssi-own-inventory-') as temporary:
        private=Path(temporary).resolve(strict=True);source=private/'source';stage=private/'stage'
        (stage/'share').mkdir(parents=True)
        publisher['export_source'](revision,source,private/'source.tar')
        environment['CARGO_TARGET_DIR']=str(private/'no-compile-target')
        destination=sbom.produce_runtime_cargo_bom(source,source/'Cargo.toml','xssi',stage,'xssi',
            [(source,revision)],target=sbom.TARGET,environment=environment)
        bom=json.loads(destination.read_bytes())
        if any(path.suffix in ('.rlib','.rmeta','.o','.so','.dll','.exe')
               for path in (private/'no-compile-target').rglob('*')):
            raise AssertionError('no-compile actual inventory created compiled artifacts')
        print(f"Actual clean XSSI Linux inventory verified: {len(bom['components'])} normal runtime dependency components; exact locked source and original license texts; no compilation.")


if __name__=='__main__':
    verify()
    verify_own_inventory()
