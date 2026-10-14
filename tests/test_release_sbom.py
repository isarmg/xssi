import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import release_sbom as sbom


class ReleaseInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='xssi-final-inventory-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.stage = self.root / 'stage'
        (self.stage / 'bin').mkdir(parents=True)
        (self.stage / 'share/licenses').mkdir(parents=True)
        (self.stage / 'bin/server').write_bytes(b'actual fixture payload\n')
        self.bom = self.root / 'runtime.json'
        self.bom.write_text(json.dumps({'bomFormat':'CycloneDX','specVersion':'1.5','version':1,
            'metadata':{'component':{'type':'application','name':'fixture','version':'1.0.0','bom-ref':'fixture'}},
            'components':[{'type':'library','name':'runtime','version':'1.0.0','bom-ref':'runtime'}],
            'dependencies':[{'ref':'fixture','dependsOn':['runtime']},{'ref':'runtime','dependsOn':[]}]}))
        self.receipt = {'format_version':1,'runtime_roots':[{'ref':'fixture','files':[self.file('bin/server')]}],'components':[]}
        self.path = self.root / 'external.json'

    def file(self, path, entry=None, contents=None):
        return {'path':path,'sha256':sbom.digest(self.stage/path) if contents is None else hashlib.sha256(contents).hexdigest(),'archive_entry':entry}

    def generate(self, **options):
        self.path.write_text(json.dumps(self.receipt))
        output = sbom.finalize(self.stage,[self.bom],self.path,'fixture','1.0.0','1'*40,'fixture-target',self.root,**options)
        return json.loads(output.read_text())

    def font(self):
        (self.stage/'share/font.woff2').write_bytes(b'font fixture')
        (self.stage/'share/licenses/font.txt').write_text('Actual upstream fixture license\n')
        component={'ref':'font','type':'data','name':'font','version':'1.0.0',
            'source':{'url':'https://example.org/font-1.0.0.woff2','sha256':sbom.digest(self.stage/'share/font.woff2')},
            'licenses':[{'name':'Fixture license','path':'share/licenses/font.txt','sha256':sbom.digest(self.stage/'share/licenses/font.txt')}],
            'delivery':'file','files':[self.file('share/font.woff2')],'dependencies':[]}
        self.receipt['components'].append(component)
        return component

    def test_final_files_and_runtime_edges_are_bound_without_self_hash_recursion(self):
        self.font()
        document=self.generate()
        self.assertEqual(document['metadata']['component']['version'],'1.0.0')
        files={item['name']:item['hashes'][0]['content'] for item in document['components'] if item['type']=='file'}
        self.assertEqual(files['bin/server'],sbom.digest(self.stage/'bin/server'))
        self.assertNotIn(sbom.OUTPUT,files)
        self.assertEqual(document,self.generate())

    def test_changed_payload_missing_graph_binding_or_license_are_rejected(self):
        component=self.font()
        original=copy.deepcopy(self.receipt)
        for variant in ('changed-binary','missing-root','changed-license','dangling-dependency'):
            self.receipt=copy.deepcopy(original)
            if variant=='changed-binary':self.receipt['runtime_roots'][0]['files'][0]['sha256']='2'*64
            if variant=='missing-root':self.receipt['runtime_roots']=[]
            if variant=='changed-license':self.receipt['components'][0]['licenses'][0]['sha256']='3'*64
            if variant=='dangling-dependency':self.receipt['components'][0]['dependencies']=['missing']
            with self.subTest(variant=variant),self.assertRaises(ValueError):self.generate()
        self.receipt=original
        (self.stage/'share/licenses/font.txt').unlink()
        with self.assertRaises(ValueError):self.generate()

    def test_archive_font_is_verified_and_cannot_escape_component_coverage(self):
        component=self.font()
        data=(self.stage/'share/font.woff2').read_bytes()
        (self.stage/'share/font.woff2').unlink()
        with zipfile.ZipFile(self.stage/'client.apk','w') as archive:
            archive.writestr('assets/font.woff2',data)
        component['delivery']='embedded'
        component['files']=[self.file('client.apk','assets/font.woff2',data)]
        self.generate()
        component['files'][0]['sha256']='4'*64
        with self.assertRaises(ValueError):self.generate()
        self.receipt['components']=[]
        with self.assertRaises(ValueError):self.generate()

    def test_archive_embedding_also_requires_matching_actual_build_inputs(self):
        component=self.font()
        data=(self.stage/'share/font.woff2').read_bytes()
        source=self.root/'original-font.woff2';source.write_bytes(data)
        (self.stage/'share/font.woff2').unlink()
        with zipfile.ZipFile(self.stage/'client.apk','w') as archive:
            archive.writestr('assets/font.woff2',data)
        component['delivery']='embedded'
        component['files']=[self.file('client.apk','assets/font.woff2',data)]
        component['embedding']={'kind':'compiled-resource',
            'source_files':[{'path':source.name,'sha256':sbom.digest(source)}],
            'target_files':component['files']}
        self.generate()
        source.write_bytes(b'changed original compilation input')
        with self.assertRaisesRegex(ValueError,'actual build input'):self.generate()

    def test_final_serialized_document_bound_is_enforced_before_publication(self):
        with patch.object(sbom,'MAX_JSON',1024):
            with self.assertRaisesRegex(ValueError,'final inventory document'):self.generate()
        self.assertFalse((self.stage/sbom.OUTPUT).exists())

    def test_actual_native_imports_are_runtime_prerequisites_and_require_a_graph_binding(self):
        shutil.copyfile('/usr/bin/true',self.stage/'bin/server')
        self.receipt['runtime_roots'][0]['files']=[self.file('bin/server')]
        document=self.generate()
        prerequisites=json.loads(next(item['value'] for item in document['metadata']['properties'] if item['name']=='runtime-prerequisites'))
        self.assertEqual(prerequisites[0]['format'],'ELF')
        self.assertIn('libc.so.6',prerequisites[0]['imports'])
        shutil.copyfile('/usr/bin/true',self.stage/'bin/unbound')
        with self.assertRaises(ValueError):self.generate()

    def test_actual_native_inspector_output_has_a_live_byte_bound(self):
        self.assertIn('libc.so.6',sbom.import_requirements(Path('/usr/bin/true'))['imports'])
        with patch.object(sbom,'MAX_JSON',128):
            with self.assertRaisesRegex(ValueError,'exceed'):sbom.import_requirements(Path('/usr/bin/true'))

    def test_compiled_resource_requires_actual_source_and_target_hashes(self):
        component=self.font()
        source=self.root/'source-font.woff2'
        shutil.copyfile(self.stage/'share/font.woff2',source)
        (self.stage/'share/font.woff2').unlink()
        component['delivery']='embedded'
        component['files']=[self.file('bin/server')]
        component['embedding']={'kind':'compiled-resource','source_files':[{'path':'source-font.woff2','sha256':sbom.digest(source)}],'target_files':component['files']}
        self.generate()
        source.write_bytes(b'changed compilation input')
        with self.assertRaises(ValueError):self.generate()

    def test_native_installation_aliases_resolve_only_to_delivered_files(self):
        alias=self.stage/'bin/alias'
        alias.symlink_to('/bin/server')
        with self.assertRaises(ValueError):self.generate()
        document=self.generate(package_symlinks=True)
        file=next(item for item in document['components'] if item['name']=='bin/alias')
        properties={item['name']:item['value'] for item in file['properties']}
        self.assertEqual(properties['delivered-referent'],'bin/server')
        alias.unlink();alias.symlink_to('server')
        self.generate(package_symlinks=True)
        for target in ('../../outside','/bin/missing','alias'):
            alias.unlink();alias.symlink_to(target)
            with self.subTest(target=target),self.assertRaises((ValueError,FileNotFoundError)):
                self.generate(package_symlinks=True)

    def test_embedded_native_imports_are_checked_against_the_final_archive(self):
        binary=Path('/usr/bin/true').read_bytes()
        with zipfile.ZipFile(self.stage/'client.apk','w') as archive:
            archive.writestr('lib/x86_64/libclient.so',binary)
        self.receipt['runtime_roots'][0]['files'].append(self.file('client.apk','lib/x86_64/libclient.so',binary))
        document=self.generate()
        prerequisites=json.loads(next(item['value'] for item in document['metadata']['properties'] if item['name']=='runtime-prerequisites'))
        record=next(item for item in prerequisites if item['path']=='client.apk')
        self.assertEqual(record['archive_entry'],'lib/x86_64/libclient.so')
        self.assertIn('libc.so.6',record['imports'])
        self.receipt['runtime_roots'][0]['files'].pop()
        with self.assertRaises(ValueError):self.generate()

    def test_native_inventory_uses_the_actual_installation_metadata_location(self):
        document=self.generate(output_relative='usr/share/doc/fixture/release-sbom.cdx.json')
        self.assertTrue((self.stage/'usr/share/doc/fixture/release-sbom.cdx.json').is_file())
        self.assertFalse((self.stage/sbom.OUTPUT).exists())
        self.assertEqual(document,self.generate(output_relative='usr/share/doc/fixture/release-sbom.cdx.json'))
        self.assertFalse(any(item.get('name')=='usr/share/doc/fixture/release-sbom.cdx.json' for item in document['components']))


if __name__=='__main__':unittest.main()
