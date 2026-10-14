import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import sqlite_receipt as native

class SQLiteReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name);self.source=self.root/'source';self.stage=self.root/'stage'
        self.vendor=self.source/'xssi-vendor/libsqlite3-sys-0.37.0';(self.vendor/'sqlite3').mkdir(parents=True)
        (self.stage/'share').mkdir(parents=True);(self.stage/'libexec').mkdir();(self.stage/'libexec/setup').write_bytes(b'actual fixture executable')
        self.c=self.vendor/'sqlite3/sqlite3.c';self.header=self.vendor/'sqlite3/sqlite3.h';self.c.write_text('amalgamation fixture source')
        self.header.write_text('/*\n** The author disclaims copyright to this source code.\n*************************************************************************\n#define SQLITE_VERSION "3.51.3"\n')
        (self.vendor/'.cargo_vcs_info.json').write_text(json.dumps({'git':{'sha1':'a'*40},'path_in_vcs':'libsqlite3-sys'}))
        (self.vendor/'.cargo-checksum.json').write_text(json.dumps({'package':'b'*64,'files':{'sqlite3/sqlite3.c':native.sha(self.c),'sqlite3/sqlite3.h':native.sha(self.header)}}))
        (self.source/'Cargo.lock').write_text('version=4\n[[package]]\nname="libsqlite3-sys"\nversion="0.37.0"\nsource="registry+https://github.com/rust-lang/crates.io-index"\nchecksum="'+'b'*64+'"\n')
        (self.source/'xssi-cargo-metadata.json').write_text(json.dumps({'packages':[{'name':'libsqlite3-sys','id':'sqlite','version':'0.37.0','source':'registry+https://github.com/rust-lang/crates.io-index','manifest_path':str(self.vendor/'Cargo.toml')}],'resolve':{'nodes':[{'id':'sqlite','features':['bundled']}]}}))
        (self.stage/'share/external-components.json').write_text(json.dumps({'format_version':1,'runtime_roots':[],'components':[]}))
        self.bom=self.stage/'share/setup-sbom.cdx.json';self.bom.write_text(json.dumps({'metadata':{'component':{'bom-ref':'setup'}}}))
    def test_actual_inputs_upstream_notice_archive_checksum_and_target_are_bound(self):
        component=native.record(self.source,self.stage,'setup','libexec/setup')
        native.merge(self.stage,[component],[(self.bom,'libexec/setup')])
        receipt=json.loads((self.stage/'share/external-components.json').read_text())
        self.assertEqual(len(receipt['components']),1);self.assertEqual(component['version'],'3.51.3')
        self.assertEqual(component['embedding']['target_files'],component['files'])
        evidence=json.loads((self.stage/'share/build-inputs/setup-sqlite/source.json').read_text())
        self.assertEqual(evidence['crate']['archive_sha256'],'b'*64)
        self.assertIn('disclaims copyright',(self.stage/component['licenses'][0]['path']).read_text())
        self.assertEqual((self.stage/component['embedding']['source_files'][0]['path']).read_bytes(),self.c.read_bytes())
    def test_changed_source_and_unbundled_library_are_rejected_before_receipt(self):
        self.c.write_text('changed source')
        with self.assertRaisesRegex(ValueError,'verified vendor source'):native.record(self.source,self.stage,'setup','libexec/setup')
        metadata=json.loads((self.source/'xssi-cargo-metadata.json').read_text());metadata['resolve']['nodes'][0]['features']=[]
        (self.source/'xssi-cargo-metadata.json').write_text(json.dumps(metadata))
        with self.assertRaisesRegex(ValueError,'actual bundled'):native.record(self.source,self.stage,'setup','libexec/setup')
    def test_missing_or_wrong_upstream_notice_is_not_replaced_by_generic_text(self):
        self.header.write_text('#define SQLITE_VERSION "3.51.3"\n')
        checksum=json.loads((self.vendor/'.cargo-checksum.json').read_text());checksum['files']['sqlite3/sqlite3.h']=native.sha(self.header);(self.vendor/'.cargo-checksum.json').write_text(json.dumps(checksum))
        with self.assertRaisesRegex(ValueError,'notice is missing'):native.record(self.source,self.stage,'setup','libexec/setup')

    def test_actual_archive_entry_and_platform_resource_directory_are_bound(self):
        artifact=self.stage/'application.apk'
        with zipfile.ZipFile(artifact,'w') as archive:
            archive.writestr('lib/arm64-v8a/libapplication.so',b'actual native entry fixture')
        binding={'path':'application.apk','archive_entry':'lib/arm64-v8a/libapplication.so',
                 'sha256':hashlib.sha256(b'actual native entry fixture').hexdigest()}
        component=native.record(self.source,self.stage,'runtime',files=[binding],
                                inventory_relative='Application/Resources/share')
        self.assertEqual(component['files'],[binding])
        self.assertTrue(all(item['path'].startswith('Application/Resources/share/')
                            for item in component['embedding']['source_files']))
        self.assertTrue((self.stage/component['licenses'][0]['path']).is_file())
        for item in component['embedding']['source_files']:
            self.assertEqual(native.sha(self.stage/item['path']),item['sha256'])

    def test_large_real_target_does_not_use_the_source_document_limit(self):
        target=self.stage/'libexec/setup'
        with target.open('wb') as output:
            output.write(b'payload')
            output.truncate(33*1024*1024)
        component=native.record(self.source,self.stage,'setup','libexec/setup')
        self.assertEqual(component['files'][0]['sha256'],native.sha(target))

if __name__=='__main__':unittest.main()
