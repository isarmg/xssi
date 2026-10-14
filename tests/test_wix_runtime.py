import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import wix_runtime


class WixRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='xssi-wix-source-')
        self.addCleanup(self.temporary.cleanup);self.root=Path(self.temporary.name).resolve(strict=True)
        self.cache=self.root/'cache';self.inputs=self.root/'inputs';self.inputs.mkdir()
        self.payload=self.root/'payload';self.payload.mkdir()
        self.packages={}
        self.runtime=b'actual reviewed fixture runtime\r\n\x1a bytes'
        for name in ('wixtoolset.sdk','wixtoolset.ui.wixext'):
            directory=self.cache/name/'4.0.6';(directory/'tools').mkdir(parents=True)
            binary=b'real cached fixture assembly '+name.encode()
            assembly='tools/current.dll'
            if name=='wixtoolset.ui.wixext':
                library=io.BytesIO()
                with zipfile.ZipFile(library,'w') as resource:
                    resource.writestr('wix-ir.json','{}')
                    resource.writestr('wix-ir/uica.dll',self.runtime)
                binary=b'MZ actual fixture resource prefix'+library.getvalue()+b'trailing fixture certificate'
                assembly='wixext4/WixToolset.UI.wixext.dll'
            (directory/assembly).parent.mkdir(parents=True,exist_ok=True)
            (directory/assembly).write_bytes(binary)
            metadata=f'<package><metadata><id>{name}</id><version>4.0.6</version><license type="expression">MS-RL</license><copyright>Actual upstream fixture copyright</copyright><repository commit="{wix_runtime.REVISION}"/></metadata></package>'
            archive=directory/(name+'.4.0.6.nupkg')
            with zipfile.ZipFile(archive,'w') as output:
                output.writestr(name+'.nuspec',metadata)
                output.writestr(assembly,binary)
            self.packages[name]=hashlib.sha256(archive.read_bytes()).hexdigest()
        source=io.BytesIO()
        with tarfile.open(fileobj=source,mode='w:gz') as archive:
            license_=b'Actual reviewed upstream fixture license text\n'
            item=tarfile.TarInfo('wix-'+wix_runtime.REVISION+'/LICENSE.TXT');item.size=len(license_)
            archive.addfile(item,io.BytesIO(license_))
        self.source=source.getvalue()
        self.owned=self.root/'maintenance.exe';self.owned.write_bytes(b'owned current helper')

    def extract(self,artifact,private,include_embedded=False):
        payload=private/'payload';(payload/'installer-binaries').mkdir(parents=True)
        streams={}
        for name,value in [('OwnedMaintenance.exe',self.owned.read_bytes()),('WixActualRuntime',self.runtime)]:
            relative='installer-binaries/'+name
            (payload/relative).write_bytes(value)
            streams[relative]={'sha256':hashlib.sha256(value).hexdigest(),'size':len(value),'mode':0o644}
        return payload,streams

    def generate(self):
        with patch.object(wix_runtime,'PACKAGES',self.packages), \
             patch.object(wix_runtime,'SOURCE_SHA',hashlib.sha256(self.source).hexdigest()), \
             patch.object(wix_runtime.native_package,'msi_payload',side_effect=self.extract):
            return wix_runtime.stage_runtime(self.payload,self.root/'actual.msi',self.inputs,
                cache=self.cache,owned_inputs=[self.owned],packages=tuple(self.packages),
                download=lambda url,maximum:self.source)

    def test_actual_selected_source_license_and_stream_hashes_are_bound(self):
        # The MSI extractor is tested on Windows; this fixture verifies source
        # archive/cache/license binding using physical inputs and output bytes.
        (self.root/'actual.msi').write_bytes(b'bootstrap container fixture')
        result=self.generate();self.assertEqual(len(result),1)
        component=result[0]
        self.assertEqual([item['path'] for item in component['files']],['installer-binaries/WixActualRuntime'])
        self.assertEqual(component['embedding']['target_files'],component['files'])
        self.assertEqual(len(component['embedding']['source_files']),3)
        authority=json.loads((self.inputs/'wix/runtime-origins.json').read_text())
        self.assertEqual(authority['streams'][0]['origins'][0]['resource_entry'],'wix-ir/uica.dll')
        self.assertEqual((self.payload/'share/THIRD_PARTY_WIX_LICENSE.txt').read_bytes(),b'Actual reviewed upstream fixture license text\n')
        self.assertIn(b'Actual upstream fixture copyright',(self.payload/'share/THIRD_PARTY_WIX_COPYRIGHTS.txt').read_bytes())

    def test_changed_restored_package_or_actual_build_assembly_is_rejected(self):
        (self.root/'actual.msi').write_bytes(b'bootstrap container fixture')
        package=self.cache/'wixtoolset.sdk/4.0.6'
        (package/'tools/current.dll').write_bytes(b'replaced build input')
        with self.assertRaisesRegex(ValueError,'actual WiX build assembly'):self.generate()
        self.assertFalse((self.payload/'share/THIRD_PARTY_WIX_LICENSE.txt').exists())

    def test_unknown_stream_cannot_borrow_the_verified_wix_source_or_license(self):
        (self.root/'actual.msi').write_bytes(b'bootstrap container fixture')
        self.runtime=b'unknown binary unrelated to the reviewed NuGet resources'
        with self.assertRaisesRegex(ValueError,'no exact reviewed WiX runtime resource origin'):
            self.generate()
        self.assertFalse((self.payload/'share/THIRD_PARTY_WIX_LICENSE.txt').exists())

    def test_changed_owned_stream_is_preserved_and_rejected(self):
        (self.root/'actual.msi').write_bytes(b'bootstrap container fixture')
        existing=self.payload/'installer-binaries/OwnedMaintenance.exe';existing.parent.mkdir()
        existing.write_bytes(b'unowned replacement')
        with self.assertRaisesRegex(ValueError,'existing owned MSI binary'):self.generate()
        self.assertEqual(existing.read_bytes(),b'unowned replacement')


if __name__=='__main__':unittest.main()
