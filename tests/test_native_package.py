import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import native_package
import release_sbom


class MsiExtractionLayoutTests(unittest.TestCase):
    """Exercise the retained WiX 4.0.6 output contract, not Windows installation."""
    def test_compressed_file_and_binary_use_their_exact_extracted_streams(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve(strict=True)
            def decompile(command):
                extraction=Path(command[command.index('-x')+1]);(extraction/'File').mkdir(parents=True,exist_ok=True)
                (extraction/'Binary').mkdir()
                (extraction/'File'/'ClientExecutable').write_bytes(b'actual compressed stream')
                (extraction/'Binary'/'Wix4UtilCA_X64').write_bytes(b'actual embedded stream')
                document=ET.Element('Wix');package=ET.SubElement(document,'Package')
                directory=ET.SubElement(package,'Directory',Id='INSTALLFOLDER',Name='Client')
                component=ET.SubElement(directory,'Component',Id='ServiceComponent')
                ET.SubElement(component,'File',Id='ClientExecutable',Name='client.exe',Source=r'SourceDir\File\ClientExecutable')
                ET.SubElement(package,'Binary',Id='Wix4UtilCA_X64',SourceFile=str(extraction/'Binary'/'Wix4UtilCA_X64'))
                ET.ElementTree(document).write(command[command.index('-o')+1])
            with patch.object(native_package,'tool',return_value='fixture-wix'),patch.object(native_package,'run',side_effect=decompile):
                payload,embedded=native_package.msi_payload(root/'input.msi',root/'work',include_embedded=True)
            self.assertEqual((payload/'client.exe').read_bytes(),b'actual compressed stream')
            self.assertEqual((payload/'installer-binaries/Wix4UtilCA_X64').read_bytes(),b'actual embedded stream')
            self.assertEqual(embedded['installer-binaries/Wix4UtilCA_X64']['sha256'],hashlib.sha256(b'actual embedded stream').hexdigest())

    def test_unknown_source_aliases_and_symlinked_streams_are_rejected(self):
        changes=['logical-source','physical-symlink','binary-source']
        for change in changes:
            with self.subTest(change=change),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary).resolve(strict=True)
                def decompile(command):
                    extraction=Path(command[command.index('-x')+1]);(extraction/'File').mkdir(parents=True,exist_ok=True)
                    (extraction/'Binary').mkdir()
                    stream=extraction/'File'/'ClientExecutable';stream.write_bytes(b'original')
                    if change=='physical-symlink':
                        outside=root/'outside';outside.write_bytes(b'original');stream.unlink()
                        try:stream.symlink_to(outside)
                        except OSError as error:self.skipTest('host cannot create file symlinks: '+str(error))
                    binary=extraction/'Binary'/'Util';binary.write_bytes(b'binary')
                    document=ET.Element('Wix');package=ET.SubElement(document,'Package')
                    directory=ET.SubElement(package,'Directory',Id='INSTALLFOLDER',Name='Client')
                    component=ET.SubElement(directory,'Component',Id='ServiceComponent')
                    ET.SubElement(component,'File',Id='ClientExecutable',Name='client.exe',Source='File/ClientExecutable' if change=='logical-source' else 'SourceDir/File/ClientExecutable')
                    ET.SubElement(package,'Binary',Id='Util',SourceFile=str(root/'outside-binary' if change=='binary-source' else binary))
                    ET.ElementTree(document).write(command[command.index('-o')+1])
                with patch.object(native_package,'tool',return_value='fixture-wix'),patch.object(native_package,'run',side_effect=decompile),self.assertRaises(ValueError):
                    native_package.msi_payload(root/'input.msi',root/'work')


@unittest.skipUnless(shutil.which('dpkg-deb'),'actual DEB extraction requires dpkg-deb')
class NativePackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='xssi-actual-deb-')
        self.addCleanup(self.temporary.cleanup);self.root=Path(self.temporary.name)
        self.payload=self.root/'payload';(self.payload/'usr/bin').mkdir(parents=True)
        (self.payload/'share').mkdir()
        control=self.payload/'DEBIAN';control.mkdir()
        (control/'control').write_text('Package: fixture\nVersion: 1.0.0\nArchitecture: amd64\nMaintainer: Fixture <fixture@example.invalid>\nDescription: actual temporary payload verification\n')
        shutil.copy2('/usr/bin/true',self.payload/'usr/bin/client')
        self.bom=self.root/'runtime.json'
        self.bom.write_text(json.dumps({'bomFormat':'CycloneDX','specVersion':'1.5','version':1,
            'metadata':{'component':{'type':'application','name':'fixture','version':'1.0.0','bom-ref':'runtime'}},
            'components':[],'dependencies':[{'ref':'runtime','dependsOn':[]}]}))
        self.receipt=self.root/'bindings.json'
        self.receipt.write_text(json.dumps({'format_version':1,'runtime_roots':[{'ref':'runtime','files':[
            {'path':'usr/bin/client','sha256':release_sbom.digest(self.payload/'usr/bin/client'),'archive_entry':None}]}],'components':[]}))
        self.inner=release_sbom.finalize(self.payload,[self.bom],self.receipt,'fixture','1.0.0','1'*40,'x86_64-unknown-linux-gnu')
        self.stage=self.root/'delivery';(self.stage/'share').mkdir(parents=True)
        shutil.copyfile(self.inner,self.stage/'share/inner.cdx.json')

    def build(self,label,change=None):
        build=self.root/label;shutil.copytree(self.payload,build,symlinks=True)
        if change:change(build)
        output=self.stage/(label+'.deb')
        subprocess.run(['dpkg-deb','--build','--root-owner-group',str(build),str(output)],
            check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=30)
        return output

    def test_final_actual_deb_payload_and_binary_hash_are_verified(self):
        artifact=self.build('actual')
        result=json.loads(native_package.materialize(self.stage,artifact,self.stage/'share/inner.cdx.json','deb').read_text())
        self.assertEqual(result['artifact']['sha256'],hashlib.sha256(artifact.read_bytes()).hexdigest())
        files={item['path']:item for item in result['installed_files']}
        self.assertEqual(files['usr/bin/client']['sha256'],release_sbom.digest(self.payload/'usr/bin/client'))
        self.assertEqual(files['share/release-sbom.cdx.json']['sha256'],release_sbom.digest(self.inner))
        self.assertEqual([item['path'] for item in result['embedded_files']],['DEBIAN/control'])
        outer=self.root/'outer-bindings.json'
        outer.write_text(json.dumps({'format_version':1,'runtime_roots':[],'components':[]}))
        receipt=self.stage/'share'/(artifact.name+'.native-receipt.json')
        final=release_sbom.finalize(self.stage,[],outer,'fixture','1.0.0','1'*40,
            'x86_64-unknown-linux-gnu',native_packages=[receipt])
        document=json.loads(final.read_text())
        self.assertTrue(any(item.get('type')=='file' and item['name']==artifact.name for item in document['components']))
        artifact.write_bytes(artifact.read_bytes()+b'tampered installer trailer')
        with self.assertRaises(ValueError):release_sbom.finalize(self.stage,[],outer,'fixture','1.0.0','1'*40,
            'x86_64-unknown-linux-gnu',native_packages=[receipt])

    def test_actual_package_tamper_omission_and_extra_files_are_rejected(self):
        changes=[lambda build:(build/'usr/bin/client').write_bytes(b'changed binary'),
                 lambda build:(build/'usr/bin/client').unlink(),
                 lambda build:(build/'usr/bin/undeclared').write_bytes(b'unrecorded payload'),
                 lambda build:(build/'share/release-sbom.cdx.json').write_bytes(b'changed inventory'),
                 lambda build:((build/'DEBIAN/postinst').write_bytes(b'#!/bin/sh\nexit 0\n'),(build/'DEBIAN/postinst').chmod(0o755)),
                 lambda build:(build/'usr/bin/client').chmod(0o700)]
        for index,change in enumerate(changes):
            artifact=self.build('tamper-'+str(index),change)
            with self.subTest(index=index),self.assertRaises(ValueError):
                native_package.materialize(self.stage,artifact,self.stage/'share/inner.cdx.json','deb')
            self.assertFalse((self.stage/'share'/(artifact.name+'.native-receipt.json')).exists())

    def test_actual_alias_target_is_verified_without_resolving_host_absolute_path(self):
        alias=self.payload/'usr/bin/alias';alias.symlink_to('/usr/bin/client')
        release_sbom.finalize(self.payload,[self.bom],self.receipt,'fixture','1.0.0','1'*40,
            'x86_64-unknown-linux-gnu',package_symlinks=True)
        shutil.copyfile(self.inner,self.stage/'share/inner.cdx.json')
        artifact=self.build('alias')
        result=json.loads(native_package.materialize(self.stage,artifact,self.stage/'share/inner.cdx.json','deb').read_text())
        self.assertEqual(result['installed_symlinks'][0]['target'],'/usr/bin/client')
        def escape(build):
            (build/'usr/bin/alias').unlink();(build/'usr/bin/alias').symlink_to('/tmp/outside')
        artifact=self.build('alias-escape',escape)
        with self.assertRaises(ValueError):native_package.materialize(self.stage,artifact,self.stage/'share/inner.cdx.json','deb')

    @unittest.skipUnless(shutil.which('nfpm'),'actual nFPM control metadata requires its fixed build tool')
    def test_actual_nfpm_passive_metadata_is_separate_and_cannot_allow_scripts(self):
        # nFPM generates passive control metadata after the inner inventory;
        # its md5sums includes that inventory and cannot be recursively inside it.
        shutil.rmtree(self.payload/'DEBIAN')
        release_sbom.finalize(self.payload,[self.bom],self.receipt,'fixture','1.0.0','1'*40,'x86_64-unknown-linux-gnu')
        shutil.copyfile(self.inner,self.stage/'share/inner.cdx.json')
        configuration=self.root/'nfpm.yaml'
        configuration.write_text('name: fixture\narch: amd64\nplatform: linux\nversion: 1.0.0\nmaintainer: Fixture <fixture@example.invalid>\ndescription: Actual temporary payload verification\ncontents:\n'+
            ''.join('  - src: '+json.dumps(str(self.payload/relative))+'\n    dst: /'+relative+'\n'
                    for relative in ('usr/bin/client','share/release-sbom.cdx.json')))
        artifact=self.stage/'actual-nfpm.deb'
        subprocess.run([shutil.which('nfpm'),'package','--config',str(configuration),'--packager','deb','--target',str(artifact)],
            check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=30)
        path=native_package.materialize(self.stage,artifact,self.stage/'share/inner.cdx.json','deb')
        data=json.loads(path.read_text())
        self.assertTrue(data['package_metadata'])
        self.assertTrue({item['path'] for item in data['package_metadata']}<= {'DEBIAN/control','DEBIAN/md5sums','DEBIAN/conffiles'})
        self.assertEqual(data['embedded_files'],[])
        outer=self.root/'outer-bindings.json';outer.write_text(json.dumps({'format_version':1,'runtime_roots':[],'components':[]}))
        release_sbom.finalize(self.stage,[],outer,'fixture','1.0.0','1'*40,'x86_64-unknown-linux-gnu',native_packages=[path])
        data['package_metadata'][0]['path']='DEBIAN/postinst';path.write_text(json.dumps(data))
        with self.assertRaises(ValueError):release_sbom.finalize(self.stage,[],outer,'fixture','1.0.0','1'*40,
            'x86_64-unknown-linux-gnu',native_packages=[path])

    @unittest.skipUnless(all(shutil.which(name) for name in ('nfpm','rpm','bsdtar')),
                         'actual RPM payload/header inspection requires its mature tools')
    def test_actual_rpm_script_bodies_and_interpreter_are_verified_without_fake_modes(self):
        shutil.rmtree(self.payload/'DEBIAN')
        scripts=self.payload/'installer-scripts';scripts.mkdir()
        for name in ('postinstall','preremove','postremove'):
            path=scripts/(name+'.sh');path.write_text('#!/bin/sh\n# actual fixture '+name+'\nexit 0\n');path.chmod(0o755)
        release_sbom.finalize(self.payload,[self.bom],self.receipt,'fixture','1.0.0','1'*40,'x86_64-unknown-linux-gnu')
        shutil.copyfile(self.inner,self.stage/'share/inner.cdx.json')
        configuration=self.root/'nfpm.yaml'
        configuration.write_text('name: fixture\narch: amd64\nplatform: linux\nversion: 1.0.0\nmaintainer: Fixture <fixture@example.invalid>\ndescription: Actual temporary payload verification\ncontents:\n'+
            ''.join('  - src: '+json.dumps(str(self.payload/relative))+'\n    dst: /'+relative+'\n'
                    for relative in ('usr/bin/client','share/release-sbom.cdx.json'))+
            'scripts:\n'+''.join('  '+name+': '+json.dumps(str(scripts/(name+'.sh')))+'\n' for name in ('postinstall','preremove','postremove')))
        artifact=self.stage/'actual-nfpm.rpm'
        subprocess.run([shutil.which('nfpm'),'package','--config',str(configuration),'--packager','rpm','--target',str(artifact)],
            check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=30)
        path=native_package.materialize(self.stage,artifact,self.stage/'share/inner.cdx.json','rpm')
        data=json.loads(path.read_text())
        self.assertEqual(len(data['embedded_files']),3)
        self.assertTrue(all(item['mode'] is None for item in data['embedded_files']))
        self.assertEqual({item['path']:item['sha256'] for item in data['embedded_files']},
            {'installer-scripts/'+name+'.sh':release_sbom.digest(scripts/(name+'.sh')) for name in ('postinstall','preremove','postremove')})
        # The actual nFPM header counts file contents, excluding CPIO framing.
        # Verify the mature direct-RPM path even for the mismatched header that
        # makes rpm2cpio 4.18 return a silent failure after copying its payload.
        declared=int(native_package.run([native_package.tool('rpm'),'--query','--package',
            '--queryformat','%{LONGARCHIVESIZE}',str(artifact)]))
        normalized=native_package.run([native_package.tool('bsdtar'),'-cf','-',
            '--format=newc','@'+str(artifact)])
        self.assertGreater(len(normalized),declared)
        limited=self.stage/'limited-nfpm.rpm';shutil.copyfile(artifact,limited)
        stream=native_package.bounded_dependency_file
        def bounded_stream(command,cwd,environment,destination,**options):
            return stream(command,cwd,environment,destination,maximum=32,timeout=30)
        with patch.object(native_package,'bounded_dependency_file',side_effect=bounded_stream),self.assertRaisesRegex(ValueError,'exceeds its bound'):
            native_package.materialize(self.stage,limited,self.stage/'share/inner.cdx.json','rpm')
        self.assertFalse((self.stage/'share'/(limited.name+'.native-receipt.json')).exists())
        outer=self.root/'outer-bindings.json';outer.write_text(json.dumps({'format_version':1,'runtime_roots':[],'components':[]}))
        release_sbom.finalize(self.stage,[],outer,'fixture','1.0.0','1'*40,'x86_64-unknown-linux-gnu',native_packages=[path])
        ordinary=data['installed_files'][0];ordinary['mode']=None;path.write_text(json.dumps(data))
        with self.assertRaises(ValueError):release_sbom.finalize(self.stage,[],outer,'fixture','1.0.0','1'*40,
            'x86_64-unknown-linux-gnu',native_packages=[path])
        (self.payload/'usr/bin/client').write_bytes(b'changed actual RPM executable')
        changed=self.stage/'changed-nfpm.rpm'
        subprocess.run([shutil.which('nfpm'),'package','--config',str(configuration),'--packager','rpm','--target',str(changed)],
            check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=30)
        with self.assertRaisesRegex(ValueError,'payload differs'):
            native_package.materialize(self.stage,changed,self.stage/'share/inner.cdx.json','rpm')
        self.assertFalse((self.stage/'share'/(changed.name+'.native-receipt.json')).exists())


if __name__=='__main__':unittest.main()
