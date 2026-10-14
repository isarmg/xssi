"""Actual archive/DEB fixtures; source records are public test identities."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import release_sbom
import static_native_receipt as native


class StaticNativeTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='xssi-static-native-')
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)
        self.stage=self.root/'stage'
        (self.stage/'bin').mkdir(parents=True)
        shutil.copyfile('/usr/bin/true',self.stage/'bin/client')
        self.targets=[{'path':'bin/client','sha256':release_sbom.digest(self.stage/'bin/client'),'archive_entry':None}]

    @unittest.skipUnless(shutil.which('cc') and shutil.which('ar'),'actual static object archives require their native tools')
    def test_actual_static_archive_license_and_final_binary_are_bound(self):
        source=self.root/'fixture.c';source.write_text('int fixture_function(void) { return 7; }\n')
        object_=self.root/'fixture.o'
        subprocess.run(['cc','-c',str(source),'-o',str(object_)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        archive=self.root/'libfixture.a'
        subprocess.run(['ar','rcs',str(archive),str(object_)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        component=native.component(self.stage,'fixture','Fixture runtime','1.0.0',
            {'url':'https://upstream.example.invalid/fixture.tar.xz','sha256':'a'*64},[archive],
            [('Original fixture license','LICENSE',b'Actual upstream fixture license and copyright.\n')],self.targets,'share')
        self.assertEqual(component['embedding']['input_root'],'stage')
        for item in component['embedding']['source_files']:
            self.assertEqual((self.stage/item['path']).read_bytes(),archive.read_bytes())
            self.assertEqual(release_sbom.digest(self.stage/item['path']),item['sha256'])
        receipt=self.root/'external.json';receipt.write_text(json.dumps({'format_version':1,'runtime_roots':[],'components':[component]}))
        bom=release_sbom.finalize(self.stage,[],receipt,'fixture','1.0.0','b'*40,'x86_64-unknown-linux-gnu')
        self.assertTrue(bom.is_file())
        (self.stage/component['embedding']['source_files'][0]['path']).write_bytes(b'changed build input')
        with self.assertRaisesRegex(ValueError,'actual build input'):
            release_sbom.finalize(self.stage,[],receipt,'fixture','1.0.0','b'*40,'x86_64-unknown-linux-gnu')

    def test_changed_final_target_and_unsupported_target_fail_before_sources(self):
        (self.stage/'bin/client').write_bytes(b'changed final binary')
        with self.assertRaisesRegex(ValueError,'final target changed'):
            native.record(self.root,self.stage,target_files=self.targets,build_input_root=self.root,target='x86_64-unknown-linux-gnu')

    def test_nonarchive_and_unknown_or_empty_original_notices_are_rejected(self):
        archive=self.root/'libfixture.a';archive.write_bytes(b'not a static library')
        with self.assertRaisesRegex(ValueError,'actual archive'):
            native.component(self.stage,'fixture','Fixture','1',{'url':'https://upstream.example.invalid/a','sha256':'a'*64},[archive],[],self.targets,'share')
        archive.write_bytes(b'!<arch>\n')
        with self.assertRaisesRegex(ValueError,'license is empty'):
            native.component(self.stage,'fixture','Fixture','1',{'url':'https://upstream.example.invalid/a','sha256':'a'*64},[archive],[('Actual','LICENSE',b'')],self.targets,'share')

    @unittest.skipIf(os.name=='nt','actual POSIX directory link')
    def test_native_material_cannot_write_through_a_parent_link(self):
        outside=self.root/'unrelated';outside.mkdir()
        protected=outside/'LICENSE';protected.write_bytes(b'original unrelated material')
        (self.stage/'share').symlink_to(outside,target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'physical directories'):
            native.put(self.stage,'share/LICENSE',b'native build evidence')
        self.assertEqual(protected.read_bytes(),b'original unrelated material')

    def test_configuration_gpl_nonfree_shared_and_duplicate_fields_fail_closed(self):
        path=self.root/'config.mak'
        path.write_text('CONFIG_STATIC=yes\nCONFIG_OPENSSL=yes\n')
        self.assertEqual(native.native_configuration(path)['CONFIG_OPENSSL'],'yes')
        for additional in ('CONFIG_GPL=yes\n','CONFIG_NONFREE=yes\n','CONFIG_SHARED=yes\n','CONFIG_STATIC=yes\n'):
            path.write_text('CONFIG_STATIC=yes\n'+additional)
            with self.subTest(additional=additional),self.assertRaises(ValueError):native.native_configuration(path)
        with self.assertRaises(ValueError):native.control('Package: a\nPackage: b\n')

    def test_configured_static_graph_rejects_hidden_link_arguments(self):
        prefix=self.root/'prefix'
        with mock.patch.object(native,'command',return_value='-L/tmp/fixture -lavformat -lavcodec -lavutil -lssl -lcrypto -lz -lzstd -latomic -lm -pthread'):
            libraries,_=native.link_closure(prefix,self.root,{},False)
            self.assertEqual(libraries,{'avformat','avcodec','avutil','ssl','crypto','z','zstd','atomic','m'})
        for flags in ('-lavformat -lavcodec','-lavformat -lavcodec -lavutil /tmp/private/hidden.a','-lavformat -lavcodec -lavutil -Wl,-rpath,/tmp/private'):
            with self.subTest(flags=flags),mock.patch.object(native,'command',return_value=flags),self.assertRaises(ValueError):
                native.link_closure(prefix,self.root,{},False)

    def windows_fixture(self):
        work=self.root/'native';prefix=work/'installed/x64-windows-static';vcpkg=work/'vcpkg'
        for path in (prefix/'lib',prefix/'share/ffmpeg',work/'installed/vcpkg/info',vcpkg/'ports/ffmpeg',vcpkg/'downloads',vcpkg/'buildtrees/ffmpeg/x64-windows-static-rel/ffbuild'):
            path.mkdir(parents=True,exist_ok=True)
        output=io.BytesIO()
        self.lgpl=b'Actual fixture LGPL copyright terms.\n';self.license_md=b'Actual fixture FFmpeg licensing document.\n'
        with tarfile.open(fileobj=output,mode='w:gz') as archive:
            for name,value in [('COPYING.LGPLv2.1',self.lgpl),('LICENSE.md',self.license_md)]:
                entry=tarfile.TarInfo('ffmpeg-n9.0.2/'+name);entry.size=len(value);archive.addfile(entry,io.BytesIO(value))
        raw=output.getvalue();checksum=hashlib.sha512(raw).hexdigest()
        (vcpkg/'downloads/ffmpeg-ffmpeg-n9.0.2.tar.gz').write_bytes(raw)
        (vcpkg/'ports/ffmpeg/portfile.cmake').write_text('vcpkg_from_github(\n REPO ffmpeg/ffmpeg\n REF "n${VERSION}"\n SHA512 '+checksum+'\n)\n')
        (vcpkg/'ports/ffmpeg/vcpkg.json').write_text(json.dumps({'version':'9.0.2','port-version':1}))
        self.generated_copyright=b'COPYING.LGPLv2.1:\n\n'+self.lgpl+b'\n\nLICENSE.md:\n\n'+self.license_md+b'\n\n'
        (prefix/'share/ffmpeg/copyright').write_bytes(self.generated_copyright)
        files=[]
        for name in sorted(native.FFMPEG_LIBRARIES):
            (prefix/'lib'/(name+'.lib')).write_bytes(b'!<arch>\n')
            files.append('x64-windows-static/lib/'+name+'.lib')
        (work/'installed/vcpkg/info/ffmpeg_9.0.2_x64-windows-static.list').write_text('\n'.join(files)+'\n')
        self.windows_config=vcpkg/'buildtrees/ffmpeg/x64-windows-static-rel/ffbuild/config.mak'
        self.windows_config.write_text('CONFIG_STATIC=yes\nCONFIG_SCHANNEL=yes\n')
        definitions={'ffmpeg':{'version':'9.0.2'},'vcpkg':{'revision':'e456309491fd875487bf02b8a0dca76c1b1b00cc','triplet':'x64-windows-static'}}
        return work,prefix,vcpkg,definitions

    def windows_command(self,arguments,cwd,env,maximum=4*1024*1024):
        if arguments[0]=='git':
            if 'rev-parse' in arguments:return 'e456309491fd875487bf02b8a0dca76c1b1b00cc\n'
            if 'diff' in arguments:return ''
            if 'remote' in arguments:return 'https://github.com/microsoft/vcpkg.git\n'
        if arguments[1:3]==['--libs','--static']:return '-lavformat -lavcodec -lavutil -lbcrypt -lsecur32 -lws2_32\n'
        raise AssertionError('unexpected provider operation: '+repr(arguments))

    def test_windows_source_copyright_config_and_only_runtime_graph_are_bound(self):
        # Public test archives and tool reports validate the Windows material
        # protocol here. These do not claim an MSVC or vcpkg build on Linux.
        work,_,_,definitions=self.windows_fixture()
        with mock.patch.object(native,'command',side_effect=self.windows_command):
            components=native.record_windows(work,self.stage,definitions,self.targets,'share',{})
        self.assertEqual([item['name'] for item in components],['FFmpeg','Microsoft Schannel'])
        media=components[0]
        self.assertEqual(media['dependencies'],[])
        self.assertIn('actual', (self.stage/media['licenses'][0]['path']).read_text().lower())
        original={item['path'].rsplit('/',1)[1]:(self.stage/item['path']).read_bytes() for item in media['licenses']}
        self.assertEqual(original,{'COPYING.LGPLv2.1':self.lgpl,'LICENSE.md':self.license_md,'copyright':self.generated_copyright})
        self.assertTrue(all(item['path'].startswith('share/build-inputs/native/') for item in media['embedding']['source_files']))
        self.assertNotIn('pkgconf',json.dumps(components))
        self.assertEqual(components[1]['delivery'],'platform')
        self.assertEqual(components[1]['files'],[])

    def test_windows_changed_archive_license_source_and_build_features_are_rejected(self):
        work,prefix,vcpkg,definitions=self.windows_fixture()
        with mock.patch.object(native,'command',side_effect=self.windows_command):
            (prefix/'share/ffmpeg/copyright').write_bytes(b'substitute license')
            with self.assertRaisesRegex(ValueError,'copyright differs'):
                native.record_windows(work,self.stage,definitions,self.targets,'share',{})
            (prefix/'share/ffmpeg/copyright').write_bytes(self.generated_copyright)
            self.windows_config.write_text('CONFIG_STATIC=yes\nCONFIG_SCHANNEL=yes\nCONFIG_OPENSSL=yes\n')
            with self.assertRaisesRegex(ValueError,'TLS or license'):
                native.record_windows(work,self.stage,definitions,self.targets,'share',{})
            self.windows_config.write_text('CONFIG_STATIC=yes\nCONFIG_SCHANNEL=yes\n')
            (vcpkg/'downloads/ffmpeg-ffmpeg-n9.0.2.tar.gz').write_bytes(b'changed source')
            with self.assertRaisesRegex(ValueError,'verified source download'):
                native.record_windows(work,self.stage,definitions,self.targets,'share',{})


@unittest.skipUnless(shutil.which('dpkg-deb'),'actual distro archives require dpkg-deb')
class DebianSourceTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='xssi-native-source-deb-')
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.payload=self.root/'payload'
        (self.payload/'DEBIAN').mkdir(parents=True)
        (self.payload/'DEBIAN/control').write_text('Package: fixture-dev\nVersion: 1.0.0\nArchitecture: amd64\nMaintainer: Fixture <fixture@example.invalid>\nDescription: Real native provenance fixture\n')
        (self.payload/'usr/lib').mkdir(parents=True)
        self.static=b'!<arch>\n'
        (self.payload/'usr/lib/libfixture.a').write_bytes(self.static)
        (self.payload/'usr/share/doc/fixture-dev').mkdir(parents=True)
        self.notice=b'Actual fixture upstream copyright and license.\n'
        (self.payload/'usr/share/doc/fixture-dev/copyright').write_bytes(self.notice)
        self.archive=self.root/'source.deb'
        subprocess.run(['dpkg-deb','--build','--root-owner-group',str(self.payload),str(self.archive)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        self.raw=self.archive.read_bytes();self.sha=hashlib.sha256(self.raw).hexdigest()
        self.url='https://deb.debian.org/debian/pool/fixture/fixture-dev_1.0.0_amd64.deb'
        self.original_command=native.command

    def command(self,arguments,cwd,env,maximum=4*1024*1024):
        if arguments[0]=='apt-cache':
            return 'Package: fixture-dev\nVersion: 1.0.0\nArchitecture: amd64\nSHA256: '+self.sha+'\n'
        if arguments[0]=='apt-get':
            return "'"+self.url+"' fixture-dev_1.0.0_amd64.deb "+str(len(self.raw))+' SHA256:'+self.sha+'\n'
        return self.original_command(arguments,cwd,env,maximum)

    def download(self,url,expected):
        if url!=self.url or hashlib.sha256(self.raw).hexdigest()!=expected:
            raise ValueError('actual fixture distribution checksum differs')
        return self.raw

    def select(self):
        selected=native.DebianSources(self.root,os.environ.copy())
        with mock.patch.object(native,'command',side_effect=self.command),mock.patch.object(native.frontend_receipt,'download',side_effect=self.download):
            return selected,selected.package(('fixture-dev:amd64','1.0.0','amd64'))

    def test_actual_deb_control_static_bytes_and_original_copyright_match(self):
        selected,package=self.select()
        self.assertEqual(package['source'],{'url':self.url,'sha256':self.sha})
        self.assertEqual(package['files']['usr/lib/libfixture.a'],self.static)
        source=selected.license_source(package)
        self.assertEqual(source['contents'],self.notice)
        self.assertEqual(source['distribution'],package['source'])
        self.assertEqual(source['package_path'],'usr/share/doc/fixture-dev/copyright')

    def test_distro_download_hash_identity_and_official_origin_are_all_enforced(self):
        self.raw+=b'changed distribution'
        with self.assertRaisesRegex(ValueError,'checksum differs'):self.select()
        self.raw=self.archive.read_bytes()
        self.url='https://unreviewed.example.invalid/package.deb'
        with self.assertRaisesRegex(ValueError,'official distro origin'):self.select()
        self.url='https://deb.debian.org/debian/pool/fixture/fixture-dev_1.0.0_amd64.deb'
        def changed(arguments,cwd,env,maximum=4*1024*1024):
            if arguments[0]=='dpkg-deb' and arguments[1]=='-f':return 'Package: different\nVersion: 1.0.0\nArchitecture: amd64\n'
            return self.command(arguments,cwd,env,maximum)
        source=native.DebianSources(self.root,os.environ.copy())
        with mock.patch.object(native,'command',side_effect=changed),mock.patch.object(native.frontend_receipt,'download',side_effect=self.download):
            with self.assertRaisesRegex(ValueError,'archive identity differs'):
                source.package(('fixture-dev:amd64','1.0.0','amd64'))


if __name__=='__main__':unittest.main()
