"""Real archive/hash fixtures for the rendered frontend inventory boundary.

The JavaScript, font, and Server bytes are opaque fixture data, not claims of a
compiled product. Network requests alone are replaced; tar, lock integrity,
source hashes, licenses, graphs, and final payload hashes use production code.
"""
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import frontend_receipt


def digest(value):
    return hashlib.sha256(value).hexdigest()


def tarball(entries):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode='w:gz') as archive:
        for path, value in sorted(entries.items()):
            member = tarfile.TarInfo('package/' + path)
            member.size = len(value)
            archive.addfile(member, io.BytesIO(value))
    return result.getvalue()


class FrontendReceiptTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='xssi-frontend-receipt-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / 'source'
        self.web = self.source / 'web'
        self.stage = self.root / 'stage'
        self.web.mkdir(parents=True)
        (self.stage / 'bin').mkdir(parents=True)
        (self.stage / 'share').mkdir()
        (self.source / 'xcss-web-build.json').write_text(json.dumps({'web': {'directory': 'web'}}))
        (self.stage / 'bin/server').write_bytes(b'opaque Server payload fixture\n')
        self.remote = {}
        self.lock = {'lockfileVersion': 3, 'packages': {}}
        self.runtime_code = b'export const runtime = 42;\n'
        self.add_package('node_modules/runtime-lib', 'runtime-lib', '1.2.3', {'index.js': self.runtime_code})
        self.font = b'opaque complete font fixture\n'
        self.latin = b'opaque upstream Latin distribution fixture\n'
        self.cjk = b'opaque upstream CJK distribution fixture\n'
        self.latin_url = 'https://upstream.example.invalid/font-latin.zip'
        self.cjk_url = 'https://upstream.example.invalid/download/v1.0.0/font-cjk.zip'
        self.remote[self.latin_url] = self.latin
        self.remote[self.cjk_url] = self.cjk
        licenses = {name: b'Actual upstream fixture OFL terms and copyright.\n' for name in ('OFL.txt', 'CJK-LICENSE.txt', 'NORMAL-LICENSE.txt')}
        provenance = {
            'source_commit': 'a' * 40, 'source_version': 'v1.0.0',
            'latin': {'url': self.latin_url, 'sha256': digest(self.latin)},
            'cjk': {'upstream': 'https://upstream.example.invalid/tag/v1.0.0', 'archive': 'font-cjk.zip', 'sha256': digest(self.cjk)},
            'assets': {'Complete-Regular.woff2': digest(self.font), **{name: digest(value) for name, value in licenses.items()}},
        }
        self.add_package('node_modules/@xcss/web', '@xcss/web', '1.0.0', {
            'dist/web-fonts/Complete-Regular.woff2': self.font,
            'dist/web-fonts/provenance.json': json.dumps(provenance).encode(),
            **{'dist/web-fonts/' + name: value for name, value in licenses.items()},
        })
        self.entry = b'import {runtime} from "runtime-lib"; console.log(runtime);\n'
        (self.web / 'entry.js').write_bytes(self.entry)
        self.outputs = {'assets/app.js': b'console.log(42);\n', 'assets/Complete-Regular.woff2': self.font}
        for path, value in self.outputs.items():
            target = self.web / 'dist' / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(value)
        self.receipt = {
            'format_version': 1, 'distribution': 'dist',
            'modules': [
                {'path': 'entry.js', 'sha256': digest(self.entry), 'files': ['assets/app.js'], 'imports': [1]},
                {'path': 'node_modules/runtime-lib/index.js', 'sha256': digest(self.runtime_code), 'files': ['assets/app.js'], 'imports': []},
            ],
            'outputs': [{'path': path, 'sha256': digest(value)} for path, value in sorted(self.outputs.items())],
        }
        self.compiled = {'format': 'web-assets-v1', 'files': copy.deepcopy(self.receipt['outputs'])}
        self.metadata = self.root / 'frontend.json'

    def add_package(self, path, name, version, files, license_id='MIT', license_filename='LICENSE'):
        package = {'name': name, 'version': version, 'license': license_id}
        contents = {'package.json': json.dumps(package).encode(), license_filename: b'Actual upstream fixture MIT license and copyright.\n', **files}
        archive = tarball(contents)
        url = 'https://registry.example.invalid/' + name.replace('/', '-') + '-' + version + '.tgz'
        self.remote[url] = archive
        self.lock['packages'][path] = {'version': version, 'resolved': url, 'integrity': 'sha512-' + base64.b64encode(hashlib.sha512(archive).digest()).decode()}
        for relative, body in contents.items():
            destination = self.web / path / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(body)

    def fetch(self, url, expected=None):
        value = self.remote[url]
        if expected is not None and digest(value) != expected:
            raise ValueError('fixture upstream SHA differs')
        return value

    def vendor_package(self, owner, destination, mapping=None):
        package=json.loads((self.web/owner/'package.json').read_text())
        if mapping is None:
            mapping={path.relative_to(self.web/owner).as_posix():path.relative_to(self.web/owner).as_posix()
                     for path in (self.web/owner).rglob('*') if path.is_file()}
        files={}
        for name,original in mapping.items():
            content=(self.web/owner/original).read_bytes()
            target=self.web/destination/name
            target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(content)
            files[name]=digest(content)
        source={'format':1,'package':package['name'],'version':package['version'],'license':package['license'],
                'origin':self.lock['packages'][owner]['resolved'],'files':files,
                'npm':{**package,**{key:self.lock['packages'][owner][key] for key in ('resolved','integrity')},'archive_files':mapping}}
        (self.web/destination/'SOURCE.json').write_text(json.dumps(source))
        return source

    def native_vendors(self):
        self.vendor_package('node_modules/runtime-lib','vendor/runtime',{'runtime.mjs':'index.js','LICENSE':'LICENSE'})
        font_owner='node_modules/@xcss/web'
        mapping={path.relative_to(self.web/font_owner).as_posix().removeprefix('dist/'):path.relative_to(self.web/font_owner).as_posix()
                 for path in (self.web/font_owner).rglob('*') if path.is_file() and path.name!='package.json'}
        self.vendor_package(font_owner,'vendor/xcss',mapping)
        self.receipt['modules'][1]['path']='vendor/runtime/runtime.mjs'
        shutil.rmtree(self.web/'node_modules')

    def git_csr_runtime(self):
        owner='xcss-web/vendor/xcss-web'
        revision='a'*40
        files={'Cargo.toml':b'[package]\nname = "xcss-web"\nversion = "1.0.0"\nlicense = "Apache-2.0"\n',
               'LICENSE':b'Original Apache-2.0 fixture grant and copyright.\n',
               'startup.js':self.runtime_code}
        source={'format':1,'package':'xcss-web','version':'1.0.0','origin':'https://github.com/isarmg/xcss',
                'base_revision':revision,'source_directory':'web/xcss-web',
                'files':{name:digest(body) for name,body in files.items()}}
        for name,body in files.items():
            path=self.web/owner/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(body)
        (self.web/owner/'SOURCE.json').write_text(json.dumps(source))
        archive=io.BytesIO()
        with tarfile.open(fileobj=archive,mode='w:gz') as output:
            for name,body in files.items():
                path='LICENSE' if name=='LICENSE' else 'web/xcss-web/'+name
                item=tarfile.TarInfo('xcss-'+revision+'/'+path);item.size=len(body)
                output.addfile(item,io.BytesIO(body))
        url='https://codeload.github.com/isarmg/xcss/tar.gz/'+revision
        self.remote[url]=archive.getvalue()
        self.receipt['modules'][1]['path']=owner+'/startup.js'
        self.receipt['modules'][1]['sha256']=digest(self.runtime_code)
        return owner,source,url

    def generate(self):
        (self.web / 'package-lock.json').write_text(json.dumps(self.lock))
        self.metadata.write_text(json.dumps(self.receipt))
        (self.stage / 'share/web-assets.json').write_text(json.dumps(self.compiled))
        (self.stage / 'share/external-components.json').write_text(json.dumps({'format_version': 1, 'runtime_roots': [], 'components': []}))
        with mock.patch.object(frontend_receipt, 'download', side_effect=self.fetch):
            return frontend_receipt.generate(self.source, self.stage, self.metadata, 'bin/server')

    def test_actual_tar_lock_source_license_and_payload_binding(self):
        components = self.generate()
        runtime = next(item for item in components if item['name'] == 'runtime-lib')
        self.assertEqual(runtime['files'][0]['sha256'], digest((self.stage / 'bin/server').read_bytes()))
        self.assertEqual(runtime['embedding']['source_files'], [{'path': 'web/node_modules/runtime-lib/index.js', 'sha256': digest(self.runtime_code)}])
        self.assertEqual((self.stage / runtime['licenses'][0]['path']).read_bytes(), b'Actual upstream fixture MIT license and copyright.\n')
        self.assertIn('Maple Mono complete fonts', [item['name'] for item in components])
        font=next(item for item in components if item['name']=='Maple Mono complete fonts')
        cjk=next(item for item in components if item['name']=='Maple Mono CJK font inputs')
        self.assertEqual(cjk['source'],{'url':self.cjk_url,'sha256':digest(self.cjk)})
        self.assertEqual(font['dependencies'],[cjk['ref']])
        self.assertTrue((self.stage/'share/build-inputs/frontend/font-provenance.json').is_file())

    def test_vendored_runtime_and_fonts_need_no_installed_npm_tree(self):
        self.native_vendors()
        self.lock={'lockfileVersion':3,'packages':{}}
        components=self.generate()
        runtime=next(item for item in components if item['name']=='runtime-lib')
        self.assertEqual(runtime['embedding']['source_files'],[{'path':'web/vendor/runtime/runtime.mjs','sha256':digest(self.runtime_code)}])
        font=next(item for item in components if item['name']=='Maple Mono complete fonts')
        self.assertTrue(all(item['path'].startswith('web/vendor/xcss/') for item in font['embedding']['source_files']))

    def test_git_csr_startup_binds_original_source_license_and_server(self):
        owner,source,url=self.git_csr_runtime()
        component=next(item for item in self.generate() if item['name']=='xcss-web')
        self.assertEqual(component['ref'],'urn:rendered-git:xcss-web:1.0.0')
        self.assertEqual(component['source'],{'url':url,'sha256':digest(self.remote[url])})
        self.assertEqual(component['embedding']['source_files'],[{'path':'web/'+owner+'/startup.js','sha256':digest(self.runtime_code)}])
        self.assertEqual(component['files'][0]['sha256'],digest((self.stage/'bin/server').read_bytes()))
        self.assertEqual((self.stage/component['licenses'][0]['path']).read_bytes(),(self.web/owner/'LICENSE').read_bytes())
        receipt_path=self.stage/'share/external-components.json'
        receipt=json.loads(receipt_path.read_text())
        receipt['runtime_roots']=[{'ref':'fixture','files':component['files']}]
        receipt_path.write_text(json.dumps(receipt))
        bom=self.root/'runtime.json'
        bom.write_text(json.dumps({'bomFormat':'CycloneDX','specVersion':'1.5','version':1,
            'metadata':{'component':{'type':'application','name':'fixture','version':'1.0.0','bom-ref':'fixture'}},
            'components':[],'dependencies':[{'ref':'fixture','dependsOn':[]}]}))
        def finalize():
            return frontend_receipt.sbom.finalize(self.stage,[bom],receipt_path,'fixture','1.0.0','1'*40,'fixture-target',self.source)
        document=json.loads(finalize().read_text())
        rendered=next(item for item in document['components'] if item['bom-ref']==component['ref'])
        self.assertEqual(rendered['externalReferences'],[{'type':'distribution','url':url,
            'hashes':[{'alg':'SHA-256','content':digest(self.remote[url])}]}])
        release=document['metadata']['component']['bom-ref']
        self.assertIn(component['ref'],next(item for item in document['dependencies'] if item['ref']==release)['dependsOn'])
        (self.web/owner/'startup.js').write_bytes(b'changed after receipt generation\n')
        with self.assertRaisesRegex(ValueError,'actual build input'):finalize()

    def test_git_csr_vendor_rejects_wrong_schema_revision_and_package_identity(self):
        owner,source,url=self.git_csr_runtime()
        self.remote['https://codeload.github.com/isarmg/xcss/tar.gz/'+'b'*40]=self.remote[url]
        for key,value in [('extra',True),('origin','https://github.com/another/xcss'),
                          ('base_revision','main'),('base_revision','b'*40),('source_directory','web/other'),
                          ('package','another-package'),('version','2.0.0')]:
            with self.subTest(field=key):
                changed={**source,key:value}
                (self.web/owner/'SOURCE.json').write_text(json.dumps(changed))
                with self.assertRaises(ValueError):self.generate()

    def test_git_csr_vendor_cannot_relabel_changed_bytes_or_hide_local_files(self):
        owner,source,url=self.git_csr_runtime()
        changed=b'export const injected = true;\n'
        (self.web/owner/'startup.js').write_bytes(changed)
        source['files']['startup.js']=digest(changed)
        (self.web/owner/'SOURCE.json').write_text(json.dumps(source))
        self.receipt['modules'][1]['sha256']=digest(changed)
        with self.assertRaisesRegex(ValueError,'original source revision'):self.generate()
        self.git_csr_runtime()
        (self.web/owner/'unlisted.js').write_bytes(changed)
        with self.assertRaisesRegex(ValueError,'exact source inventory'):self.generate()

    def test_vendor_inventory_cannot_relabel_changed_original_bytes(self):
        self.native_vendors()
        changed=b'export const runtime = 1000;\n'
        (self.web/'vendor/runtime/runtime.mjs').write_bytes(changed)
        source_path=self.web/'vendor/runtime/SOURCE.json'
        source=json.loads(source_path.read_text());source['files']['runtime.mjs']=digest(changed)
        source_path.write_text(json.dumps(source))
        self.receipt['modules'][1]['sha256']=digest(changed)
        with self.assertRaisesRegex(ValueError,'original npm distribution'):
            self.generate()

    def test_vendor_unlisted_file_and_escaping_archive_map_are_rejected(self):
        self.native_vendors()
        (self.web/'vendor/runtime/extra.js').write_text('extra')
        with self.assertRaisesRegex(ValueError,'exact source inventory'):
            self.generate()
        (self.web/'vendor/runtime/extra.js').unlink()
        source_path=self.web/'vendor/runtime/SOURCE.json'
        source=json.loads(source_path.read_text());source['npm']['archive_files']['runtime.mjs']='../index.js'
        source_path.write_text(json.dumps(source))
        with self.assertRaisesRegex(ValueError,'canonical and relative'):
            self.generate()

    def test_vendor_cannot_hide_files_under_release_control_names(self):
        self.native_vendors()
        for name in ('share/package.json','share/package.sha256','share/release-sbom.cdx.json'):
            with self.subTest(name=name):
                extra=self.web/'vendor/runtime'/name
                extra.parent.mkdir(parents=True,exist_ok=True);extra.write_text('unlisted')
                with self.assertRaisesRegex(ValueError,'exact source inventory'):
                    self.generate()
                extra.unlink()

    def test_two_vendored_font_providers_are_ambiguous(self):
        self.native_vendors()
        shutil.copytree(self.web/'vendor/xcss',self.web/'web/vendor/xcss')
        with self.assertRaisesRegex(ValueError,'ambiguous'):
            self.generate()

    def test_vendor_cannot_skip_an_original_file_mapping_or_archive_integrity(self):
        self.native_vendors()
        source_path=self.web/'vendor/runtime/SOURCE.json';source=json.loads(source_path.read_text())
        missing=copy.deepcopy(source);missing['npm']['archive_files'].pop('LICENSE')
        source_path.write_text(json.dumps(missing))
        with self.assertRaisesRegex(ValueError,'map every source'):
            self.generate()
        source['npm']['integrity']='sha512-'+base64.b64encode(bytes(64)).decode()
        source_path.write_text(json.dumps(source))
        with self.assertRaisesRegex(ValueError,'lock integrity'):
            self.generate()

    def test_missing_entire_rendered_module_graph_is_rejected(self):
        self.receipt['modules'] = []
        with self.assertRaises(ValueError):
            self.generate()

    def test_reviewed_dual_license_keeps_declaration_and_original_documents(self):
        text = b'Actual upstream fixture Apache-2.0 license and copyright.\n'
        alternative = b'Actual upstream fixture MPL-2.0 alternative license.\n'
        self.add_package('node_modules/runtime-lib', 'runtime-lib', '1.2.3',
                         {'index.js': self.runtime_code, 'LICENSE': text, 'LICENSE-MPL': alternative},
                         license_id='(MPL-2.0 OR Apache-2.0)')
        runtime = next(item for item in self.generate() if item['name'] == 'runtime-lib')
        self.assertEqual(len(runtime['licenses']), 2)
        self.assertTrue(all(item['name'] == '(MPL-2.0 OR Apache-2.0)' for item in runtime['licenses']))
        self.assertEqual(runtime['licenses'][0]['sha256'], digest(text))
        self.assertEqual((self.stage / runtime['licenses'][0]['path']).read_bytes(), text)
        self.assertEqual((self.stage / runtime['licenses'][1]['path']).read_bytes(), alternative)
        self.assertEqual(runtime['licenses'][1]['sha256'], digest(alternative))

    def test_unreviewed_license_expressions_do_not_gain_an_implicit_choice(self):
        for license_id in ('MPL-2.0', '(MPL-2.0 AND Apache-2.0)',
                           '(Unreviewed OR Apache-2.0)', 'LicenseRef-Unreviewed', '', None):
            with self.subTest(license_id=license_id):
                self.add_package('node_modules/runtime-lib', 'runtime-lib', '1.2.3',
                                 {'index.js': self.runtime_code}, license_id=license_id)
                with self.assertRaisesRegex(ValueError, 'runtime-lib requires an explicitly reviewed'):
                    self.generate()

    def test_dual_license_still_requires_original_nonempty_text(self):
        self.add_package('node_modules/runtime-lib', 'runtime-lib', '1.2.3',
                         {'index.js': self.runtime_code, 'LICENSE': b''},
                         license_id='(MPL-2.0 OR Apache-2.0)')
        with self.assertRaisesRegex(ValueError, 'upstream runtime notice is empty'):
            self.generate()

    def test_local_license_metadata_cannot_replace_original_upstream_terms(self):
        path = self.web / 'node_modules/runtime-lib/package.json'
        package = json.loads(path.read_text())
        package['license'] = '(MPL-2.0 OR Apache-2.0)'
        path.write_text(json.dumps(package))
        with self.assertRaisesRegex(ValueError, 'license metadata differs from its original distribution'):
            self.generate()

    def test_original_root_license_suffixes_are_preserved(self):
        for filename in ('LICENSE-MIT.txt', 'LICENSE_MIT', 'COPYING.md'):
            with self.subTest(filename=filename):
                self.add_package('node_modules/runtime-lib', 'runtime-lib', '1.2.3',
                                 {'index.js': self.runtime_code}, license_filename=filename)
                runtime = next(item for item in self.generate() if item['name'] == 'runtime-lib')
                self.assertEqual([item['path'] for item in runtime['licenses']],
                                 ['share/licenses/frontend/runtime-lib/' + filename])
                original = b'Actual upstream fixture MIT license and copyright.\n'
                self.assertEqual((self.stage / runtime['licenses'][0]['path']).read_bytes(), original)
                self.assertEqual(runtime['licenses'][0]['sha256'], digest(original))

    def test_arbitrary_filename_does_not_replace_an_original_license(self):
        self.add_package('node_modules/runtime-lib', 'runtime-lib', '1.2.3',
                         {'index.js': self.runtime_code}, license_filename='NOTLICENSE.txt')
        with self.assertRaisesRegex(ValueError, 'runtime-lib has no original upstream license text'):
            self.generate()

    def test_partial_output_inventory_cannot_hide_compiled_javascript(self):
        self.receipt['outputs'] = [item for item in self.receipt['outputs'] if item['path'].endswith('.woff2')]
        self.receipt['modules'] = []
        with self.assertRaises(ValueError):
            self.generate()

    def test_rendered_module_must_be_bound_to_an_actual_output(self):
        self.receipt['modules'][1]['files'] = []
        with self.assertRaises(ValueError):
            self.generate()

    def test_compiled_resource_names_must_match_not_only_hash_values(self):
        self.compiled['files'][0]['path'] = 'unrelated/renamed-resource.js'
        with self.assertRaises(ValueError):
            self.generate()

    def test_runtime_dependency_edges_survive_intermediate_local_modules(self):
        second = b'export const second = 7;\n'
        self.add_package('node_modules/second-runtime', 'second-runtime', '2.0.0', {'index.js': second})
        bridge = b'export {second} from "second-runtime";\n'
        (self.web / 'bridge.js').write_bytes(bridge)
        self.receipt['modules'][1]['imports'] = [2]
        self.receipt['modules'].extend([
            {'path': 'bridge.js', 'sha256': digest(bridge), 'files': ['assets/app.js'], 'imports': [3]},
            {'path': 'node_modules/second-runtime/index.js', 'sha256': digest(second), 'files': ['assets/app.js'], 'imports': []},
        ])
        components = self.generate()
        first = next(item for item in components if item['name'] == 'runtime-lib')
        other = next(item for item in components if item['name'] == 'second-runtime')
        self.assertIn(other['ref'], first['dependencies'])

    def test_changed_npm_source_or_distribution_integrity_is_rejected(self):
        (self.web / 'node_modules/runtime-lib/index.js').write_bytes(b'changed local source')
        with self.assertRaisesRegex(ValueError, 'rendered input changed'):
            self.generate()
        (self.web / 'node_modules/runtime-lib/index.js').write_bytes(self.runtime_code)
        url = self.lock['packages']['node_modules/runtime-lib']['resolved']
        self.remote[url] = tarball({'package.json': b'{}'})
        with self.assertRaisesRegex(ValueError, 'lock integrity'):
            self.generate()

    def test_directory_only_archive_cannot_bypass_the_extraction_entry_bound(self):
        contents=io.BytesIO()
        with tarfile.open(fileobj=contents,mode='w:gz') as archive:
            for number in range(5):
                item=tarfile.TarInfo('package/directory-'+str(number));item.type=tarfile.DIRTYPE
                archive.addfile(item)
        raw=contents.getvalue();entry=self.lock['packages']['node_modules/runtime-lib']
        self.remote[entry['resolved']]=raw
        entry['integrity']='sha512-'+base64.b64encode(hashlib.sha512(raw).digest()).decode()
        with mock.patch.object(frontend_receipt,'MAX_MODULES',4),self.assertRaisesRegex(ValueError,'entry count'):
            self.generate()

    def generated_runtime(self):
        self.add_package('node_modules/rolldown','rolldown','1.2.3',{'dist/index.js':b'actual runtime generator fixture\n'})
        code='var generatedRuntime = Object.create;\n'
        self.receipt['modules'].append({'path':None,'sha256':digest(code.encode()),'code':code,
            'virtual_id':'\0rolldown/runtime.js','files':['assets/app.js'],'imports':[],
            'generated_runtime':{'provider':'rolldown','version':'1.2.3','module':'\0rolldown/runtime.js'}})
        return code

    def test_actual_generated_js_and_provider_license_are_delivered_without_native_builder(self):
        code=self.generated_runtime()
        components=self.generate()
        generated=next(item for item in components if item['name']=='rolldown generated runtime')
        self.assertEqual(generated['embedding']['input_root'],'stage')
        self.assertEqual(generated['source']['url'],self.lock['packages']['node_modules/rolldown']['resolved'])
        source=generated['embedding']['source_files'][0]
        self.assertEqual(source['path'],'share/build-inputs/frontend/rolldown-runtime.js')
        self.assertEqual((self.stage/source['path']).read_text(),code)
        self.assertNotIn('binding',json.dumps(components))

    def test_generated_js_rejects_changed_provider_code_and_native_builder_substitution(self):
        self.generated_runtime()
        item=self.receipt['modules'][-1]
        item['generated_runtime']['version']='9.9.9'
        with self.assertRaisesRegex(ValueError,'provider differs'):
            self.generate()
        item['generated_runtime']['version']='1.2.3'
        item['code']+=' altered'
        with self.assertRaisesRegex(ValueError,'helper differs'):
            self.generate()
        self.add_package('node_modules/@rolldown/binding-linux-x64-gnu','@rolldown/binding-linux-x64-gnu','1.2.3',{'binding.node':b'native builder fixture'})
        item.update(path='node_modules/@rolldown/binding-linux-x64-gnu/binding.node',sha256=digest(b'native builder fixture'))
        with self.assertRaisesRegex(ValueError,'physical runtime input'):
            self.generate()


class SourceDownloadTests(unittest.TestCase):
    def test_https_source_cannot_follow_a_redirect_to_cleartext(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b'public source fixture'
        response.geturl.return_value = 'http://upstream.example.invalid/archive.tgz'
        opener=mock.MagicMock()
        opener.open.return_value=response
        with mock.patch.object(frontend_receipt.urllib.request, 'build_opener', return_value=opener):
            with self.assertRaises(ValueError):
                frontend_receipt.download('https://upstream.example.invalid/archive.tgz')

    def test_https_release_asset_redirect_can_use_its_public_expiring_query(self):
        response=mock.MagicMock()
        response.__enter__.return_value=response
        response.geturl.return_value='https://assets.example.invalid/archive.tgz?expires=public-token'
        response.read.side_effect=[b'public source fixture',b'']
        opener=mock.MagicMock()
        opener.open.return_value=response
        with mock.patch.object(frontend_receipt.urllib.request,'build_opener',return_value=opener):
            self.assertEqual(frontend_receipt.download('https://upstream.example.invalid/archive.tgz'),b'public source fixture')

    def test_slow_source_transport_has_a_total_deadline(self):
        response=mock.MagicMock();response.__enter__.return_value=response
        response.geturl.return_value='https://assets.example.invalid/archive.tgz'
        response.read.return_value=b'one small chunk'
        opener=mock.MagicMock();opener.open.return_value=response
        with mock.patch.object(frontend_receipt.urllib.request,'build_opener',return_value=opener),mock.patch.object(frontend_receipt.time,'monotonic',side_effect=[0,0,601]):
            with self.assertRaisesRegex(TimeoutError,'total time bound'):
                frontend_receipt.download('https://upstream.example.invalid/archive.tgz')
        self.assertEqual(response.read.call_count,1)

    def test_each_redirect_hop_rejects_tls_downgrade_before_opening_it(self):
        handler=frontend_receipt.HTTPSRedirects()
        request=frontend_receipt.urllib.request.Request('https://upstream.example.invalid/archive.tgz')
        with self.assertRaises(ValueError):
            handler.redirect_request(request,None,302,'redirect',{},'http://assets.example.invalid/archive.tgz')


class MaterialPublicationTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='xssi-frontend-publication-')
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)
        self.stage=self.root/'stage';self.stage.mkdir()

    def test_identical_material_is_reused_and_conflicting_data_is_preserved(self):
        contents=b'Actual retained upstream resource.\n'
        path=frontend_receipt.retain(self.stage,'share/licenses/fixture/LICENSE',contents)
        original=(path.stat().st_ino,path.stat().st_mtime_ns)
        self.assertEqual(frontend_receipt.retain(self.stage,'share/licenses/fixture/LICENSE',contents),path)
        self.assertEqual((path.stat().st_ino,path.stat().st_mtime_ns),original)
        with self.assertRaisesRegex(ValueError,'conflicts'):
            frontend_receipt.retain(self.stage,'share/licenses/fixture/LICENSE',b'conflicting resource')
        self.assertEqual(path.read_bytes(),contents)

    @unittest.skipIf(os.name=='nt','actual POSIX symlink and FIFO creation')
    def test_parent_and_file_links_and_special_files_never_modify_outside_data(self):
        outside=self.root/'outside';outside.mkdir()
        protected=outside/'LICENSE';protected.write_bytes(b'existing unrelated file')
        (self.stage/'share').symlink_to(outside,target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'physical directories'):
            frontend_receipt.retain(self.stage,'share/LICENSE',b'new resource')
        (self.stage/'share').unlink();(self.stage/'share').mkdir()
        (self.stage/'share/LICENSE').symlink_to(protected)
        with self.assertRaises(ValueError):
            frontend_receipt.retain(self.stage,'share/LICENSE',b'new resource')
        (self.stage/'share/LICENSE').unlink();os.mkfifo(self.stage/'share/LICENSE')
        with self.assertRaises(ValueError):
            frontend_receipt.retain(self.stage,'share/LICENSE',b'new resource')
        self.assertEqual(protected.read_bytes(),b'existing unrelated file')
        self.assertFalse((outside/'licenses').exists())


if __name__ == '__main__':
    unittest.main()
