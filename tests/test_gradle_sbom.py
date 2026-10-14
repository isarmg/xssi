import copy
import hashlib
import io
import json
from pathlib import Path
import stat
import tempfile
import sys
import unittest
import urllib.error
import zipfile
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import gradle_sbom


def archive(entries):
    output=io.BytesIO()
    with zipfile.ZipFile(output,'w') as value:
        for name,body in entries.items():value.writestr(name,body)
    return output.getvalue()


class GradleRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='xssi-gradle-runtime-')
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name).resolve(strict=True);self.stage=self.root/'release';self.stage.mkdir()
        self.repository='https://repo.example.invalid/maven/'
        self.group='org.example';self.name='runtime';self.version='1.2.3';self.identity='org.example:runtime:1.2.3'
        self.artifact=archive({'classes.jar':archive({'META-INF/NOTICE.txt':b'Actual nested upstream copyright notice.\n','org/example/Class.class':b'class fixture'}),
                              'AndroidManifest.xml':b'manifest fixture'})
        self.path=self.root/'runtime-1.2.3.aar';self.path.write_bytes(self.artifact)
        self.export={'format_version':1,'configuration':'releaseRuntimeClasspath',
            'root':{'id':'project :app','dependencies':[self.identity]},'repositories':[self.repository],
            'components':[{'id':self.identity,'group':self.group,'name':self.name,'version':self.version,
                'artifacts':[{'path':str(self.path),'sha256':hashlib.sha256(self.artifact).hexdigest(),'filename':self.path.name}],
                'dependencies':[]}]}
        self.license_url='https://upstream.example.invalid/LICENSE.txt'
        self.license=b'Actual upstream fixture license and copyright terms.\n'
        base=self.repository+'org/example/runtime/1.2.3/'
        self.remote={base+self.path.name:self.artifact,
                     base+'runtime-1.2.3.pom':b'<project><groupId>org.example</groupId><artifactId>runtime</artifactId><version>1.2.3</version><licenses><license><name>Fixture License</name><url>https://upstream.example.invalid/LICENSE.txt</url></license></licenses></project>',
                     self.license_url:self.license}

    def fetch(self,url,maximum):
        if url not in self.remote:raise urllib.error.HTTPError(url,404,'missing',{},None)
        value=self.remote[url]
        if len(value)>maximum:raise ValueError('fixture bound')
        return value

    def invoke(self,export=None):
        return gradle_sbom.produce(export or self.export,self.stage,'fixture-client','1.0.0','a'*40,download=self.fetch)

    def test_binary_control_bytes_are_preserved_by_the_stable_reader(self):
        value=b'PK\x03\x04\r\n\x1a\x00 actual binary cache bytes\r\n'
        for extension in ('.dll','.exe','.nupkg'):
            with self.subTest(extension=extension):
                path=self.root/('binary-input'+extension);path.write_bytes(value)
                self.assertEqual(gradle_sbom.bytes_regular(path,len(value)),value)

    def test_actual_artifact_hash_graph_parent_and_nested_upstream_notices(self):
        output=self.invoke();bom=json.loads(output.read_text())
        self.assertEqual(bom['metadata']['properties'][1]['value'],'releaseRuntimeClasspath')
        component=bom['components'][0]
        self.assertEqual(component['purl'],'pkg:maven/org.example/runtime@1.2.3')
        values=[]
        for license_ in component['licenses']:
            properties={value['name']:value['value'] for value in license_['license']['properties']}
            value=(self.stage/properties['license-file']).read_bytes()
            self.assertEqual(hashlib.sha256(value).hexdigest(),properties['license-sha256'])
            values.append(value)
        self.assertIn(self.license,values)
        self.assertIn(b'Actual nested upstream copyright notice.\n',values)
        self.assertNotIn(str(self.root),output.read_text())
        self.assertEqual(bom['dependencies'][0]['dependsOn'],[component['bom-ref']])

    def test_repository_origin_must_reproduce_the_actual_gradle_cache_bytes(self):
        artifact_url=next(url for url in self.remote if url.endswith('.aar'))
        self.remote[artifact_url]=archive({'different':b'upstream artifact differs'})
        with self.assertRaisesRegex(ValueError,'exact resolved runtime artifact'):self.invoke()
        self.assertFalse((self.stage/'share/android-runtime-sbom.cdx.json').exists())

    def test_actual_unicode_license_identity_survives_machine_json_serialization(self):
        pom_url=next(url for url in self.remote if url.endswith('.pom'))
        license_name='Original license \u03bb\u8bb8\u53ef\u8bc1'
        self.remote[pom_url]=self.remote[pom_url].replace(b'Fixture License',license_name.encode('utf-8'))
        output=self.invoke()
        bom=json.loads(output.read_bytes())
        self.assertIn(license_name,[entry['license']['name'] for entry in bom['components'][0]['licenses']])

    def test_cached_file_change_and_alias_are_rejected_before_source_fetch(self):
        self.path.write_bytes(b'changed bytes')
        with self.assertRaisesRegex(ValueError,'changed before inventory'):self.invoke()
        self.path.rename(self.path.with_suffix('.held'));self.path.symlink_to(self.path.with_suffix('.held'))
        self.stage=self.root/'alias-release';self.stage.mkdir()
        with self.assertRaisesRegex(ValueError,'cannot follow a link'):self.invoke()

    def test_build_debug_disconnected_and_unknown_edges_cannot_enter_runtime_graph(self):
        changed=copy.deepcopy(self.export);changed['configuration']='debugRuntimeClasspath'
        with self.assertRaisesRegex(ValueError,'current release runtime'):self.invoke(changed)
        changed=copy.deepcopy(self.export);changed['root']['dependencies']=[]
        with self.assertRaisesRegex(ValueError,'disconnected'):self.invoke(changed)
        changed=copy.deepcopy(self.export);changed['components'][0]['dependencies']=['unknown:runtime:1.0.0']
        with self.assertRaisesRegex(ValueError,'closed and unique'):self.invoke(changed)
        changed=copy.deepcopy(self.export);changed['components'].append(copy.deepcopy(changed['components'][0]))
        with self.assertRaisesRegex(ValueError,'repeats'):self.invoke(changed)

    def test_actual_parent_license_is_inherited_without_a_template_fallback(self):
        pom=next(url for url in self.remote if url.endswith('.pom'))
        self.remote[pom]=b'<project><artifactId>runtime</artifactId><version>1.2.3</version><parent><groupId>org.example</groupId><artifactId>parent</artifactId><version>9.0.0</version></parent></project>'
        parent=self.repository+'org/example/parent/9.0.0/parent-9.0.0.pom'
        self.remote[parent]=b'<project><groupId>org.example</groupId><artifactId>parent</artifactId><version>9.0.0</version><licenses><license><name>Fixture Parent License</name><url>https://upstream.example.invalid/LICENSE.txt</url></license></licenses></project>'
        component=json.loads(self.invoke().read_text())['components'][0]
        self.assertEqual(component['licenses'][0]['license']['name'],'Fixture Parent License')
        metadata={value['name']:value['value'] for value in component['properties']}
        self.assertEqual(len(json.loads(metadata['maven-license-metadata'])),2)

    def test_mismatched_or_repeated_pom_identity_cannot_borrow_upstream_licenses(self):
        pom=next(url for url in self.remote if url.endswith('.pom'))
        original=self.remote[pom]
        for value in (original.replace(b'<artifactId>runtime</artifactId>',b'<artifactId>another-library</artifactId>'),
                      original.replace(b'<version>1.2.3</version>',b'<version>1.2.3</version><version>9.0.0</version>')):
            self.remote[pom]=value
            with self.assertRaisesRegex(ValueError,'identity|repeats'):
                gradle_sbom.pom_license(self.group,self.name,self.version,self.repository,self.fetch)

    def test_notice_expansion_has_per_artifact_and_whole_graph_bounds_and_rejects_links(self):
        compressed=io.BytesIO()
        with zipfile.ZipFile(compressed,'w',zipfile.ZIP_DEFLATED) as package:
            for number in range(9):package.writestr(str(number)+'/NOTICE.txt',b'x'*(1024*1024))
        with self.assertRaisesRegex(ValueError,'per-artifact bound'):
            gradle_sbom.archive_notices(compressed.getvalue())
        linked=io.BytesIO()
        with zipfile.ZipFile(linked,'w') as package:
            entry=zipfile.ZipInfo('NOTICE.txt');entry.external_attr=(stat.S_IFLNK|0o777)<<16
            package.writestr(entry,'/outside/license')
        with self.assertRaisesRegex(ValueError,'symbolic link'):gradle_sbom.archive_notices(linked.getvalue())
        self.artifact=archive({str(number)+'/NOTICE.txt':b'n'*2048 for number in range(3)})
        self.path.write_bytes(self.artifact)
        self.export['components'][0]['artifacts'][0]['sha256']=hashlib.sha256(self.artifact).hexdigest()
        artifact_url=next(url for url in self.remote if url.endswith('.aar'));self.remote[artifact_url]=self.artifact
        with patch.object(gradle_sbom,'MAX_GRAPH_BYTES',len(self.artifact)+5000),self.assertRaisesRegex(ValueError,'aggregate byte bound'):
            self.invoke()
        self.assertFalse((self.stage/'share/android-runtime-sbom.cdx.json').exists())

    def test_missing_license_or_cyclic_xml_parent_fails_without_final_inventory(self):
        pom=next(url for url in self.remote if url.endswith('.pom'))
        for contents in (b'<project/>',b'<project><parent><groupId>org.example</groupId><artifactId>runtime</artifactId><version>1.2.3</version></parent></project>',
                         b'<!DOCTYPE project [<!ENTITY x "private">]><project/>',
                         '<!DOCTYPE project [<!ENTITY x "private">]><project/>'.encode('utf-16')):
            with self.subTest(contents=contents):
                self.remote[pom]=contents
                target=self.root/('failed-'+str(len(contents)));target.mkdir()
                with self.assertRaises(ValueError):
                    gradle_sbom.produce(self.export,target,'fixture-client','1.0.0','a'*40,download=self.fetch)
                self.assertFalse((target/'share/android-runtime-sbom.cdx.json').exists())


if __name__=='__main__':unittest.main()
