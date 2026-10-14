"""Actual file/graph/license boundaries; network bytes are explicit fixtures."""
import json
from pathlib import Path
import shutil
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import frontend_receipt
import release_manifest
import release_sbom
import static_web_receipt
import test_frontend_receipt as fixtures


class StaticWebReceiptTests(unittest.TestCase):
    def setUp(self):
        fixture=fixtures.FrontendReceiptTests(methodName='runTest');fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture=fixture;self.source=fixture.web;self.revision='a'*40
        (self.source/'package-lock.json').write_text(json.dumps(fixture.lock))
        (self.source/'dist/assets/Complete-Regular.woff2').unlink()
        (self.source/'dist/fonts').mkdir()
        (self.source/'public/fonts').mkdir(parents=True)
        font={'path':'fonts/fixture.woff2','name':'Explicit font fixture','version':'Version 1.0',
              'source_path':'public/fonts/fixture.woff2',
              'license':{'name':'OFL-1.1','path':'fonts/OFL.txt'},'original_download_url':None}
        self.provenance={'format_version':1,'repository':'https://github.com/fixture/static','fonts':[font]}
        for name,contents in [('fixture.woff2',fixture.font),('OFL.txt',b'Explicit original license fixture.\n')]:
            (self.source/'public/fonts'/name).write_bytes(contents)
            (self.source/'dist/fonts'/name).write_bytes(contents)
            fixture.remote['https://raw.githubusercontent.com/fixture/static/'+self.revision+'/public/fonts/'+name]=contents
        self.refresh()

    def refresh(self):
        (self.source/'public/fonts/provenance.json').write_text(json.dumps(self.provenance))
        outputs=release_sbom.files(self.source/'dist')
        self.fixture.receipt['outputs']=[{'path':name,'sha256':value} for name,value in outputs.items()]
        self.fixture.metadata.write_text(json.dumps(self.fixture.receipt))
        self.stage=self.fixture.root/'static-stage'
        if self.stage.exists():shutil.rmtree(self.stage)
        shutil.copytree(self.source/'dist',self.stage)

    def generate(self):
        with patch.object(frontend_receipt,'download',side_effect=self.fixture.fetch):
            return static_web_receipt.generate(self.source,self.stage,self.fixture.metadata,'taken-my',self.revision)

    def test_actual_output_graph_font_source_and_complete_checksum_are_bound(self):
        components=self.generate()
        runtime=next(item for item in components if item['name']=='runtime-lib')
        self.assertEqual(runtime['files'],[{'path':'assets/app.js','sha256':fixtures.digest((self.stage/'assets/app.js').read_bytes()),'archive_entry':None}])
        font=next(item for item in components if item['name']=='Explicit font fixture')
        self.assertIn('/'+self.revision+'/public/fonts/fixture.woff2',font['source']['url'])
        release_sbom.finalize(self.stage,[],self.stage/'share/external-components.json',
                              'taken-my','1.0.2',self.revision,'static-web',self.source)
        release_manifest.finalize(self.stage,'taken-my','1.0.2',self.revision,'static-web')
        self.assertEqual(release_manifest.verify(self.stage)['identity']['product'],'taken-my')

    def test_changed_output_or_public_font_source_is_rejected(self):
        (self.stage/'assets/app.js').write_bytes(b'changed rendered output')
        with self.assertRaisesRegex(ValueError,'rendered output'):self.generate()
        self.refresh()
        url='https://raw.githubusercontent.com/fixture/static/'+self.revision+'/public/fonts/fixture.woff2'
        self.fixture.remote[url]=b'different public mirror bytes'
        with self.assertRaisesRegex(ValueError,'SHA differs'):self.generate()

    def test_undeclared_font_missing_license_and_inferred_historical_origin_are_rejected(self):
        (self.source/'dist/fonts/extra.woff2').write_bytes(b'undeclared font');self.refresh()
        with self.assertRaisesRegex(ValueError,'cover'):self.generate()
        (self.source/'dist/fonts/extra.woff2').unlink();self.refresh()
        self.provenance['fonts'][0]['license']['path']='fonts/missing.txt';self.refresh()
        with self.assertRaisesRegex(ValueError,'license'):self.generate()
        self.provenance['fonts'][0]['license']['path']='fonts/OFL.txt'
        self.provenance['fonts'][0]['original_download_url']='https://guessed.example/font';self.refresh()
        with self.assertRaisesRegex(ValueError,'unknown original'):self.generate()


if __name__=='__main__':unittest.main()
