import configparser
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import unit_templates

class UnitTests(unittest.TestCase):
    def test_camera_main_start_pulls_media_without_an_ordering_cycle(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage=Path(temporary);(stage/'share/systemd').mkdir(parents=True)
            unit_templates.write(ROOT,stage,'xcos')
            units={}
            for name in ['xcos.service','xcos-mediamtx.service']:
                value=configparser.ConfigParser(interpolation=None);value.read(stage/'share/systemd'/name);units[name]=value
            self.assertIn('xcos-mediamtx.service',units['xcos.service']['Unit']['Requires'].split())
            self.assertIn('xcos-mediamtx.service',units['xcos.service']['Unit']['After'].split())
            self.assertEqual(units['xcos-mediamtx.service']['Unit']['PartOf'],'xcos.service')
            self.assertNotIn('xcos.service',units['xcos-mediamtx.service']['Unit']['After'].split())
            self.assertEqual(units['xcos-mediamtx.service']['Service']['EnvironmentFile'],'"@ROOT@/config/mediamtx.env"')
            for unit in units.values():
                self.assertIn('@ROOT@',unit['Service']['ExecStart'])
                self.assertEqual(unit['Service']['Environment'],'TZ=UTC')

    def test_other_servers_have_one_runtime_and_no_media_dependency(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage=Path(temporary);(stage/'share/systemd').mkdir(parents=True)
            unit_templates.write(ROOT,stage,'xocs')
            self.assertEqual([path.name for path in (stage/'share/systemd').iterdir()],['xocs.service'])
            unit=configparser.ConfigParser(interpolation=None);unit.read(stage/'share/systemd/xocs.service')
            self.assertNotIn('Requires',unit['Unit'])
            self.assertEqual(unit['Service']['ExecStart'],'"@ROOT@/bin/xocs" --root "@ROOT@"')
            self.assertEqual(unit['Service']['Environment'],'TZ=UTC')

if __name__=='__main__':unittest.main()
