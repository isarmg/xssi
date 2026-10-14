import configparser
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import unit_templates
from unit_validation import template_bytes

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
            self.assertEqual(units['xcos-mediamtx.service']['Service']['EnvironmentFile'],'@ROOT@/config/mediamtx.env')
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

    def test_actual_systemd_parser_accepts_media_environment_path_including_spaces(self):
        analyzer=shutil.which('systemd-analyze')
        if analyzer is None:self.skipTest('actual systemd-analyze is unavailable')
        with tempfile.TemporaryDirectory() as temporary:
            stage=Path(temporary);(stage/'share/systemd').mkdir(parents=True)
            unit_templates.write(ROOT,stage,'xcos')
            units=stage/'isolated-units';units.mkdir()
            # Restrict the verification manager to this fixture. Never inspect,
            # load into the host manager, enable or start installed user units.
            environment={'PATH':'/usr/bin:/bin','TZ':'UTC','SYSTEMD_UNIT_PATH':str(units)}
            for target in ('network-online.target','sysinit.target','basic.target','shutdown.target'):
                (units/target).write_text('[Unit]\nDescription=Fixture target\nDefaultDependencies=no\n')
            for name in ('installed','installed with spaces'):
                with self.subTest(root=name):
                    root=stage/name;(root/'bin').mkdir(parents=True)
                    (root/'config').mkdir()
                    (root/'config/mediamtx.env').write_text('MTX_TEST=fixture\n')
                    for binary in ('xcos','mediamtx'):
                        path=root/'bin'/binary;path.write_text('#!/bin/sh\nexit 0\n');path.chmod(0o755)
                    for source in (stage/'share/systemd').iterdir():
                        (units/source.name).write_bytes(template_bytes(source.read_bytes(),root,'xcos'))
                    media=units/'xcos-mediamtx.service'
                    result=subprocess.run([analyzer,'verify','--man=no',str(media)],
                                          env=environment,capture_output=True,text=True,timeout=30)
                    if 'SO_PASSCRED failed: Operation not permitted' in result.stderr:
                        self.skipTest('execution sandbox blocks the actual systemd verification manager')
                    self.assertEqual(result.returncode,0,result.stderr)
                    self.assertNotIn('EnvironmentFile= path is not absolute',result.stderr)
                    self.assertIn('EnvironmentFile='+str(root/'config/mediamtx.env'),media.read_text())
                    # The previous quoted scalar is ignored even when verify
                    # itself exits zero; preserve this actual-parser negative.
                    media.write_text(media.read_text().replace(
                        'EnvironmentFile='+str(root/'config/mediamtx.env'),
                        'EnvironmentFile="'+str(root/'config/mediamtx.env')+'"'))
                    rejected=subprocess.run([analyzer,'verify','--man=no',str(media)],
                                            env=environment,capture_output=True,text=True,timeout=30)
                    self.assertIn('EnvironmentFile= path is not absolute',rejected.stderr)

if __name__=='__main__':unittest.main()
