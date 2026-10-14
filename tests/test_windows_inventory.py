import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import release_sbom as inventory


class PhysicalInventoryTests(unittest.TestCase):
    def test_drive_unc_ads_and_noncanonical_paths_cannot_escape_the_stage(self):
        for path in ('C:/external','C:relative','//host/share/file','\\\\host\\share\\file',
                     'share/file:stream','share/../outside','./bin/app'):
            with self.subTest(path=path),self.assertRaises(ValueError):inventory.relative(path)
        self.assertEqual(inventory.relative('share/licenses/LICENSE.txt'),'share/licenses/LICENSE.txt')

    def test_linked_stage_root_is_rejected_before_inventory(self):
        if os.name=='nt':self.skipTest('NTFS root junction covered by the actual Windows test')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);stage=root/'stage';stage.mkdir()
            (stage/'file').write_bytes(b'delivered')
            alias=root/'alias';alias.symlink_to(stage,target_is_directory=True)
            with self.assertRaisesRegex(ValueError,'physical directories'):inventory.files(alias)

    @unittest.skipUnless(os.name=='nt','requires actual Windows NTFS junctions')
    def test_actual_ntfs_junctions_are_rejected_as_roots_and_nested_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);outside=root/'outside';outside.mkdir()
            (outside/'private').write_bytes(b'outside fixture')
            stage=root/'stage';stage.mkdir()
            nested=stage/'junction';alias=root/'alias'
            for junction in (nested,alias):
                result=subprocess.run(['cmd','/d','/c','mklink','/J',str(junction),str(outside)],
                                      stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL,timeout=10)
                self.assertEqual(result.returncode,0,'could not create the actual test junction')
            try:
                with self.assertRaisesRegex(ValueError,'reparse'):inventory.files(stage)
                with self.assertRaisesRegex(ValueError,'physical directories'):inventory.files(alias)
                self.assertEqual((outside/'private').read_bytes(),b'outside fixture')
            finally:
                nested.rmdir();alias.rmdir()


if __name__=='__main__':unittest.main()
