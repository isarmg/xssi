"""Actual regular-file reader contract on POSIX and Windows runners."""
from pathlib import Path
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from release_manifest import bounded
import gradle_sbom
import release_sbom


class BoundedReaderTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='xssi-bounded-reader-')
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)

    def test_actual_regular_file_exact_limit_empty_and_overflow(self):
        file=self.root/'file'
        file.write_bytes(b'public file fixture')
        self.assertEqual(bounded(file,19),b'public file fixture')
        with self.assertRaises(ValueError):bounded(file,18)
        file.write_bytes(b'')
        self.assertEqual(bounded(file,0),b'')

    def test_actual_binary_bytes_do_not_translate_crlf_or_treat_control_z_as_eof(self):
        import hashlib
        contents=b'public\r\nbinary\x1a\x00\xfffixture\r\n'
        file=self.root/'binary';file.write_bytes(contents)
        self.assertEqual(bounded(file,len(contents)),contents)
        self.assertEqual(gradle_sbom.bytes_regular(file,len(contents)),contents)
        self.assertEqual(release_sbom.digest(file),hashlib.sha256(contents).hexdigest())

    def test_directory_and_actual_hardlink_are_rejected(self):
        with self.assertRaises(ValueError):bounded(self.root,1024)
        file=self.root/'file'
        file.write_bytes(b'public file fixture')
        os.link(file,self.root/'alias')
        with self.assertRaises(ValueError):bounded(file,1024)

    def test_symlink_or_windows_junction_is_not_followed(self):
        file=self.root/'file'
        file.write_bytes(b'public file fixture')
        alias=self.root/'alias'
        if os.name=='nt':
            import subprocess
            # A directory junction does not require Developer Mode or elevated
            # symlink privilege, and is an actual Windows reparse point.
            subprocess.run(['cmd','/d','/c','mklink','/J',str(alias),str(self.root)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            try:
                with self.assertRaises(ValueError):bounded(alias,1024)
            finally:
                alias.rmdir()
        else:
            alias.symlink_to(file)
            with self.assertRaises(ValueError):bounded(alias,1024)

    def test_inventory_json_rejects_links_duplicate_fields_and_oversized_documents(self):
        file=self.root/'inventory.json'
        file.write_bytes(b'{"identity":"fixture"}')
        self.assertEqual(release_sbom.load(file),{'identity':'fixture'})
        os.link(file,self.root/'hardlink.json')
        with self.assertRaises(ValueError):release_sbom.load(file)
        (self.root/'hardlink.json').unlink()
        file.write_bytes(b'{"identity":1,"identity":2}')
        with self.assertRaisesRegex(ValueError,'duplicate'):release_sbom.load(file)
        file.write_bytes(b'{"identity":"fixture"}')
        with patch.object(release_sbom,'MAX_JSON',8):
            with self.assertRaisesRegex(ValueError,'bounded'):release_sbom.load(file)
        if os.name!='nt':
            alias=self.root/'linked.json';alias.symlink_to(file)
            with self.assertRaises(ValueError):release_sbom.load(alias)
            directory=self.root/'linked-directory';directory.symlink_to(self.root,target_is_directory=True)
            with self.assertRaisesRegex(ValueError,'physical'):release_sbom.load(directory/file.name)

    @unittest.skipIf(os.name=='nt','POSIX named pipes are not Windows regular files')
    def test_inventory_json_rejects_fifo_without_waiting_for_a_writer(self):
        fifo=self.root/'fifo.json';os.mkfifo(fifo)
        with self.assertRaises(ValueError):release_sbom.load(fifo)

    def test_actual_concurrent_file_change_is_rejected_by_the_shared_reader(self):
        file=self.root/'changing.json';file.write_bytes(b'{"identity":"fixture"}')
        original_read=os.read
        changed=False
        def change_after_read(descriptor,count):
            nonlocal changed
            data=original_read(descriptor,count)
            if data and not changed:
                changed=True
                with file.open('ab') as output:output.write(b' ')
            return data
        with patch.object(release_sbom.os,'read',side_effect=change_after_read):
            with self.assertRaisesRegex(ValueError,'changed'):release_sbom.load(file)


if __name__=='__main__':unittest.main()
