"""Verify the fixed vcpkg copyright output, including actual Windows CMake."""
import hashlib
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import static_native_receipt as native


class CopyrightOutputTests(unittest.TestCase):
    def setUp(self):
        self.license=b'Public fixture original LGPL terms.\nSecond original line.\n'
        self.document='Public fixture source licensing document.\nUnicode \u03bb.\n'.encode('utf-8')
        self.output=(b'COPYING.LGPLv2.1:\n\n'+self.license+b'\n\nLICENSE.md:\n\n'+self.document+b'\n\n')

    def test_only_complete_fixed_generator_outputs_match_original_bytes(self):
        self.assertEqual(native.verify_windows_copyright(self.output,self.license,self.document),'lf')
        self.assertEqual(native.verify_windows_copyright(self.output.replace(b'\n',b'\r\n'),self.license,self.document),'windows-crlf')
        for altered in (self.license+b'\n'+self.document,self.output+b'Injected extra term.\n',
                        self.output.replace(b'original LGPL',b'substitute LGPL'),
                        self.output.replace(b'COPYING.LGPLv2.1:',b'COPYING.GPLv3:'),
                        self.output.replace(b'\n',b'\r\n',1),
                        self.output.split(b'LICENSE.md:',1)[1]+self.output.split(b'LICENSE.md:',1)[0]):
            with self.subTest(sha256=hashlib.sha256(altered).hexdigest()),self.assertRaisesRegex(ValueError,'copyright differs'):
                native.verify_windows_copyright(altered,self.license,self.document)

    @unittest.skipUnless(os.name=='nt','requires actual Windows CMake text-mode output')
    def test_actual_windows_cmake_generates_exact_crlf_without_changing_sources(self):
        cmake=shutil.which('cmake')
        self.assertIsNotNone(cmake,'the official Windows boundary job requires its native CMake')
        with tempfile.TemporaryDirectory(prefix='xssi-copyright-write-') as temporary:
            root=Path(temporary).resolve(strict=True)
            version=native.run([cmake,'--version'],root,native.environment(),maximum=65536,timeout=30)
            self.assertEqual(version.splitlines()[0],b'cmake version 3.31.3')
            (root/'COPYING.LGPLv2.1').write_bytes(self.license)
            (root/'LICENSE.md').write_bytes(self.document)
            # The fixed vcpkg e456309 helper's multi-file construction and
            # native file(WRITE), with only public fixture source texts.
            script=root/'write.cmake'
            script.write_text(r'''set(out_string "")
foreach(file_name IN ITEMS COPYING.LGPLv2.1 LICENSE.md)
    file(READ "${CMAKE_CURRENT_LIST_DIR}/${file_name}" file_contents)
    string(APPEND out_string "${file_name}:\n\n${file_contents}\n\n")
endforeach()
file(WRITE "${CMAKE_CURRENT_LIST_DIR}/copyright" "${out_string}")
''',encoding='utf-8')
            native.run([cmake,'-P',str(script)],root,native.environment(),maximum=65536,timeout=30)
            actual=native.bounded(root/'copyright',65536)
            self.assertEqual(actual,self.output.replace(b'\n',b'\r\n'))
            self.assertEqual(native.verify_windows_copyright(actual,self.license,self.document),'windows-crlf')
            self.assertEqual((root/'COPYING.LGPLv2.1').read_bytes(),self.license)
            self.assertEqual((root/'LICENSE.md').read_bytes(),self.document)


if __name__=='__main__':unittest.main()
