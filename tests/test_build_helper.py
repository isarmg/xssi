import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
spec=importlib.util.spec_from_file_location('build_helper',Path(__file__).resolve().parents[1]/'scripts/build-helper.py')
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)

class ResolutionTests(unittest.TestCase):
    def record(self,name,source,checksum='a',version='1.0.0'):
        return {'name':name,'version':version,'source':source,'checksum':checksum}

    def test_independent_helper_graph_is_immutable(self):
        registry='registry+https://github.com/rust-lang/crates.io-index'
        old={'package':[self.record('argon2',registry),self.record('xcsc','git+https://github.com/isarmg/xcsc.git?rev='+'a'*40)]}
        helper.verify_resolution(old,old)
        for changed in [{'package':old['package'][:-1]}, {'package':[self.record('argon2',registry,checksum='different'),old['package'][1]]}]:
            with self.assertRaises(ValueError):helper.verify_resolution(old,changed)

    def test_compilers_preserve_transport_trust_without_inherited_secrets(self):
        supplied={'PATH':'/trusted/tools','HTTPS_PROXY':'https://session-proxy',
                  'SSL_CERT_FILE':'/session/ca.pem','PRIVATE_KEY_FILE':'/private/fixture',
                  'CUSTOM_SECRET':'explicit fixture secret','REPOSITORY_TOKEN':'fixture repository access',
                  'XSSI_BUILD_METADATA_DIR':'/private/receipt','XSSI_IDENTITY_FILE':'/private/identity',
                  'XSSI_SCHEMA_FILE':'/private/schema','TZ':'Asia/Shanghai'}
        with mock.patch.dict(os.environ,supplied,clear=True):actual=helper.build_environment()
        self.assertEqual(actual,{'PATH':'/trusted/tools','HTTPS_PROXY':'https://session-proxy',
                                 'SSL_CERT_FILE':'/session/ca.pem','TZ':'UTC'})

if __name__=='__main__':unittest.main()
