"""Actual archive/checksum tests; the executable is an explicit report fixture."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

SCRIPTS=Path(__file__).resolve().parents[1]/'scripts'
sys.path.insert(0,str(SCRIPTS))
import release_manifest
import release_sbom


def module(name):
    specification=importlib.util.spec_from_file_location(name.replace('-','_'),SCRIPTS/(name+'.py'))
    value=importlib.util.module_from_spec(specification);specification.loader.exec_module(value)
    return value


publisher=module('finalize-release')
stager=module('stage-release')


class ToolReleaseTests(unittest.TestCase):
    def fixture(self,helper_version='1.0.0',provenance_revision='a'*40):
        temporary=tempfile.TemporaryDirectory(prefix='xssi-tool-release-test-');self.addCleanup(temporary.cleanup)
        root=Path(temporary.name);stage=root/'stage';output=root/'assets'
        (stage/'libexec').mkdir(parents=True);(stage/'share').mkdir();output.mkdir()
        helper=stage/'libexec/setup'
        helper.write_text('#!/bin/sh\n[ "$1" = --version ] || exit 2\nprintf "setup '+helper_version+'\\n"\n');helper.chmod(0o755)
        (stage/'share/README.md').write_text('这是公开的发布验证夹具，不代表编译产物。\n')
        provenance={'format_version':1,'product':'xssi','version':'1.0.0','source_revision':provenance_revision,
                    'target':publisher.TARGET,'helper_sha256':release_sbom.digest(helper)}
        (stage/'share/build-provenance.json').write_text(json.dumps(provenance)+'\n')
        receipt=root/'external.json';receipt.write_text(json.dumps({'format_version':1,'runtime_roots':[],'components':[]})+'\n')
        release_sbom.finalize(stage,[],receipt,'xssi','1.0.0','a'*40,publisher.TARGET)
        release_manifest.finalize(stage,'xssi','1.0.0','a'*40,publisher.TARGET)
        return stage,output

    def test_actual_archive_roundtrip_and_whole_sha256_cover_all_delivered_files(self):
        stage,output=self.fixture()
        archive=publisher.finalize(stage,output,'a'*40,'1.0.0')
        expected=hashlib.sha256(archive.read_bytes()).hexdigest()+'  '+archive.name+'\n'
        self.assertEqual(archive.with_name(archive.name+'.sha256').read_text(),expected)
        with tarfile.open(archive,'r:gz') as package:
            names=package.getnames()
            self.assertIn('xssi-1.0.0-linux-x86_64/share/package.json',names)
            self.assertIn('xssi-1.0.0-linux-x86_64/share/package.sha256',names)
            self.assertIn('xssi-1.0.0-linux-x86_64/share/release-sbom.cdx.json',names)
        with self.assertRaisesRegex(ValueError,'overwrite'):
            publisher.finalize(stage,output,'a'*40,'1.0.0')

    def test_changed_final_payload_or_wrong_source_never_produces_an_archive(self):
        for changed in ('payload','source','version'):
            stage,output=self.fixture()
            if changed=='payload':(stage/'share/README.md').write_text('changed payload')
            revision='b'*40 if changed=='source' else 'a'*40
            version='9.9.9' if changed=='version' else '1.0.0'
            with self.subTest(changed=changed),self.assertRaises(ValueError):
                publisher.finalize(stage,output,revision,version)
            self.assertEqual(list(output.iterdir()),[])

    def test_actual_helper_report_and_provenance_must_match_expected_release(self):
        for helper_version,revision in [('9.9.9','a'*40),('1.0.0','b'*40)]:
            stage,output=self.fixture(helper_version,revision)
            with self.subTest(helper_version=helper_version,revision=revision),self.assertRaises(ValueError):
                publisher.finalize(stage,output,'a'*40,'1.0.0')
            self.assertEqual(list(output.iterdir()),[])

    def test_source_tag_and_clean_checkout_identity_are_checked_before_build(self):
        manifest=b'[package]\nname="xssi"\nversion="1.0.0"\n'
        for reports in [('b'*40,'','a'*40),('a'*40,' M source.rs','a'*40),('a'*40,'','b'*40)]:
            with self.subTest(reports=reports),mock.patch.object(stager,'git',side_effect=reports),mock.patch.object(stager.release_manifest,'bounded',return_value=manifest):
                with self.assertRaises(ValueError):stager.source_identity('a'*40,'1.0.0')
        with mock.patch.object(stager,'git',side_effect=['a'*40,'','a'*40]),mock.patch.object(stager.release_manifest,'bounded',return_value=manifest):
            stager.source_identity('a'*40,'1.0.0')


if __name__=='__main__':unittest.main()
