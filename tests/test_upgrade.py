"""Exercise upgrade download boundaries and ordering without touching systemd."""
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import upgrade

class UpgradeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)

    def test_readiness_normalizes_wildcards_and_preserves_explicit_addresses(self):
        for source,expected in [
            ('0.0.0.0:18105','127.0.0.1:18105'),
            ('[::]:18105','[::1]:18105'),
            ('[0:0:0:0:0:0:0:0]:18105','[::1]:18105'),
            ('[::ffff:0.0.0.0]:18105','127.0.0.1:18105'),
            ('192.168.1.20:18105','192.168.1.20:18105'),
            ('[fd00:0:0:0:0:0:0:20]:18105','[fd00::20]:18105'),
            ('[fe80::20%3]:18105','[fe80::20%3]:18105'),
        ]:
            with self.subTest(source=source):
                self.assertEqual(upgrade.readiness_address(source),expected)

    def archive(self, entries):
        path=self.root/'archive.tar.gz'
        with tarfile.open(path,'w:gz') as tar:
            for name,data,kind in entries:
                item=tarfile.TarInfo(name);item.type=kind;item.size=len(data) if kind==tarfile.REGTYPE else 0
                if kind in (tarfile.SYMTYPE,tarfile.LNKTYPE):item.linkname='/etc/passwd'
                tar.addfile(item,io.BytesIO(data) if item.isfile() else None)
        return path

    def test_archive_rejects_links_and_traversal_before_extracting(self):
        for entry in [('bundle/a',b'',tarfile.SYMTYPE),('bundle/a',b'',tarfile.LNKTYPE),
                      ('../escape',b'x',tarfile.REGTYPE),('/absolute',b'x',tarfile.REGTYPE)]:
            with self.subTest(entry=entry):
                target=self.root/'extracted'
                with self.assertRaises(ValueError):upgrade.extract(self.archive([entry]),target)
                self.assertFalse(target.exists())

    def test_archive_rejects_duplicates_and_multiple_roots(self):
        for entries in [[('bundle/a',b'a',tarfile.REGTYPE),('bundle/a',b'b',tarfile.REGTYPE)],
                        [('bundle/a',b'a',tarfile.REGTYPE),('other/a',b'b',tarfile.REGTYPE)]]:
            with self.assertRaises(ValueError):upgrade.extract(self.archive(entries),self.root/'out')

    def test_archive_accepts_one_normal_package(self):
        archive=self.archive([('bundle/bin/server',b'fixture',tarfile.REGTYPE)])
        target=upgrade.extract(archive,self.root/'out')
        self.assertEqual((target/'bin/server').read_bytes(),b'fixture')

    def test_asset_selection_requires_exact_product_version_and_platform(self):
        name='xocs-2.0.0-linux-x86_64.tar.gz'
        asset={'name':name,'browser_download_url':'https://github.com/isarmg/xocs/releases/download/v2.0.0/'+name,'size':100,'digest':'sha256:'+'a'*64}
        release={'tag_name':'v2.0.0','draft':False,'prerelease':False,'assets':[asset]}
        self.assertEqual(upgrade.select_asset(release,'xocs','2.0.0'),asset)
        for change in [{'size':True},{'size':upgrade.package.MAX_TOTAL_BYTES+1},{'digest':'MD5:bad'},
                       {'browser_download_url':'https://example.com/'+name},{'name':'xocs-2.0.0-linux-arm64.tar.gz'}]:
            with self.subTest(change=change),self.assertRaises(ValueError):
                upgrade.select_asset(dict(release,assets=[dict(asset,**change)]),'xocs','2.0.0')
        with self.assertRaises(ValueError):upgrade.select_asset(dict(release,assets=[asset,asset]),'xocs','2.0.0')

    def test_redirect_cannot_downgrade_https(self):
        with self.assertRaises(ValueError):
            upgrade.SecureRedirect().redirect_request(None,None,302,'redirect',{},'http://example.com/archive')

    def test_tool_lock_blocks_download_and_service_operations(self):
        import fcntl,os
        (self.root/'maintenance').mkdir(mode=0o700);lock=self.root/'maintenance/tool.lock';lock.touch(mode=0o600)
        fd=os.open(lock,os.O_RDWR)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            args=types.SimpleNamespace(root=self.root,config=None)
            with patch.object(upgrade,'require_root'),patch.object(upgrade,'controlled_chain'),patch.object(upgrade,'locked_run') as operation:
                with self.assertRaises(BlockingIOError):upgrade.run(args)
                operation.assert_not_called()
        finally:os.close(fd)

    def test_unsafe_coordinator_inode_is_rejected_before_any_operation(self):
        import os
        maintenance=self.root/'maintenance';maintenance.mkdir(mode=0o700)
        lock=maintenance/'tool.lock';lock.touch(mode=0o600)
        args=types.SimpleNamespace(root=self.root,config=None)
        for change in ('writable-lock','hardlink-lock','writable-control'):
            lock.chmod(0o600);maintenance.chmod(0o700)
            alias=self.root/'lock-alias'
            if alias.exists():alias.unlink()
            if change=='writable-lock':lock.chmod(0o666)
            elif change=='hardlink-lock':os.link(lock,alias)
            else:maintenance.chmod(0o775)
            with self.subTest(change=change),patch.object(upgrade,'require_root'),patch.object(upgrade,'controlled_chain'),patch.object(upgrade,'locked_run') as operation:
                with self.assertRaises(ValueError):upgrade.run(args)
                operation.assert_not_called()

    def test_invalid_checksum_never_stops_a_service(self):
        args=types.SimpleNamespace(version='2.0.0')
        with patch.object(upgrade.package,'verify_checksum',side_effect=ValueError('invalid checksum')),patch.object(upgrade,'process') as service:
            with self.assertRaises(ValueError):upgrade.locked_run(args,self.root)
            service.assert_not_called()

if __name__=='__main__':unittest.main()
