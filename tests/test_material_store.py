"""Actual private filesystem retention; no service or business data mutations."""
import fcntl
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import material_store as materials


class MaterialStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='xssi-material-store-')
        self.root = Path(self.temporary.name) / 'root'
        self.root.mkdir(mode=0o755)
        (self.root / 'maintenance').mkdir(mode=0o700)
        self.lock = os.open(self.root / 'maintenance/tool.lock', os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        fcntl.flock(self.lock, fcntl.LOCK_EX)

    def tearDown(self):
        os.close(self.lock)
        self.temporary.cleanup()

    def completed(self):
        record, work = materials.begin(self.root, 'download', self.lock)
        for name in ['first', 'second']:
            path = work / name
            path.write_bytes(name.encode());path.chmod(0o600)
        materials.complete(self.root, record, self.lock, {'first', 'second'})
        return record, work

    def test_plan_is_pure_and_explicit_collection_only_removes_known_material(self):
        record, work = self.completed()
        business = self.root / 'business';business.mkdir()
        (business / 'retained').write_bytes(b'user data')
        before = record.read_bytes()
        plan = materials.collect(self.root, self.lock, 0, 0)
        self.assertEqual(plan['eligible'], [str(work)])
        self.assertEqual(record.read_bytes(), before)
        self.assertTrue(work.exists())
        result = materials.collect(self.root, self.lock, 0, 0, True)
        self.assertEqual(result['status'], 'material-collection-complete')
        self.assertFalse(work.exists())
        self.assertEqual((business / 'retained').read_bytes(), b'user data')
        self.assertEqual(json.loads(record.read_bytes())['phase'], 'collected')
        materials.collect(self.root, self.lock, 0, 0, True)
        self.assertFalse(record.exists())

    def test_unfinished_unknown_and_explicit_retention_remain(self):
        _, unfinished = materials.begin(self.root, 'download', self.lock)
        _, work = self.completed()
        (self.root / 'maintenance/material-records/unknown').write_bytes(b'unknown')
        for age, keep in [(100000, 0), (0, 1)]:
            plan = materials.collect(self.root, self.lock, age, keep, True)
            self.assertEqual(plan['eligible'], [])
            self.assertTrue(work.exists());self.assertTrue(unfinished.exists())
            self.assertTrue(any(item['reason'] == 'unknown-authority' for item in plan['retained']))

    def test_complete_material_with_an_active_reference_is_retained(self):
        _, work = self.completed()
        parent = self.root / 'maintenance/upgrades';parent.mkdir(mode=0o700)
        operation = parent / str(materials.uuid.uuid4());operation.mkdir(mode=0o700)
        journal = operation / 'upgrade.json'
        journal.write_text(json.dumps({'phase': 'Ready', 'target_binary': str(work / 'first')}));journal.chmod(0o600)
        plan = materials.collect(self.root, self.lock, 0, 0, True)
        self.assertEqual(plan['eligible'], [])
        self.assertEqual(plan['retained'][0]['reason'], 'referenced')
        self.assertTrue(work.exists())

    def test_unknown_reference_record_blocks_deletion(self):
        _, work = self.completed()
        parent = self.root / 'maintenance/upgrades';parent.mkdir(mode=0o700)
        (parent / str(materials.uuid.uuid4())).mkdir(mode=0o700)
        result = materials.collect(self.root, self.lock, 0, 0, True)
        self.assertEqual(result['eligible'], [])
        self.assertTrue(work.exists())

    def test_changed_inode_or_added_content_is_preserved(self):
        _, work = self.completed()
        first = work / 'first'
        replacement = work / 'new';replacement.write_bytes(b'first');replacement.chmod(0o600)
        replacement.replace(first)
        result = materials.collect(self.root, self.lock, 0, 0, True)
        self.assertEqual(result['eligible'], [])
        self.assertTrue((work / 'second').exists())

    def test_recorded_partial_removal_resumes_without_guessing_unknown_paths(self):
        record, work = self.completed()
        actual = Path.unlink
        interrupted = False
        def remove(path, *args, **kwargs):
            nonlocal interrupted
            if path == work / 'first' and not interrupted:
                actual(path, *args, **kwargs);interrupted = True
                raise InterruptedError('fixture kill after first removal')
            return actual(path, *args, **kwargs)
        with patch.object(Path, 'unlink', remove):
            with self.assertRaises(InterruptedError):materials.collect(self.root, self.lock, 0, 0, True)
        self.assertEqual(json.loads(record.read_bytes())['phase'], 'collecting')
        materials.collect(self.root, self.lock, 0, 0, True)
        self.assertFalse(work.exists())

    def test_lock_and_creation_window_authority_are_required(self):
        with tempfile.TemporaryFile() as unrelated:
            with self.assertRaises(ValueError):materials.begin(self.root, 'download', unrelated.fileno())
        record, work = materials.begin(self.root, 'download', self.lock)
        value = json.loads(record.read_bytes());value['directory'] = None
        materials.save(record, value)
        inode = work.stat().st_ino
        with self.assertRaises(ValueError):materials.begin(self.root, 'download', self.lock, value['operation_id'])
        self.assertEqual(work.stat().st_ino, inode)

    def test_installation_creation_material_is_retained_until_outer_install_completes(self):
        operation = str(materials.uuid.uuid4())
        parent = self.root/'maintenance/install';parent.mkdir(mode=0o700)
        work = parent/operation;work.mkdir(mode=0o700)
        parent_info, work_info = parent.stat(), work.stat()
        authority = dict(version=1, operation_id=operation, root=str(self.root), parent_device=parent_info.st_dev,
                         parent_inode=parent_info.st_ino, directory_device=work_info.st_dev, directory_inode=work_info.st_ino)
        for path, value in [(parent/(operation+'.json'),authority),(work/'created.json',dict(operation_id=operation,complete=True)),
                            (self.root/'maintenance/install.json',dict(operation_id=operation,phase='startup-restored'))]:
            path.write_text(json.dumps(value));path.chmod(0o600)
        materials.record_install(self.root,operation,self.lock)
        self.assertEqual(materials.collect(self.root,self.lock,0,0,True)['eligible'],[])
        materials.save(self.root/'maintenance/install.json',dict(operation_id=operation,phase='complete'))
        materials.collect(self.root,self.lock,0,0,True)
        self.assertFalse(work.exists());self.assertFalse((parent/(operation+'.json')).exists())
        self.assertTrue((self.root/'maintenance/install.json').exists())


if __name__ == '__main__': unittest.main()
