"""Exercise the maintenance entry point with real records and a simulated manager."""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import types
import unittest
import uuid
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import maintenance
import writer_control
import test_writer_control as fixtures


class MaintenanceResumeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.WriterControlTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.operation = str(uuid.uuid4())
        self.work = self.root / 'maintenance' / 'operations' / self.operation
        self.work.mkdir(parents=True)
        self.fixture.record = self.work / 'startup-control.json'
        self.fixture.start_control()
        self.manifest = {'identity': {'product': 'xcos'}, 'setup': 'bin/setup',
                         'files': [{'path': 'bin/setup', 'sha256': 'a' * 64}],
                         'services': [{'name': name} for name in self.fixture.states]}
        self.args = types.SimpleNamespace(root=self.root, config=None, operation='admin-reset',
            operation_id=self.operation, username='administrator', execute=False,
            minimum_age_seconds=None, keep_completed=None)

    def resume(self, only_cleanup=True):
        output = io.StringIO()
        descriptor = os.open(self.root / 'tool.lock', os.O_CREAT | os.O_RDWR, 0o600)
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(maintenance, 'require_root'))
            stack.enter_context(patch.object(maintenance, 'controlled_chain'))
            stack.enter_context(patch.object(maintenance, 'coordinator_lock', return_value=descriptor))
            stack.enter_context(patch.object(maintenance.package, 'verify', return_value=self.manifest))
            stack.enter_context(patch.object(maintenance, 'service_identity', return_value=(1000, 1000)))
            stack.enter_context(patch.object(maintenance.material_store, 'begin',
                return_value=(self.root / 'materials.json', self.work)))
            completed = stack.enter_context(patch.object(maintenance.material_store, 'complete'))
            credentials = stack.enter_context(patch.object(maintenance, 'credential_input', return_value=b'fixture-password'))
            helper = stack.enter_context(patch.object(maintenance, 'sealed_setup', return_value=b'{}'))
            stack.enter_context(contextlib.redirect_stdout(output))
            maintenance.run(self.args)
            if only_cleanup:
                credentials.assert_not_called()
                helper.assert_not_called()
            else:
                credentials.assert_called_once()
                self.assertEqual(helper.call_count, 2)
            completed.assert_called_once_with(self.root, self.root / 'materials.json', descriptor,
                                              {'startup-control.json'})
        return json.loads(output.getvalue())

    def test_resume_finishes_interrupted_startup_restoration_without_replaying_reset(self):
        self.fixture.fail_reload = True
        with self.assertRaises(ValueError):
            writer_control.restore_startup(self.fixture.record)
        self.assertEqual(writer_control.inspect_control(self.fixture.record)['phase'], 'restore-startup-intent')
        result = self.resume()
        self.assertEqual(result['status'], 'maintenance_startup_restored')
        self.assertEqual(result['operation_id'], self.operation)
        self.assertEqual(writer_control.inspect_control(self.fixture.record)['phase'], 'startup-restored')

    def test_resume_finishes_pending_material_registration_without_replaying_reset(self):
        writer_control.restore_startup(self.fixture.record)
        self.assertEqual(self.resume()['status'], 'maintenance_startup_restored')

    def test_stopped_operation_still_runs_requested_helper_and_check(self):
        self.assertEqual(self.resume(only_cleanup=False), {})
        self.assertEqual(writer_control.inspect_control(self.fixture.record)['phase'], 'startup-restored')

    def test_resume_refuses_changed_service_set(self):
        writer_control.restore_startup(self.fixture.record)
        self.manifest['services'] = self.manifest['services'][:1]
        with self.assertRaises(ValueError):
            self.resume()

    def test_resume_refuses_a_writer_that_has_restarted(self):
        writer_control.restore_startup(self.fixture.record)
        self.fixture.states['xcos.service'].update(ActiveState='active', SubState='running', MainPID='99')
        with self.assertRaises(ValueError):
            self.resume()
