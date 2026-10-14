import os
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import unit_validation
import upgrade


class LoadedUnitTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)/'installed root%'
        self.template=b'[Service]\nUser=isarmg-xocs\nExecStart="@ROOT@/bin/xocs" --root "@ROOT@"\n'
        self.paths=[str(self.root/'state'),str(self.root/'logs'),str(self.root/'run')]
        (self.root/'state').mkdir(mode=0o700,parents=True)
        mocked=patch.object(upgrade,'service_identity',return_value=(os.geteuid(),os.getegid()))
        mocked.start();self.addCleanup(mocked.stop)
        self.unit=Path('/etc/systemd/system/xocs.service')
        self.dropin=Path('/etc/systemd/system/xocs.service.d/state.conf')
        self.observation=('LoadState=loaded\nFragmentPath='+str(self.unit)+'\nDropInPaths='+str(self.dropin)+'\nNeedDaemonReload=no\n').encode()
        self.manifest={'identity':{'product':'xocs'},'services':[{'name':'xocs.service','path':'share/systemd/xocs.service','role':'server'}]}
        self.report={'writable_paths':self.paths,'data_dir':str(self.root/'state')}

    def readers(self,unit=None,writable=None):
        values={self.root/'share/systemd/xocs.service':self.template,
                self.unit:unit_validation.template_bytes(self.template,self.root,'xocs') if unit is None else unit,
                self.dropin:unit_validation.writable_bytes(self.paths) if writable is None else writable}
        def read(path,*args,**kwargs):return values[path]
        return read

    def test_current_loaded_fragment_and_exact_declared_dropin_match(self):
        with patch.object(upgrade,'process',return_value=self.observation) as systemd,patch.object(upgrade,'controlled_chain') as parents,patch.object(upgrade.package,'bytes_regular',side_effect=self.readers()) as files:
            upgrade.verify_installed_units(self.root,self.manifest,self.report,120)
            self.assertEqual(systemd.call_args.args[0][1],'show')
            self.assertEqual(parents.call_count,2)
            self.assertEqual(files.call_count,3)
            self.assertEqual(files.call_args.kwargs['expected'],(0o644,0))

    def test_wrong_loaded_root_alias_override_or_pending_reload_never_reads_arbitrary_files(self):
        for changed in [self.observation.replace(b'FragmentPath=/etc/systemd/system/xocs.service',b'FragmentPath=/etc/shadow'),
                        self.observation.replace(b'NeedDaemonReload=no',b'NeedDaemonReload=yes'),
                        self.observation.replace(b'DropInPaths=',b'DropInPaths=/etc/systemd/system/xocs.service.d/extra.conf '),
                        self.observation+b'LoadState=loaded\n']:
            with patch.object(upgrade,'process',return_value=changed) as systemd,patch.object(upgrade.package,'bytes_regular') as files,self.assertRaises(ValueError):
                upgrade.verify_installed_units(self.root,self.manifest,self.report,120)
            files.assert_not_called()
            self.assertEqual(systemd.call_count,1)
            self.assertNotIn('stop',systemd.call_args.args[0])

    def test_wrong_exec_root_or_writable_contract_is_refused_before_stop(self):
        for unit,writable in [(b'[Service]\nExecStart=/another/root/bin/xocs --root /another/root\n',None),
                              (None,b'[Service]\nReadWritePaths=/another/state\n')]:
            with patch.object(upgrade,'process',return_value=self.observation) as systemd,patch.object(upgrade,'controlled_chain'),patch.object(upgrade.package,'bytes_regular',side_effect=self.readers(unit,writable)),self.assertRaises(ValueError):
                upgrade.verify_installed_units(self.root,self.manifest,self.report,120)
            self.assertEqual(systemd.call_count,1)
            self.assertNotIn('stop',systemd.call_args.args[0])

    def test_changed_nss_groups_or_private_state_owner_prevent_any_service_operation(self):
        for mode in ('nss','state-group'):
            supplied={'side_effect':upgrade.ServiceIdentityError('supplementary group mismatch')} if mode=='nss' else {'return_value':(os.geteuid(),os.getegid()+1)}
            with self.subTest(mode=mode),patch.object(upgrade,'service_identity',**supplied),patch.object(upgrade,'process') as systemd,patch.object(upgrade.package,'bytes_regular') as files,self.assertRaises(upgrade.ServiceIdentityError):
                upgrade.verify_installed_units(self.root,self.manifest,self.report,120)
            systemd.assert_not_called();files.assert_not_called()


if __name__=='__main__':unittest.main()
