from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import install


class ServiceIdentityTests(unittest.TestCase):
    def test_primary_gid_and_supplementary_memberships_are_readonly_checked(self):
        for primary,group,members,valid in [(1002,1002,[1002],True),(1002,1003,[1002],False),
                                          (1002,1002,[1002,2000],False),(0,0,[0],False)]:
            entry=types.SimpleNamespace(pw_uid=1001,pw_gid=primary)
            with self.subTest(primary=primary,group=group,members=members),patch.object(install.pwd,'getpwnam',return_value=entry),patch.object(install.grp,'getgrnam',return_value=types.SimpleNamespace(gr_gid=group)),patch.object(install.os,'getgrouplist',return_value=members),patch.object(install,'process') as mutation:
                if valid:self.assertEqual(install.service_identity('xczs',False,create=False),(1001,1002))
                else:
                    with self.assertRaises(install.ServiceIdentityError):install.service_identity('xczs',False,create=False)
                mutation.assert_not_called()

    def test_upgrade_missing_account_never_creates_or_changes_users(self):
        with patch.object(install.pwd,'getpwnam',side_effect=KeyError),patch.object(install,'process') as mutation:
            with self.assertRaises(install.ServiceIdentityError):install.service_identity('xocs',False,create=False)
            mutation.assert_not_called()


if __name__=='__main__':unittest.main()
