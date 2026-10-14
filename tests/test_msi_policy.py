import copy
import json
import os
import shutil
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import msi_policy
from sbom import run

# A standalone source fixture exercises effects without relying on sibling
# product repositories or pretending that a compiled MSI ran on this host.
AUTHORING='''<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs"
 xmlns:ui="http://wixtoolset.org/schemas/v4/wxs/ui"
 xmlns:util="http://wixtoolset.org/schemas/v4/wxs/util">
 <Package Name="fixture" Manufacturer="sarmg" UpgradeCode="01234567-0123-0123-0123-012345678901"
 Version="$(var.ProductVersion)" Scope="perMachine" InstallerVersion="500">
  <Property Id="WINDOWSBUILD"><RegistrySearch Id="WindowsBuild" Root="HKLM" Key="SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" Name="CurrentBuildNumber" Type="raw" Bitness="always64" /></Property>
  <ui:WixUI Id="WixUI_InstallDir" InstallDirectory="INSTALLFOLDER" />
  <StandardDirectory Id="ProgramFiles64Folder"><Directory Id="INSTALLFOLDER" Name="Fixture">
   <Component Id="ServiceComponent" Guid="01234567-0123-0123-0123-012345678901" Bitness="always64">
    <File Id="ClientExe" Name="fixture.exe" Source="$(var.ClientExe)" KeyPath="yes" />
    <Environment Id="MachinePath" Name="PATH" Value="[INSTALLFOLDER]" Action="set" Part="last" Permanent="no" System="yes" />
    <RegistryValue Root="HKLM" Key="Software\\sarmg\\fixture" Name="InstallLocation" Type="string" Value="[INSTALLFOLDER]" />
    <RegistryValue Root="HKLM" Key="Software\\sarmg\\fixture" Name="Enabled" Type="integer" Value="1" />
    <ServiceInstall Id="SvcInstall" Name="FixtureSvc" DisplayName="Fixture" Description="Fixture service description"
     Type="ownProcess" Start="demand" ErrorControl="normal" Account="NT AUTHORITY\\LocalService"
     Arguments="--windows-service --config &quot;[CommonAppDataFolder]Fixture&quot;">
     <util:ServiceConfig FirstFailureActionType="restart" SecondFailureActionType="restart" ThirdFailureActionType="restart"
      ResetPeriodInDays="1" RestartServiceDelayInSeconds="60" />
    </ServiceInstall>
    <ServiceControl Id="SvcControl" Name="FixtureSvc" Stop="both" Remove="uninstall" Wait="yes" />
   </Component>
  </Directory></StandardDirectory>
  <Feature Id="ProductFeature" Level="1"><ComponentRef Id="ServiceComponent" /></Feature>
  <CustomAction Id="PrepareSetup" FileRef="ClientExe" ExeCommand="installer prepare-setup" Execute="commit" Impersonate="no" Return="check" />
  <InstallExecuteSequence><Custom Action="PrepareSetup" After="InstallFiles" Condition="NOT REMOVE~=&quot;ALL&quot;" /></InstallExecuteSequence>
 </Package>
</Wix>'''


class MsiPolicyTests(unittest.TestCase):
    @unittest.skipUnless(os.name=='nt','actual WiX and Windows Installer COM database')
    def test_actual_wix_msi_tables_preserve_rows_and_reject_unreviewed_actions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve(strict=True)
            executable=root/'fixture.exe';shutil.copyfile(sys.executable,executable)
            wix=shutil.which('wix')
            self.assertIsNotNone(wix,'Windows producer gate requires exact WiX 4.0.6')
            environment=dict(os.environ)
            version=run([wix,'--version'],root,environment,maximum=8192,timeout=30).decode().strip()
            self.assertTrue(version=='4.0.6' or version.startswith('4.0.6+'),version)
            for extension in ('WixToolset.UI.wixext','WixToolset.Util.wixext'):
                run([wix,'extension','add','-g',extension+'/4.0.6'],root,environment,maximum=1024*1024,timeout=120)
            source=root/'fixture.wxs';source.write_text(AUTHORING,encoding='utf-8')
            policy=msi_policy.create(source,root/'stage','1.0.0','a'*40)
            for altered in (False,True):
                if altered:
                    source.write_text(AUTHORING.replace('</Package>',
                        '<CustomAction Id="Unreviewed" FileRef="ClientExe" ExeCommand="unreviewed native effect" Execute="deferred" Impersonate="no" Return="check" /></Package>'),encoding='utf-8')
                artifact=root/('altered.msi' if altered else 'actual.msi')
                run([wix,'build','-arch','x64','-ext','WixToolset.UI.wixext','-ext','WixToolset.Util.wixext',
                     '-d','ProductVersion=1.0.0','-d','ClientExe='+str(executable),
                     '-o',str(artifact),str(source)],root,environment,maximum=1024*1024,timeout=120)
                output=root/('altered.json' if altered else 'actual.json')
                run(['powershell.exe','-NoProfile','-NonInteractive','-File',
                     str(Path(msi_policy.__file__).with_name('msi_tables.ps1')),
                     '-Artifact',str(artifact),'-Output',str(output)],root,environment,maximum=8192,timeout=30)
                actual=json.loads(output.read_text(encoding='utf-8'))
                self.assertTrue({'Property','Component','Directory','Registry','InstallExecuteSequence','ServiceInstall'}<=set(actual['table_names']))
                self.assertTrue(all(isinstance(value,str) for value in actual['table_names']))
                self.assertTrue(all(isinstance(row,list) and len(row)==2 for row in actual['properties']))
                self.assertTrue(['ProductName','fixture'] in actual['properties'])
                self.assertEqual(len(actual['services']),1)
                self.assertEqual(len(actual['services'][0]),13)
                self.assertEqual(actual['services'][0][9],'')
                self.assertEqual(len(actual['registry']),2)
                self.assertTrue(all(isinstance(row,list) and len(row)==6 for row in actual['registry']))
                self.assertEqual(actual['remove_files'],[])
                self.assertEqual(actual['app_search'],[['WINDOWSBUILD','WindowsBuild']])
                self.assertEqual(actual['registry_search'],[['WindowsBuild','2','SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion','CurrentBuildNumber','18']])
                self.assertEqual(actual['file_signatures'],[])
                self.assertEqual((actual['template'],actual['installer_version']),('x64;1033',500))
                if altered:
                    self.assertTrue(any(row[0]=='Unreviewed' for row in actual['actions']))
                    with self.assertRaises(ValueError):self.check(policy,actual)
                else:
                    try:self.check(policy,actual)
                    except ValueError:
                        public_fields={'ProductName','Manufacturer','UpgradeCode','ProductVersion','ALLUSERS','MSIINSTALLPERUSER'}
                        print('Actual standalone fixture identity:',json.dumps({key:value for key,value in actual['properties'] if key in public_fields}))
                        print('Declared standalone fixture identity:',json.dumps(policy['package']))
                        print('Actual standalone fixture tables:',json.dumps(actual,sort_keys=True))
                        print('Declared standalone fixture policy:',json.dumps(policy,sort_keys=True))
                        raise

    def fixture(self,authoring=AUTHORING):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        folder=Path(temporary.name);source=folder/'fixture.wxs';source.write_text(authoring)
        policy=msi_policy.create(source,folder/'stage','1.0.0','a'*40)
        # Literal Windows Installer table evidence checks the translation rather
        # than deriving expected rows from the policy implementation itself.
        tables={
            'table_names':['Property','CustomAction','InstallExecuteSequence','File','Component','Directory','ServiceInstall','ServiceControl','Registry','Environment','Wix4ServiceConfig','CheckBox','ListBox','AppSearch','RegLocator','Signature'],
            'properties':[['ProductName','fixture'],['Manufacturer','sarmg'],['UpgradeCode','{01234567-0123-0123-0123-012345678901}'],['ProductVersion','1.0.0'],['ALLUSERS','1']],
            'actions':[['PrepareSetup',3602,'ClientExe','installer prepare-setup'],
                       ['WixUIPrintEula_X64',65,'WixUiCa_X64','PrintEula'],['WixUIValidatePath_X64',65,'WixUiCa_X64','ValidatePath'],
                       ['Wix4SchedServiceConfig_X64',1,'Wix4UtilCA_X64','SchedServiceConfig'],
                       ['Wix4ExecServiceConfig_X64',3073,'Wix4UtilCA_X64','ExecServiceConfig'],
                       ['Wix4RollbackServiceConfig_X64',3329,'Wix4UtilCA_X64','RollbackServiceConfig']],
            'sequence':[['InstallFiles','',200],['PrepareSetup','NOT REMOVE~="ALL"',300],['InstallServices','',400],
                        ['Wix4SchedServiceConfig_X64','NOT REMOVE~="ALL" AND VersionNT > 400',500]],
            'other_sequences':[],
            'services':[['SvcInstall','FixtureSvc','Fixture',16,3,1,'','','NT AUTHORITY\\LocalService','',
                         '--windows-service --config "[CommonAppDataFolder]Fixture"','ServiceComponent','Fixture service description']],
            'service_controls':[['SvcControl','FixtureSvc',162,'',1,'ServiceComponent']],
            'registry':[['GeneratedLocation',2,'Software\\sarmg\\fixture','InstallLocation','[INSTALLFOLDER]','ServiceComponent'],
                        ['GeneratedEnabled',2,'Software\\sarmg\\fixture','Enabled','#1','ServiceComponent']],
            'environment':[['MachinePath','=-*PATH','[~];[INSTALLFOLDER]','ServiceComponent']],
            'ui_checkboxes':[['LicenseAccepted','1'],['WIXUI_EXITDIALOGOPTIONALCHECKBOX','1']],
            'ui_listboxes':[],
            'app_search':[['WINDOWSBUILD','WindowsBuild']],
            'registry_search':[['WindowsBuild',2,'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion','CurrentBuildNumber',18]],
            'file_signatures':[],
            'remove_files':[],
            'service_config':[['FixtureSvc','ServiceComponent',1,'restart','restart','restart',1,60,'','']],
            'components':[['ServiceComponent','01234567-0123-0123-0123-012345678901','INSTALLFOLDER',256,'','ClientExe']],
            'directories':[['TARGETDIR','','SourceDir'],['ProgramFiles64Folder','TARGETDIR','PFiles64'],['INSTALLFOLDER','ProgramFiles64Folder','Fixture']],
            'template':'x64;1033','installer_version':500}
        return policy,tables

    def check(self,policy,tables):
        msi_policy.validate(policy,tables,{'source_revision':'a'*40})

    def test_current_native_effect_contract_matches_literal_table_evidence(self):
        self.check(*self.fixture())

    def test_raw_registry_search_binds_property_target_bitness_and_empty_signature_table(self):
        policy,tables=self.fixture()
        changes=[('app_search',lambda rows:rows[0].__setitem__(0,'INSTALLFOLDER')),
                 ('app_search',lambda rows:rows[0].__setitem__(1,'ForeignSearch')),
                 ('app_search',lambda rows:rows.clear()),
                 ('app_search',lambda rows:rows.append(['FOREIGN','WindowsBuild'])),
                 ('registry_search',lambda rows:rows[0].__setitem__(0,'ForeignSearch')),
                 ('registry_search',lambda rows:rows[0].__setitem__(1,1)),
                 ('registry_search',lambda rows:rows[0].__setitem__(2,'SOFTWARE\\ForeignProduct')),
                 ('registry_search',lambda rows:rows[0].__setitem__(3,'ForeignValue')),
                 ('registry_search',lambda rows:rows[0].__setitem__(4,2)),
                 ('registry_search',lambda rows:rows[0].__setitem__(4,17)),
                 ('registry_search',lambda rows:rows.clear()),
                 ('registry_search',lambda rows:rows.append(['ForeignSearch',2,'SOFTWARE\\ForeignProduct','Value',18])),
                 ('file_signatures',lambda rows:rows.append(['WindowsBuild','arbitrary.exe','','','','','','','']))]
        for field,mutate in changes:
            altered=copy.deepcopy(tables);mutate(altered[field])
            with self.subTest(field=field,mutate=mutate),self.assertRaisesRegex(ValueError,'lookup semantics'):
                self.check(policy,altered)
        for replacement in ('Type="file" Bitness="always64"','Type="raw" Bitness="always32"','Type="raw"'):
            with self.subTest(replacement=replacement),self.assertRaisesRegex(ValueError,'registry search semantics'):
                self.fixture(AUTHORING.replace('Type="raw" Bitness="always64"',replacement))

    def test_source_upgrade_family_uses_the_exact_wix_guid_representation(self):
        source_guid='a0d593e5-31a3-4675-9821-be03d92ad465'
        for authored in (source_guid,'{'+source_guid+'}'):
            policy,tables=self.fixture(AUTHORING.replace('UpgradeCode="01234567-0123-0123-0123-012345678901"','UpgradeCode="'+authored+'"'))
            expected='{A0D593E5-31A3-4675-9821-BE03D92AD465}'
            self.assertEqual(policy['package']['UpgradeCode'],expected)
            tables['properties'][2][1]=expected
            self.check(policy,tables)
            tables['properties'][2][1]='{F0D593E5-31A3-4675-9821-BE03D92AD465}'
            with self.assertRaisesRegex(ValueError,'identity'):self.check(policy,tables)
        with self.assertRaisesRegex(ValueError,'valid upgrade-family GUID'):
            self.fixture(AUTHORING.replace('UpgradeCode="01234567-0123-0123-0123-012345678901"','UpgradeCode="invalid-family"'))

    def test_service_vital_defaults_to_current_wix_no_and_explicit_values_remain_bound(self):
        for declared,expected in ((None,1),('no',1),('yes',32769)):
            source=AUTHORING
            if declared is not None:source=source.replace('ErrorControl="normal" Account=', 'ErrorControl="normal" Vital="'+declared+'" Account=')
            policy,tables=self.fixture(source)
            self.assertEqual(policy['services'][0][5],expected)
            tables['services'][0][5]=expected
            self.check(policy,tables)
            tables['services'][0][5]^=32768
            with self.assertRaisesRegex(ValueError,'services effects'):self.check(policy,tables)

    def test_ui_data_cannot_add_controlled_properties_or_source_undeclared_values(self):
        policy,tables=self.fixture()
        for field,rows in (('ui_checkboxes',[['INSTALLFOLDER','[WindowsFolder]']]),
                           ('ui_checkboxes',[['LicenseAccepted','0'],['WIXUI_EXITDIALOGOPTIONALCHECKBOX','1']]),
                           ('ui_listboxes',[['INSTALLFOLDER',1,'[WindowsFolder]','Undeclared path']])):
            altered=copy.deepcopy(tables);altered[field]=rows
            with self.subTest(field=field,rows=rows),self.assertRaisesRegex(ValueError,'fixed selected SDK source'):
                self.check(policy,altered)
        with self.assertRaisesRegex(ValueError,'selected native installer UI'):
            self.fixture(AUTHORING.replace('InstallDirectory="INSTALLFOLDER"','InstallDirectory="FOREIGNROOT"'))

    def test_unknown_actions_or_changed_privileges_identity_and_native_services_fail(self):
        policy,tables=self.fixture()
        for change in ('unknown','flags','scope','upgrade','platform','service','password','service_binary','component_flags','component_guid','component_condition','directory_parent','directory_name','directory_override'):
            altered=copy.deepcopy(tables)
            if change=='unknown':altered['actions'].append(['Unknown',1,'WixUiCa_X64','Arbitrary'])
            elif change=='flags':altered['actions'][0][1]^=2048
            elif change=='scope':altered['properties'][-1][1]='2'
            elif change=='upgrade':altered['properties'][2][1]='different upgrade family'
            elif change=='platform':altered['template']='Intel;1033'
            elif change=='password':altered['services'][0][9]='hidden-password'
            elif change=='service_binary':altered['components'][0][5]='OtherExecutable'
            elif change=='component_flags':altered['components'][0][3]|=16
            elif change=='component_guid':altered['components'][0][1]='ffffffff-ffff-ffff-ffff-ffffffffffff'
            elif change=='component_condition':altered['components'][0][4]='0'
            elif change=='directory_parent':altered['directories'][2][1]='CommonAppDataFolder'
            elif change=='directory_name':altered['directories'][2][2]='ForeignProduct'
            elif change=='directory_override':altered['properties'].append(['INSTALLFOLDER','[WindowsFolder]'])
            else:altered['services'][0][10]='different runtime entry'
            with self.subTest(change=change),self.assertRaises(ValueError):
                self.check(policy,altered)

    def test_all_native_effect_tables_reject_added_removed_or_changed_authority(self):
        policy,tables=self.fixture()
        changes=[('service_controls',lambda rows:rows[0].__setitem__(1,'OtherService')),
                 ('service_controls',lambda rows:rows.clear()),
                 ('registry',lambda rows:rows[0].__setitem__(2,'Software\\ForeignProduct')),
                 ('registry',lambda rows:rows.append(['Foreign',2,'Software\\Foreign','Enabled','#1','ServiceComponent'])),
                 ('environment',lambda rows:rows[0].__setitem__(1,'=-*SYSTEMROOT')),
                 ('environment',lambda rows:rows[0].__setitem__(2,'[INSTALLFOLDER]')),
                 ('remove_files',lambda rows:rows.append(['Cleanup','ServiceComponent','*','CommonAppDataFolder',3])),
                 ('service_config',lambda rows:rows[0].__setitem__(0,'OtherService')),
                 ('service_config',lambda rows:rows[0].__setitem__(8,'arbitrary executable')),
                 ('service_config',lambda rows:rows[0].__setitem__(7,0)),
                 ('table_names',lambda rows:rows.append('Wix4RemoveFolderEx'))]
        for field,mutate in changes:
            altered=copy.deepcopy(tables);mutate(altered[field])
            with self.subTest(field=field,mutate=mutate),self.assertRaises(ValueError):self.check(policy,altered)

    def test_environment_prefix_order_is_semantic_and_append_is_preserved(self):
        policy,tables=self.fixture();tables['environment'][0][1]='*-=PATH'
        self.check(policy,tables)

    def test_changed_custom_action_condition_or_order_is_rejected(self):
        policy,tables=self.fixture()
        for change in ('condition','order','unexpected_dynamic_schedule','other_execution_path'):
            altered=copy.deepcopy(tables);item=policy['constraints'][0]
            by_name={row[0]:row for row in altered['sequence']}
            if change=='condition':by_name[item['action']][1]='1'
            elif change=='order':by_name[item['action']][2]=by_name[item['anchor']][2]
            elif change=='unexpected_dynamic_schedule':altered['sequence'].append(['Wix4ExecServiceConfig_X64','1',450])
            else:altered['other_sequences'].append(['AdminExecuteSequence','PrepareSetup','1',300])
            with self.subTest(change=change),self.assertRaises(ValueError):self.check(policy,altered)

    def test_unreviewed_authoring_cleanup_and_extensions_fail_before_packaging(self):
        for added in ['<RemoveFile Id="ForeignCleanup" Name="*" On="both" />',
                      '<util:RemoveFolderEx Id="ForeignCleanup" Property="STATEDIRECTORY" On="both" />']:
            altered=AUTHORING.replace('</Component>',added+'</Component>')
            with self.subTest(added=added),self.assertRaises(ValueError):self.fixture(altered)


if __name__=='__main__':unittest.main()
