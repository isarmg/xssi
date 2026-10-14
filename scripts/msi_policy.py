"""Compare actual Windows Installer tables with the current reviewed authoring."""
import hashlib
import json
from pathlib import Path
import re
import uuid
import xml.etree.ElementTree as ET
import release_sbom as sbom
from release_manifest import bounded

POLICY='share/msi-install-policy.json'
UI='http://wixtoolset.org/schemas/v4/wxs/ui'
UTIL='http://wixtoolset.org/schemas/v4/wxs/util'
CORE='http://wixtoolset.org/schemas/v4/wxs'
# WiX 4.0.6 WindowsInstallerStandard.cs definitions used by current authoring.
STANDARD_DIRECTORIES={'TARGETDIR':'SourceDir','ProgramFiles64Folder':'PFiles64','CommonAppDataFolder':'CommApp','ProgramMenuFolder':'PMenu'}
# Current native authoring uses these standard payload/UI tables. Any other
# table needs an explicit, reviewed effects contract before it may be shipped.
ALLOWED_TABLES=set('ActionText AdminExecuteSequence AdminUISequence AdvtExecuteSequence AppSearch Binary Component Control ControlCondition ControlEvent CustomAction Dialog Directory Environment Error EventMapping Feature FeatureComponents File InstallExecuteSequence InstallUISequence LaunchCondition Media MsiFileHash Property RadioButton Registry RegLocator RemoveFile ServiceControl ServiceInstall TextStyle UIText Upgrade Wix4ServiceConfig _Validation'.split())


def name(node):return node.tag.rsplit('}',1)[-1]


def attributes(node,allowed):
    if set(node.attrib)-set(allowed):
        raise ValueError('review unsupported '+name(node)+' installer attributes')


def boolean(node,key,default):
    value=node.get(key,default)
    if value not in ('yes','no'):raise ValueError('invalid installer boolean '+key)
    return value=='yes'


def owner(node,parents,kind):
    current=parents.get(node)
    while current is not None:
        if name(current)==kind:return current
        current=parents.get(current)
    raise ValueError('installer effect has no exact '+kind+' owner')


def sorted_rows(rows):
    return sorted(rows,key=lambda row:json.dumps(row,separators=(',',':')))


def environment_name(value):
    match=re.fullmatch(r'([=+\-!*]*)(.+)',value)
    if match is None or len(set(match[1]))!=len(match[1]):
        raise ValueError('invalid native environment-variable operation')
    return ''.join(sorted(match[1]))+match[2]


def effects(tree):
    parents={child:parent for parent in tree.iter() for child in parent}
    result={key:[] for key in ('services','service_controls','registry','environment','remove_files','service_config','service_components','directories')}
    result['directories'].append(['TARGETDIR','','SourceDir'])
    for node in tree.iter():
        kind=name(node)
        if kind=='StandardDirectory':
            attributes(node,('Id',))
            identity=node.get('Id')
            if identity not in STANDARD_DIRECTORIES:raise ValueError('review native standard installation directories before packaging')
            # Empty declarations are just optional references; retain directory
            # authority when the source actually declares resources beneath it.
            if len(node) and identity!='TARGETDIR':result['directories'].append([identity,'TARGETDIR',STANDARD_DIRECTORIES[identity]])
        elif kind=='Directory':
            attributes(node,('Id','Name'))
            parent=parents.get(node)
            if parent is None or name(parent) not in ('StandardDirectory','Directory','DirectoryRef'):
                raise ValueError('native installation directory has no reviewed source parent')
            result['directories'].append([node.get('Id'),parent.get('Id'),node.get('Name')])
        elif kind=='ServiceInstall':
            attributes(node,('Id','Name','DisplayName','Description','Type','Start','ErrorControl','Vital','Account','Password','Arguments','LoadOrderGroup','Interactive'))
            component=owner(node,parents,'Component')
            attributes(component,('Id','Guid','Bitness','Directory'))
            row=[node.get('Id'),node.get('Name'),node.get('DisplayName',''),
                 {'ownProcess':16,'shareProcess':32}[node.get('Type')]+(256 if boolean(node,'Interactive','no') else 0),
                 {'auto':2,'demand':3,'disabled':4}[node.get('Start')],
                 {'ignore':0,'normal':1,'severe':2,'critical':3}[node.get('ErrorControl')]+(32768 if boolean(node,'Vital','yes') else 0),
                 node.get('LoadOrderGroup',''),'',node.get('Account',''),node.get('Password',''),
                 node.get('Arguments',''),component.get('Id'),node.get('Description','')]
            result['services'].append(row)
            keypaths=[item.get('Id') for item in component if name(item)=='File' and item.get('KeyPath')=='yes']
            if len(keypaths)!=1 or component.get('Bitness')!='always64':
                raise ValueError('native service needs one exact x64 executable component key path')
            parent=parents.get(component)
            directory=component.get('Directory') or (parent.get('Id') if parent is not None else None)
            if component.get('Guid') in (None,'*'):
                raise ValueError('native service component needs its exact explicit current GUID')
            result['service_components'].append([component.get('Id'),str(uuid.UUID(component.get('Guid').strip('{}'))),directory,256,'',keypaths[0]])
        elif kind=='ServiceControl':
            attributes(node,('Id','Name','Start','Stop','Remove','Wait'))
            event=0
            for attribute,install,uninstall in [('Start',1,16),('Stop',2,32),('Remove',8,128)]:
                value=node.get(attribute)
                if value is not None:
                    if value not in ('install','uninstall','both'):raise ValueError('invalid service-control phase')
                    event+=(install if value in ('install','both') else 0)+(uninstall if value in ('uninstall','both') else 0)
            result['service_controls'].append([node.get('Id'),node.get('Name'),event,'',1 if boolean(node,'Wait','yes') else 0,owner(node,parents,'Component').get('Id')])
        elif kind=='RegistryValue':
            attributes(node,('Id','Root','Key','Name','Type','Value','KeyPath'))
            value=node.get('Value','');value_type=node.get('Type')
            if value_type=='integer':value='#'+value
            elif value_type=='string':value=('#' if value.startswith('#') else '')+value
            else:raise ValueError('review this native registry-value type before packaging')
            result['registry'].append([{'HKCR':0,'HKCU':1,'HKLM':2,'HKU':3}[node.get('Root')],node.get('Key'),node.get('Name',''),value,owner(node,parents,'Component').get('Id')])
        elif kind=='Environment':
            attributes(node,('Id','Name','Value','Action','Part','Permanent','System','Separator'))
            action_=node.get('Action','set')
            prefix={'set':'=','create':'+','remove':'!'}[action_]
            if not boolean(node,'Permanent','no'):prefix+='-'
            if boolean(node,'System','no'):prefix+='*'
            value=node.get('Value','');part=node.get('Part','all');separator=node.get('Separator',';')
            if part=='last':value='[~]'+separator+value
            elif part=='first':value=value+separator+'[~]'
            elif part!='all':raise ValueError('invalid environment-variable append location')
            result['environment'].append([node.get('Id'),environment_name(prefix+node.get('Name','')),value,owner(node,parents,'Component').get('Id')])
        elif kind in ('RemoveFile','RemoveFolder'):
            # These authoring effects are absent from the current clients. Fail
            # instead of silently inventing cleanup authority or wildcard rules.
            raise ValueError('review native file-removal effects before packaging')
        elif node.tag=='{'+UTIL+'}ServiceConfig':
            attributes(node,('FirstFailureActionType','SecondFailureActionType','ThirdFailureActionType','RestartServiceDelayInSeconds','ResetPeriodInDays','ProgramCommandLine','RebootMessage','ServiceName'))
            parent=parents[node];new=name(parent)=='ServiceInstall'
            service=parent.get('Name') if new else node.get('ServiceName')
            if not service:raise ValueError('service recovery configuration has no exact target')
            failures=[node.get(key) for key in ('FirstFailureActionType','SecondFailureActionType','ThirdFailureActionType')]
            if any(value not in ('none','reboot','restart','runCommand') for value in failures):raise ValueError('invalid service recovery action')
            result['service_config'].append([service,owner(node,parents,'Component').get('Id'),int(new),*failures,
                int(node.get('ResetPeriodInDays')) if node.get('ResetPeriodInDays') is not None else None,
                int(node.get('RestartServiceDelayInSeconds')) if node.get('RestartServiceDelayInSeconds') is not None else None,
                node.get('ProgramCommandLine',''),node.get('RebootMessage','')])
    return {key:sorted_rows(rows) for key,rows in result.items()}


def action(attributes):
    allowed={'Id','BinaryRef','FileRef','DllEntry','ExeCommand','Execute','Return','Impersonate','HideTarget','TerminalServerAware','SuppressModularization'}
    if set(attributes)-allowed:raise ValueError('review the current installer custom-action contract')
    sources=[(key,value) for key,value in attributes.items() if key in ('BinaryRef','FileRef')]
    targets=[(key,value) for key,value in attributes.items() if key in ('DllEntry','ExeCommand')]
    if len(sources)!=1 or len(targets)!=1:raise ValueError('custom action needs one exact native source and target')
    kind={'BinaryRef':0,'FileRef':16}[sources[0][0]]+{'DllEntry':1,'ExeCommand':2}[targets[0][0]]
    kind+={'immediate':0,'deferred':1024,'rollback':1280,'commit':1536}[attributes.get('Execute','immediate')]
    kind+={'check':0,'ignore':64}[attributes.get('Return','check')]
    kind+=2048 if attributes.get('Impersonate','yes')=='no' else 0
    kind+=8192 if attributes.get('HideTarget','no')=='yes' else 0
    kind+=16384 if attributes.get('TerminalServerAware','no')=='yes' else 0
    return [attributes['Id'],kind,sources[0][1],targets[0][1]]


def create(source,stage,version,revision):
    source=Path(source);raw=bounded(source,2*1024*1024)
    if b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():raise ValueError('installer authoring contains an unsupported XML declaration')
    tree=ET.fromstring(raw)
    namespaces={node.tag.split('}',1)[0][1:] for node in tree.iter() if node.tag.startswith('{')}
    if not namespaces<={CORE,UI,UTIL}:raise ValueError('review unknown native installer extension namespace')
    products=[node for node in tree.iter() if name(node)=='Package']
    if len(products)!=1 or not re.fullmatch('[0-9a-f]{40}',revision):raise ValueError('installer authoring identity is ambiguous')
    product=products[0]
    if product.get('Scope')!='perMachine':raise ValueError('review installer privilege scope before packaging')
    identity={key:product.get(key) for key in ('Name','Manufacturer','UpgradeCode')}
    # WiX 4.0.6 ParseHelper.GetAttributeGuidValue writes uppercase braced GUIDs
    # into the MSI Property table, even when WXS authoring omits those braces.
    # Bind the exact compiled representation without accepting another UUID.
    try:identity['UpgradeCode']='{'+str(uuid.UUID(identity['UpgradeCode'])).upper()+'}'
    except (ValueError,TypeError,AttributeError) as error:
        raise ValueError('installer source requires its exact valid upgrade-family GUID') from error
    declared=product.get('Version')
    if declared!='$(var.ProductVersion)' and declared!=version:raise ValueError('installer version differs from the exact source')
    identity['Version']=version
    actions=[action(dict(node.attrib)) for node in tree.iter() if name(node)=='CustomAction']
    ui=[node for node in tree.iter() if node.tag=='{'+UI+'}WixUI']
    if len(ui)!=1 or ui[0].get('Id')!='WixUI_InstallDir':raise ValueError('review the exact selected native installer UI')
    actions += [[ 'WixUIPrintEula_X64',65,'WixUiCa_X64','PrintEula'],['WixUIValidatePath_X64',65,'WixUiCa_X64','ValidatePath']]
    extensions=[node for node in tree.iter() if node.tag.startswith('{'+UTIL+'}')]
    if any(name(node)!='ServiceConfig' for node in extensions):raise ValueError('review unknown installer extension effects')
    if extensions:
        actions += [['Wix4SchedServiceConfig_X64',1,'Wix4UtilCA_X64','SchedServiceConfig'],
                    ['Wix4ExecServiceConfig_X64',3073,'Wix4UtilCA_X64','ExecServiceConfig'],
                    ['Wix4RollbackServiceConfig_X64',3329,'Wix4UtilCA_X64','RollbackServiceConfig']]
    constraints=[]
    for container in tree.iter():
        if name(container)=='InstallExecuteSequence':
            for node in container:
                if name(node)!='Custom':continue
                keys=[key for key in ('Before','After') if node.get(key)]
                if len(keys)!=1:raise ValueError('installer action has no single execution-order authority')
                constraints.append({'action':node.get('Action'),'relation':keys[0],'anchor':node.get(keys[0]),'condition':node.get('Condition','')})
    # The WiX 4.0.6 original UtilExtension_Platform.wxi schedules only the
    # immediate scheduler. It dynamically queues rollback/deferred actions.
    if extensions:
        constraints.append({'action':'Wix4SchedServiceConfig_X64','relation':'After','anchor':'InstallServices',
                            'condition':'NOT REMOVE~="ALL" AND VersionNT > 400'})
    policy={'format_version':1,'source_revision':revision,'source_sha256':hashlib.sha256(raw).hexdigest(),
            'package':identity,'installer_version':int(product.get('InstallerVersion','500')),'platform':'x64',
            'actions':sorted(actions),'constraints':constraints,**effects(tree)}
    material=Path(stage)/'share/msi-authoring.wxs'
    material.parent.mkdir(parents=True,exist_ok=True)
    with material.open('xb') as output:output.write(raw)
    material.chmod(0o644)
    destination=Path(stage)/POLICY;destination.parent.mkdir(parents=True,exist_ok=True)
    with destination.open('x') as out:json.dump(policy,out,sort_keys=True,indent=2);out.write('\n')
    destination.chmod(0o644)
    return policy


def validate(policy,tables,identity):
    sbom.fields(policy,['format_version','source_revision','source_sha256','package','installer_version','platform','actions','constraints','services','service_controls','registry','environment','remove_files','service_config','service_components','directories'])
    if policy['format_version']!=1 or policy['source_revision']!=identity['source_revision']:
        raise ValueError('MSI policy differs from its exact current source identity')
    properties=dict(tables['properties'])
    if len(properties)!=len(tables['properties']):raise ValueError('MSI repeats an identity property')
    fields={'Name':'ProductName','Manufacturer':'Manufacturer','UpgradeCode':'UpgradeCode','Version':'ProductVersion'}
    if any(properties.get(fields[key])!=value for key,value in policy['package'].items()) or properties.get('ALLUSERS')!='1' or properties.get('MSIINSTALLPERUSER') not in (None,''):
        raise ValueError('MSI product identity or per-machine privilege scope differs from its current authoring')
    if tables['template'].split(';')[0]!=policy['platform'] or tables['installer_version']!=policy['installer_version']:
        raise ValueError('MSI platform or installer version differs from the current contract')
    actions=[[row[0],int(row[1]),row[2],row[3]] for row in tables['actions']]
    if sorted(actions)!=policy['actions']:raise ValueError('MSI custom-action source, target, execution or privilege flags differ from its current authoring')
    names=tables['table_names']
    if len(set(names))!=len(names) or set(names)-ALLOWED_TABLES:
        raise ValueError('MSI contains an unreviewed installer effects table')
    services=[[row[0],row[1],row[2],int(row[3]),int(row[4]),int(row[5]),*row[6:]] for row in tables['services']]
    controls=[[row[0],row[1],int(row[2]),row[3],int(row[4] or '1'),row[5]] for row in tables['service_controls']]
    registry=[[int(row[1]),*row[2:]] for row in tables['registry']]
    environment=[[row[0],environment_name(row[1]),*row[2:]] for row in tables['environment']]
    recovery=[[row[0],row[1],int(row[2]),*row[3:6],int(row[6]) if row[6] not in ('',None) else None,int(row[7]) if row[7] not in ('',None) else None,*row[8:]] for row in tables['service_config']]
    for field,actual in [('services',services),('service_controls',controls),('registry',registry),('environment',environment),('service_config',recovery),('remove_files',tables['remove_files'])]:
        if sorted_rows(actual)!=policy[field]:raise ValueError('MSI '+field+' effects differ from current source authoring')
    components={row[0]:row for row in tables['components']}
    if len(components)!=len(tables['components']):raise ValueError('MSI repeats a component identity')
    for component,guid,directory,flags,condition,keypath in policy['service_components']:
        actual=components.get(component)
        if actual is None or str(uuid.UUID(actual[1].strip('{}')))!=guid or actual[2]!=directory or actual[5]!=keypath or int(actual[3])!=flags or actual[4]!=condition:
            raise ValueError('MSI service executable component binding differs from current authoring')
    directories={row[0]:row for row in tables['directories']}
    if len(directories)!=len(tables['directories']):raise ValueError('MSI repeats an installation directory identity')
    for identity,parent,target_name in policy['directories']:
        actual=directories.get(identity)
        if actual is None or actual[1]!=parent or actual[2].split(':',1)[0].split('|')[-1]!=target_name:
            raise ValueError('MSI installation directory differs from current source hierarchy')
        if identity in properties:
            raise ValueError('MSI added a source-undeclared installation-directory property override')
    sequence={row[0]:(row[1],int(row[2])) for row in tables['sequence']}
    if len(sequence)!=len(tables['sequence']):raise ValueError('MSI repeats an execution-sequence action')
    scheduled={row[0] for row in actions if row[0] in sequence}
    if scheduled!={item['action'] for item in policy['constraints']}:
        raise ValueError('MSI added or removed a scheduled custom action')
    if any(row[1] in {item[0] for item in actions} for row in tables['other_sequences']):
        raise ValueError('MSI scheduled a native custom action in another execution path')
    for item in policy['constraints']:
        current=sequence.get(item['action']);anchor=sequence.get(item['anchor'])
        if current is None or anchor is None or current[0]!=item['condition'] or ((current[1]<anchor[1])!=(item['relation']=='Before')) or current[1]==anchor[1]:
            raise ValueError('MSI custom-action condition or order differs from its current authoring')
