#!/usr/bin/env python3
"""Download and OS orchestration; Rust XSSC owns upgrade and recovery."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import ssl
import stat
import sys
import tarfile
import time
import urllib.request
import uuid
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import package
import material_store
from unit_validation import loaded_paths, match_bytes
from install import ServiceIdentityError, atomic, controlled_chain, coordinator_lock, directory, process, require_root, sealed_setup, service_identity

class SecureRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        if not url.startswith('https://'):
            raise ValueError('release redirects must retain HTTPS')
        return super().redirect_request(request, response, code, message, headers, url)

def download(url, destination, maximum):
    if not url.startswith('https://'):raise ValueError('release download must use HTTPS')
    request=urllib.request.Request(url,headers={'User-Agent':'xssi/1.0','Accept':'application/vnd.github+json'})
    total=0
    deadline=time.monotonic()+600
    opener=urllib.request.build_opener(SecureRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    with opener.open(request,timeout=30) as response:
        if not response.geturl().startswith('https://'):raise ValueError('download transport was downgraded')
        length=response.headers.get('Content-Length')
        if length is not None and (not length.isdecimal() or int(length)>maximum):
            raise ValueError('declared download size exceeds its byte bound')
        with destination.open('xb') as output:
            while True:
                if time.monotonic()>deadline:raise TimeoutError('release download exceeded its total time bound')
                chunk=response.read(1024*1024)
                if not chunk:break
                total+=len(chunk)
                if total>maximum:raise ValueError('release download exceeds its byte bound')
                output.write(chunk)
            output.flush();os.fsync(output.fileno())
        if length is not None and total!=int(length):raise ValueError('download size differs from Content-Length')
    return total

def extract(archive,destination):
    with tarfile.open(archive,'r:gz') as tar:
        members=[]
        names=set();roots=set();total=0
        for entry in tar:
            members.append(entry)
            if len(members)>package.MAX_FILES+256:raise ValueError('archive entry count exceeds its bound')
            name=PurePosixPath(entry.name)
            if name.is_absolute() or '..' in name.parts or not name.parts or not (entry.isfile() or entry.isdir()):
                raise ValueError('archive entry is not a safe directory or regular file')
            normalized=str(name)
            if normalized in names:raise ValueError('duplicate archive path')
            names.add(normalized);roots.add(name.parts[0]);total+=entry.size
            if entry.size>package.MAX_FILE_BYTES or total>package.MAX_TOTAL_BYTES:raise ValueError('archive exceeds its byte bound')
        if len(roots)!=1 or not members:raise ValueError('archive must have one product package root')
        tar.extractall(destination,members=members,filter='data')
        return destination/next(iter(roots))

def select_asset(release,product,version):
    if product not in package.PRODUCTS or not re.fullmatch(package.VERSION_PATTERN,version):
        raise ValueError('release selection requires a supported product and canonical version')
    if release.get('draft') or release.get('prerelease') or release.get('tag_name')!='v'+version:
        raise ValueError('release does not identify the requested stable tag')
    expected=f'{product}-{version}-linux-x86_64.tar.gz'
    assets=release.get('assets')
    if not isinstance(assets,list) or len(assets)>256:raise ValueError('invalid release asset list')
    candidates=[asset for asset in assets if isinstance(asset,dict) and asset.get('name')==expected]
    if len(candidates)!=1:raise ValueError('release must contain one exact platform archive')
    asset=candidates[0]
    prefix=f'https://github.com/isarmg/{product}/releases/download/v{version}/'
    if asset.get('browser_download_url')!=prefix+expected:raise ValueError('asset is outside the official product release')
    if type(asset.get('size')) is not int or not 0<asset['size']<=package.MAX_TOTAL_BYTES:
        raise ValueError('invalid release archive size')
    digest=asset.get('digest')
    if digest is not None and not re.fullmatch(r'sha256:[0-9a-f]{64}',digest):raise ValueError('invalid asset digest')
    return asset

def resources(report):
    paths=[Path(value) for value in report['state_paths']]
    if not paths or len(paths)>128:raise ValueError('invalid persistent resource coverage')
    paths=sorted(set(paths),key=lambda path:(len(path.parts),str(path)))
    normalized=[]
    for path in paths:
        if any(ancestor.is_dir() and path.is_relative_to(ancestor) for ancestor in normalized):continue
        normalized.append(path)
    output=[]
    for i,path in enumerate(normalized):
        package.private_chain(path.parent if path.is_file() else path)
        if path.is_symlink() or not path.exists():raise ValueError('persistent resource is unsafe or absent')
        name='state' if path==Path(report['data_dir']) else ('config' if path==Path(report['root'])/'config/config.json' else ('logs' if path==Path(report['root'])/'logs' else f'resource-{i}'))
        output.append({'name':name,'path':str(path),'kind':'file' if path.is_file() else 'directory'})
    return output

def verify_installed_units(root,manifest,report,timeout):
    identity=service_identity(manifest['identity']['product'],False,create=False)
    information=package.private_chain(Path(report['data_dir'])).lstat()
    if not stat.S_ISDIR(information.st_mode) or stat.S_IMODE(information.st_mode)!=0o700 or (information.st_uid,information.st_gid)!=identity:
        raise ServiceIdentityError('Private state ownership must match the fixed service UID and primary group before stopping writers.')
    for service in manifest['services']:
        observation=process(['/usr/bin/systemctl','show',service['name'],'--property=LoadState','--property=FragmentPath','--property=DropInPaths','--property=NeedDaemonReload'],timeout=timeout)
        unit,dropin=loaded_paths(service['name'],observation)
        for path in (unit,dropin):controlled_chain(path.parent)
        template=package.bytes_regular(root/service['path'])
        actual_unit=package.bytes_regular(unit,expected=(0o644,0))
        actual_writable=package.bytes_regular(dropin,expected=(0o644,0))
        match_bytes(root,manifest['identity']['product'],template,report['writable_paths'],actual_unit,actual_writable,report.get('readonly_paths',[]))

def run(args):
    require_root()
    root=package.private_chain(args.root.absolute())
    controlled_chain(root)
    if args.config is not None and args.config.absolute()!=root/'config/config.json':raise ValueError('config must identify ROOT/config/config.json')
    lock=coordinator_lock(root)
    try:
        return locked_run(args,root,lock)
    finally:os.close(lock)

def locked_run(args,root,tool_lock_fd=None):
    source=package.verify(root,installed=True)
    product=source['identity']['product']
    if product not in package.PRODUCTS or not re.fullmatch(package.VERSION_PATTERN,args.version):
        raise ValueError('unsupported product or explicit version')
    if source['identity']['version']==args.version:raise ValueError('requested version is already installed')
    material_record,work=material_store.begin(root,'download',tool_lock_fd)
    info=work/'release-api.json'
    download(f'https://api.github.com/repos/isarmg/{product}/releases/tags/v{args.version}',info,1024*1024)
    release=package.loads(package.bytes_regular(info))
    asset=select_asset(release,product,args.version)
    archive=work/'release.tar.gz'
    if download(asset['browser_download_url'],archive,package.MAX_TOTAL_BYTES)!=asset['size']:
        raise ValueError('release download differs from API size')
    if asset.get('digest') is not None:
        hash=hashlib.sha256()
        with archive.open('rb') as stream:
            for chunk in iter(lambda:stream.read(1024*1024),b''):hash.update(chunk)
        if 'sha256:'+hash.hexdigest()!=asset['digest']:raise ValueError('release archive differs from API digest')
    unpack=work/'unpacked';directory(unpack,0o755)
    target=extract(archive,unpack)
    manifest=package.verify(target)
    if manifest['identity']['product']!=product or manifest['identity']['version']!=args.version:
        raise ValueError('verified package identity differs from the requested release')
    # Download and full SHA256/hash/permissions verification finish before any writer is stopped.
    identity=service_identity(product,False,create=False)
    source_helper=next(e for e in source['files'] if e['path']==source['setup'])
    report=package.loads(sealed_setup(root/source['setup'],source_helper['sha256'],['--product',product,'--root',str(root),'--json','--service-uid',str(identity[0]),'--service-gid',str(identity[1]),'config-validate'],None,tool_lock_fd=tool_lock_fd))
    if report['product']!=product or Path(report['root'])!=root or report['schema_identity']!=source['schema_identity']:
        raise ValueError('source configuration report differs from trusted installed metadata')
    protected=resources(report)
    address=report['bind']
    if address.startswith('0.0.0.0:'):address='127.0.0.1:'+address.rsplit(':',1)[1]
    if address.startswith('[::]:'):address='[::1]:'+address.rsplit(':',1)[1]
    operation=root/'maintenance/upgrades'/str(uuid.uuid4())
    directory(operation.parent,0o700)
    writers=source['services']
    if manifest['services']!=writers:raise ValueError('automatic upgrade cannot silently add or drop state-writer units')
    for service in writers:
        old=next(entry for entry in source['files'] if entry['path']==service['path'])
        new=next(entry for entry in manifest['files'] if entry['path']==service['path'])
        if old!=new:raise ValueError('automatic upgrade cannot change the installed systemd contract')
    services=[e['name'] for e in writers]
    main=next(e for e in writers if e['role']=='server')
    plan={'plan_version':1,'service':main['name'],
          'additional_services':[{'role':e['role'],'service':e['name']} for e in writers if e['role']!='server'],
          'installed_binary':str(root/source['server']),'target_binary':str(target/manifest['server']),
          'release_manifest':str(target/package.MANIFEST),'release_checksum':str(target/package.CHECKSUM),
          'config':str(root/'config/config.json'),'data_dir':report['data_dir'],'resources':protected,
          'work_directory':str(operation),'readiness_address':address,
          'timeout_seconds':args.timeout,'max_backup_bytes':args.max_backup_bytes,
          'native_release':{'root':str(root),'source_manifest':str(root/package.MANIFEST)}}
    plan_path=work/'upgrade-plan.json';atomic(plan_path,(json.dumps(plan,sort_keys=True)+'\n').encode())
    expected_materials={'release-api.json','release.tar.gz','upgrade-plan.json'}
    expected_materials.update(str((target/entry['path']).relative_to(work)) for entry in manifest['files'])
    expected_materials.update(str((target/name).relative_to(work)) for name in [package.MANIFEST,package.CHECKSUM])
    # XSSC is an independently installed root-controlled tool. Seal one exact
    # executable for apply and recovery; do not reopen an untrusted path later.
    xssc=args.xssc.absolute()
    package.private_chain(xssc.parent)
    for parent in xssc.parents:
        info=parent.lstat()
        if info.st_uid!=0 or info.st_mode&0o022:raise ValueError('XSSC parent directory is not root controlled')
    xssc_bytes=package.bytes_regular(xssc,package.MAX_FILE_BYTES,(0o755,0))
    xssc_digest=hashlib.sha256(xssc_bytes).hexdigest()
    support=package.loads(sealed_setup(xssc,xssc_digest,['support','--json'],None,timeout=args.timeout))
    if support.get('release_upgrade_protocol')!='fixed-root-payload-v1' or support.get('compiled_target')!='x86_64-unknown-linux-gnu':
        raise ValueError('installed XSSC does not implement the sole fixed-root upgrade protocol')
    products=support.get('products',[])
    if not any(entry.get('product')==product and entry.get('release_upgrade') is True and entry.get('durable_recovery') is True for entry in products if isinstance(entry,dict)):
        raise ValueError('installed XSSC does not support this product upgrade and recovery')
    verify_installed_units(root,source,report,args.timeout)
    try:
        output=sealed_setup(xssc,xssc_digest,['--json','apply-upgrade','--plan',str(plan_path)],None,timeout=args.operation_timeout,tool_lock_fd=tool_lock_fd)
        material_store.complete(root,material_record,tool_lock_fd,expected_materials)
        print(output.decode().strip())
    except Exception:
        # XSSC reestablishes its recorded startup inhibition before stopping
        # writers for recovery; restoration still requires loss authorization.
        if (operation/'upgrade.json').exists():
            sealed_setup(xssc,xssc_digest,['--json','recover-upgrade','--work-directory',str(operation)],None,timeout=args.operation_timeout,tool_lock_fd=tool_lock_fd)
            material_store.complete(root,material_record,tool_lock_fd,expected_materials)
        raise

def main():
    parser=package.MachineParser()
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--config',type=Path)
    parser.add_argument('--json',action='store_true')
    parser.add_argument('--version',required=True)
    parser.add_argument('--xssc',type=Path,default=Path('/usr/local/bin/xssc'))
    parser.add_argument('--timeout',type=int,default=120)
    parser.add_argument('--operation-timeout',type=int,default=24*60*60)
    parser.add_argument('--max-backup-bytes',type=int,default=1024**4)
    args=parser.parse_args()
    if not 1<=args.timeout<=600 or not 1<=args.operation_timeout<=7*24*60*60 or args.max_backup_bytes<=0:parser.error('invalid resource/time budget')
    try:run(args)
    except ServiceIdentityError as failure:
        if args.json: print(json.dumps({'error':{'code':'SERVICE_IDENTITY_INVALID','message':str(failure),'retryable':False}}))
        else: print(str(failure),file=sys.stderr)
        raise SystemExit(1)
    except Exception:
        message='Automatic upgrade failed. Verified downloads and recovery journals were preserved; inspect the recorded startup controls and XSSC recovery before manually starting services.'
        if args.json:print(json.dumps({'error':{'code':'UPGRADE_FAILED','message':message,'retryable':False}}))
        else:print(message,file=sys.stderr)
        raise SystemExit(1)

if __name__=='__main__':main()
