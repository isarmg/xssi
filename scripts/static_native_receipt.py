"""Bind the actual XCOC static media link closure to final release targets."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import tarfile
import tempfile
from urllib.parse import urlsplit, urlunsplit

import frontend_receipt
import release_sbom as release
from release_manifest import bounded
from sbom import run

MAX_INPUT=256*1024*1024
FFMPEG_LIBRARIES={'avformat','avcodec','avutil'}
UNIX_SYSTEM={'c','m','dl','pthread','rt','gcc','gcc_s'}
# Schannel's CNG key storage uses the Windows SDK Ncrypt.lib/Ncrypt.dll:
# https://learn.microsoft.com/windows/win32/api/ncrypt/nf-ncrypt-ncryptopenstorageprovider
WINDOWS_SYSTEM={'advapi32','bcrypt','crypt32','gdi32','kernel32','ncrypt','ole32','oleaut32','secur32','shell32','user32','uuid','vfw32','ws2_32','strmiids','mfplat','mfuuid','dxva2','d3d11','d3d12','dxgi','avrt'}
DEBIAN_HOSTS={'deb.debian.org','security.debian.org','archive.debian.org','snapshot.debian.org','archive.ubuntu.com','security.ubuntu.com','ports.ubuntu.com'}


def environment():
    return {name:value for name,value in os.environ.items()
            if not any(part in name.upper() for part in ('TOKEN','PASSWORD','SECRET','SIGNING','PRIVATE_KEY'))}


def command(arguments,cwd,env,maximum=4*1024*1024):
    return run(arguments,cwd,env,maximum=maximum,timeout=120).decode('utf-8')


def control(value):
    result={};name=None
    for line in value.splitlines():
        if not line.strip():continue
        if line.startswith((' ','\t')):
            if name is None:raise ValueError('native package control has an orphan continuation')
            result[name]+='\n'+line[1:]
            continue
        name,separator,body=line.partition(':')
        if not separator or name in result:raise ValueError('native package control is ambiguous')
        result[name]=body.strip()
    return result


def tar_files(raw):
    files={};total=0;entries=0
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:*') as archive:
        for member in archive:
            entries+=1
            if entries>16384:
                raise ValueError('native source archive entry count exceeds its bound')
            if not member.isfile():continue
            name=member.name.removeprefix('./')
            release.relative(name)
            if type(member.size)is not int or member.size<0:
                raise ValueError('native source archive file size is invalid')
            total+=member.size
            if name in files or len(files)>=16384 or member.size>MAX_INPUT or total>2*MAX_INPUT:
                raise ValueError('native source archive exceeds its extraction bound')
            value=archive.extractfile(member).read(member.size+1)
            if len(value)!=member.size:raise ValueError('native source archive member size differs')
            files[name]=value
    return files


def put(stage,path,contents):
    path=release.relative(path)
    target=frontend_receipt.retain(stage,path,contents)
    return {'path':path,'sha256':release.digest(target)}


def component(stage,label,name,version,source,archives,notices,targets,inventory):
    if not re.fullmatch('[A-Za-z0-9_.+-]+',label):raise ValueError('native evidence label is invalid')
    if not archives:raise ValueError('native component has no actual static archives')
    inputs=[]
    for path in archives:
        contents=bounded(path,MAX_INPUT)
        if not contents.startswith(b'!<arch>\n'):raise ValueError('static native build input is not an actual archive')
        inputs.append(put(stage,inventory+'/build-inputs/native/'+label+'/'+path.name,contents))
    licenses=[]
    for license_name,filename,contents in notices:
        if not contents.strip():raise ValueError('native upstream license is empty')
        entry=put(stage,inventory+'/licenses/native/'+label+'/'+filename,contents)
        licenses.append({'name':license_name,**entry})
    if not licenses:raise ValueError('native component has no original upstream license')
    return {'ref':'urn:static-native:'+label+':'+source['sha256'],'type':'library','name':name,'version':version,
            'source':source,'licenses':licenses,'delivery':'embedded','files':targets,'dependencies':[],
            'embedding':{'kind':'static-link','input_root':'stage','source_files':inputs,'target_files':targets}}


class DebianSources:
    def __init__(self,work,env):
        self.work=work;self.env=env;self.cache={};self.downloaded=0

    def owner(self,path):
        matches=command(['dpkg-query','-S',str(path)],self.work,self.env).splitlines()
        owners=[]
        for line in matches:
            package,separator,filename=line.rpartition(': ')
            if separator and filename==str(path):owners.append(package)
        if len(owners)!=1:raise ValueError('native archive has no unique actual distro package owner')
        data=command(['dpkg-query','-W','-f=${binary:Package}\n${Version}\n${Architecture}\n',owners[0]],self.work,self.env).splitlines()
        if len(data)!=3:raise ValueError('native distro package identity is incomplete')
        return data

    def package(self,identity):
        name,version,architecture=identity
        if not re.fullmatch('[A-Za-z0-9+.-]+(?::[a-z0-9]+)?',name) or not version or any(character.isspace() for character in version) or not re.fullmatch('[a-z0-9]+',architecture):
            raise ValueError('native distro package identity is invalid')
        key=(name,version,architecture)
        if key in self.cache:return self.cache[key]
        specification=name+'='+version
        metadata=control(command(['apt-cache','show','--no-all-versions',specification],self.work,self.env))
        if metadata.get('Package')!=name.split(':',1)[0] or metadata.get('Version')!=version or metadata.get('Architecture')!=architecture:
            raise ValueError('official native package metadata differs from the selected identity')
        expected=release.sha(metadata['SHA256'])
        lines=command(['apt-get','--print-uris','download',specification],self.work,self.env).splitlines()
        entries=[shlex.split(line) for line in lines if line.startswith("'")]
        if len(entries)!=1 or len(entries[0])!=4:raise ValueError('official native package has no unique distribution URI')
        url,filename,size,checksum=entries[0]
        parsed=urlsplit(url)
        if parsed.hostname not in DEBIAN_HOSTS or parsed.scheme not in ('http','https'):
            raise ValueError('native package distribution is not an official distro origin')
        url=urlunsplit(parsed._replace(scheme='https'))
        if not size.isdigit() or int(size)>MAX_INPUT or checksum!='SHA256:'+expected:
            raise ValueError('native distro package download is not exact SHA-256 metadata')
        raw=frontend_receipt.download(url,expected)
        self.downloaded+=len(raw)
        if len(raw)!=int(size) or self.downloaded>MAX_INPUT:raise ValueError('native distro package downloads exceed their aggregate bound')
        with tempfile.TemporaryDirectory(prefix='xssi-native-deb-') as temporary:
            archive=Path(temporary)/'source.deb';archive.write_bytes(raw)
            actual=control(command(['dpkg-deb','-f',str(archive)],self.work,self.env))
            if any(actual.get(field)!=value for field,value in [('Package',name.split(':',1)[0]),('Version',version),('Architecture',architecture)]):
                raise ValueError('actual native distro archive identity differs')
            contents=run(['dpkg-deb','--fsys-tarfile',str(archive)],self.work,self.env,maximum=2*MAX_INPUT,timeout=120)
        result={'source':{'url':url,'sha256':expected},'files':tar_files(contents),'metadata':metadata,'identity':identity}
        self.cache[key]=result
        return result

    def origin(self,path):
        path=path.resolve(strict=True)
        dependency_root=self.work/'dependency-root'
        if dependency_root.exists() and path.is_relative_to(dependency_root):
            logical=path.relative_to(dependency_root).as_posix()
            candidates=[]
            for archive in (self.work/'dependency-packages').glob('*.deb'):
                actual=control(command(['dpkg-deb','-f',str(archive)],self.work,self.env))
                identity=(actual['Package']+':'+actual['Architecture'],actual['Version'],actual['Architecture'])
                selected=self.package(identity)
                if selected['files'].get(logical) is not None and hashlib.sha256(selected['files'][logical]).hexdigest()==release.digest(path):
                    if release.digest(archive)!=selected['source']['sha256']:raise ValueError('private extracted dependency differs from its official archive')
                    candidates.append((selected,logical))
            if len(candidates)!=1:raise ValueError('private native archive has no unique actual distro origin')
            return candidates[0]
        selected=self.package(self.owner(path))
        logical=path.relative_to('/').as_posix()
        if logical not in selected['files'] or hashlib.sha256(selected['files'][logical]).hexdigest()!=release.digest(path):
            raise ValueError('actual system static archive differs from its owning official distro archive')
        return selected,logical

    def license_source(self,selected):
        name=selected['identity'][0].split(':',1)[0]
        logical='usr/share/doc/'+name+'/copyright'
        if logical in selected['files']:
            return {'contents':selected['files'][logical],'distribution':selected['source'],'package_path':logical}
        # GCC development packages point at a separately packaged shared
        # copyright file. Resolve its actual owner; never borrow libatomic1.
        actual=(Path('/')/logical).resolve(strict=True)
        document=self.package(self.owner(actual))
        logical=actual.relative_to('/').as_posix()
        contents=document['files'].get(logical)
        if contents is None or hashlib.sha256(contents).hexdigest()!=release.digest(actual):
            raise ValueError('native copyright differs from its exact owning distro archive')
        return {'contents':contents,'distribution':document['source'],'package_path':logical}


def native_configuration(path):
    result={}
    for line in bounded(path,4*1024*1024).decode().splitlines():
        if line.startswith('CONFIG_'):
            name,separator,value=line.partition('=')
            if not separator or name in result:raise ValueError('native build configuration is ambiguous')
            result[name]=value
    if result.get('CONFIG_STATIC')!='yes' or result.get('CONFIG_SHARED') not in (None,'no') or result.get('CONFIG_GPL')=='yes' or result.get('CONFIG_NONFREE')=='yes':
        raise ValueError('native media build is not the approved redistributable static configuration')
    return result


def link_closure(prefix,work,env,windows):
    tool=str(prefix/'tools/pkgconf/pkgconf.exe') if windows else 'pkg-config'
    env=dict(env,PKG_CONFIG_PATH=str(prefix/'lib/pkgconfig'))
    output=command([tool,'--libs','--static','libavformat','libavcodec','libavutil'],work,env,32768)
    libraries=set();frameworks=set();tokens=shlex.split(output,posix=not windows)
    pending_framework=False
    for token in tokens:
        if pending_framework:
            if not re.fullmatch('[A-Za-z0-9_]+',token):raise ValueError('native framework name is invalid')
            frameworks.add(token);pending_framework=False
        elif token=='-framework':pending_framework=True
        elif token.startswith('-l'):libraries.add(token[2:])
        elif token.startswith('-L') or token in ('-pthread','-Wl,-Bsymbolic'):continue
        else:raise ValueError('native static closure has an unsupported linker argument')
    if pending_framework or not FFMPEG_LIBRARIES<=libraries:raise ValueError('native static closure is incomplete')
    return libraries,frameworks


def pc_libraries(contents):
    value=contents.decode('utf-8')
    bodies=re.findall(r'^(?:Libs|Libs\.private):([^\n]*)',value,re.M)
    return {name for body in bodies for name in re.findall(r'(?:^|\s)-l([A-Za-z0-9_.+-]+)(?=\s|$)',body)}


def verify_windows_copyright(installed,license_,license_md):
    # vcpkg e456309 scripts/cmake/vcpkg_install_copyright.cmake assembles
    # these exact two files, including basenames and blank lines. CMake's
    # file(WRITE) uses a text-mode stream; native Windows converts LF to CRLF.
    expected=b'COPYING.LGPLv2.1:\n\n'+license_+b'\n\nLICENSE.md:\n\n'+license_md+b'\n\n'
    if installed==expected:return 'lf'
    if installed==expected.replace(b'\n',b'\r\n'):return 'windows-crlf'
    raise ValueError('Windows FFmpeg installed copyright differs from its original source')


def record(work,stage,*,target_files,build_input_root,target,inventory_relative='share'):
    work=Path(work).resolve(strict=True);stage=Path(stage).resolve(strict=True)
    build_input_root=Path(build_input_root).resolve(strict=True)
    inventory=release.relative(inventory_relative)
    if not isinstance(target_files,list) or not target_files:raise ValueError('static media has no final release target')
    for item in target_files:
        release.fields(item,['path','sha256','archive_entry'])
        if item['archive_entry'] is not None:raise ValueError('static media targets require installed regular files')
        if release.digest(stage/release.relative(item['path']))!=release.sha(item['sha256']):raise ValueError('static media final target changed')
    if len({item['path'] for item in target_files})!=len(target_files):raise ValueError('static media final targets repeat')
    sources=release.load(build_input_root/'packaging/native/sources.json')
    version=sources['ffmpeg']['version']
    if version!='9.0.2' or sources['ffmpeg']['sha256']!='8c3850283eb25fa026482078a04051e0be17347b09ef81a0849bec15a96e002e':
        raise ValueError('native media source differs from the current reviewed build identity')
    windows=target=='x86_64-pc-windows-msvc'
    darwin=target in ('x86_64-apple-darwin','aarch64-apple-darwin')
    if not windows and not darwin and target!='x86_64-unknown-linux-gnu':raise ValueError('static media target is unsupported')
    env=environment()
    if windows:
        return record_windows(work,stage,sources,target_files,inventory,env)
    prefix=work/'install'
    archive=work/'source'/('ffmpeg-'+version+'.tar.xz')
    raw=bounded(archive,MAX_INPUT)
    if hashlib.sha256(raw).hexdigest()!=sources['ffmpeg']['sha256']:raise ValueError('actual FFmpeg source checksum differs')
    upstream=tar_files(raw)
    source=work/'source'/('ffmpeg-'+version)
    configuration=native_configuration(source/'ffbuild/config.mak')
    provider='CONFIG_SECURETRANSPORT' if darwin else 'CONFIG_OPENSSL'
    if configuration.get(provider)!='yes':
        raise ValueError('actual media TLS provider differs from the target build')
    libraries,frameworks=link_closure(prefix,work,env,False)
    if darwin and (libraries-FFMPEG_LIBRARIES-UNIX_SYSTEM or not frameworks<={'CoreFoundation','Security','CoreVideo','CoreMedia','VideoToolbox','AudioToolbox','AVFoundation','Foundation','AppKit'}):
        raise ValueError('macOS media closure contains unreviewed third-party libraries')
    license_file='COPYING.LGPLv3' if configuration.get('CONFIG_VERSION3')=='yes' else 'COPYING.LGPLv2.1'
    notice=upstream['ffmpeg-'+version+'/'+license_file]
    license_md=upstream['ffmpeg-'+version+'/LICENSE.md']
    if bounded(prefix/'share/xcoc-native'/license_file,1024*1024)!=notice or bounded(prefix/'share/xcoc-native/LICENSE.md',1024*1024)!=license_md:
        raise ValueError('installed FFmpeg license differs from its actual source')
    media=component(stage,'ffmpeg','FFmpeg',version,{'url':sources['ffmpeg']['url'],'sha256':sources['ffmpeg']['sha256']},
        [prefix/'lib'/('lib'+name+'.a') for name in sorted(FFMPEG_LIBRARIES)],
        [('LGPL-3.0-or-later' if license_file.endswith('v3') else 'LGPL-2.1-or-later',license_file,notice),
         ('FFmpeg source licensing document','LICENSE.md',license_md)],target_files,inventory)
    components=[media]
    evidence={'format_version':1,'target':target,'source':media['source'],'configuration_sha256':release.digest(source/'ffbuild/config.mak'),
              'static_libraries':sorted(libraries),'platform_frameworks':sorted(frameworks),'archive_origins':[],'license_origins':[]}
    if darwin:
        components.append({'ref':'urn:platform:apple:securetransport','type':'library','name':'Apple SecureTransport','version':'macOS',
            'source':{'url':'https://developer.apple.com/documentation/security/secure-transport','sha256':None},
            'licenses':[],'delivery':'platform','files':[],'dependencies':[]})
    else:
        origins=DebianSources(work,env);groups={};library_refs={}
        for name in sorted(libraries-FFMPEG_LIBRARIES-UNIX_SYSTEM):
            if not re.fullmatch('[A-Za-z0-9_.+-]+',name):raise ValueError('native static dependency name is invalid')
            filename='lib'+name+'.a'
            original=command(['cc','-print-file-name='+filename],work,env,4096).strip()
            if original==filename:raise ValueError('actual compiler cannot resolve the static dependency')
            path=Path(original).resolve(strict=True)
            if release.digest(path)!=release.digest(prefix/'lib'/filename):raise ValueError('staged static library differs from the actual compiler origin')
            selected,logical=origins.origin(path)
            key=tuple(selected['identity']);group=groups.setdefault(key,{'package':selected,'archives':[]})
            group['archives'].append(prefix/'lib'/filename)
            evidence['archive_origins'].append({'file':filename,'package':list(key),'distribution':selected['source'],'package_path':logical})
        for identity,group in sorted(groups.items()):
            selected=group['package'];name=identity[0].split(':',1)[0]
            library_names={path.name for path in group['archives']}
            known={frozenset({'libssl.a','libcrypto.a'}):'OpenSSL static libraries',
                   frozenset({'libatomic.a'}):'libatomic static library',frozenset({'libz.a'}):'zlib static library',
                   frozenset({'libzstd.a'}):'Zstandard static library'}
            delivered_name=known.get(frozenset(library_names),' + '.join(sorted(library_names))+' static libraries')
            license_source=origins.license_source(selected)
            value=component(stage,'debian-'+name,delivered_name,identity[1],selected['source'],group['archives'],
                            [('Actual upstream copyright ('+name+')','copyright',license_source['contents'])],target_files,inventory)
            components.append(value);group['component']=value
            evidence['license_origins'].append({'component':value['ref'],'distribution':license_source['distribution'],
                                                'package_path':license_source['package_path'],'sha256':hashlib.sha256(license_source['contents']).hexdigest()})
            for path in group['archives']:library_refs[path.name.removeprefix('lib').removesuffix('.a')]=value['ref']
        direct=set()
        for path in (prefix/'lib/pkgconfig').glob('*.pc'):
            direct.update(pc_libraries(bounded(path,1024*1024)))
        media['dependencies']=sorted({library_refs[name] for name in direct if name in library_refs})
        for group in groups.values():
            value=group['component'];own={name for name,ref in library_refs.items() if ref==value['ref']}
            children=set()
            for path,contents in group['package']['files'].items():
                if path.endswith('.pc'):
                    declared=pc_libraries(contents)
                    if declared&own:children.update(declared)
            value['dependencies']=sorted({library_refs[name] for name in children if name in library_refs and library_refs[name]!=value['ref']})
        reachable={media['ref']};pending=[media['ref']];by_ref={item['ref']:item for item in components}
        while pending:
            current=by_ref[pending.pop()]
            for child in current['dependencies']:
                if child not in reachable:reachable.add(child);pending.append(child)
        if set(by_ref)!=reachable:
            raise ValueError('actual native static dependency graph is disconnected from the configured media libraries')
        evidence['dependency_edges']={item['ref']:item['dependencies'] for item in components}
    put(stage,inventory+'/build-inputs/native/provenance.json',(json.dumps(evidence,sort_keys=True,indent=2)+'\n').encode())
    return components


def record_windows(work,stage,sources,targets,inventory,env):
    definition=sources['vcpkg']
    revision=definition['revision']
    if revision!='e456309491fd875487bf02b8a0dca76c1b1b00cc' or definition['triplet']!='x64-windows-static':
        raise ValueError('Windows native provider differs from the reviewed immutable build')
    vcpkg=work/'vcpkg';prefix=work/'installed/x64-windows-static'
    if command(['git','-C',str(vcpkg),'rev-parse','HEAD'],work,env,4096).strip()!=revision or command(['git','-C',str(vcpkg),'diff','--name-only','HEAD','--'],work,env,4096).strip():
        raise ValueError('actual Windows native provider has unreviewed source changes')
    origin=command(['git','-C',str(vcpkg),'remote','get-url','origin'],work,env,4096).strip()
    if origin!='https://github.com/microsoft/vcpkg.git':raise ValueError('Windows native provider has an unexpected origin')
    port=bounded(vcpkg/'ports/ffmpeg/portfile.cmake',2*1024*1024).decode()
    definition_actual=release.load(vcpkg/'ports/ffmpeg/vcpkg.json')
    if definition_actual.get('version')!=sources['ffmpeg']['version'] or definition_actual.get('port-version')!=1:
        raise ValueError('actual Windows FFmpeg port identity differs')
    matches=re.findall(r'vcpkg_from_github\s*\((.*?)\)',port,re.S)
    if len(matches)!=1:raise ValueError('Windows FFmpeg source origin is not uniquely declared')
    block=matches[0]
    repository=re.findall(r'\bREPO\s+([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)',block)
    refs=re.findall(r'\bREF\s+"([^"\n]+)"',block)
    checksums=re.findall(r'\bSHA512\s+([0-9a-f]{128})\b',block)
    if repository!=['ffmpeg/ffmpeg'] or refs!=['n${VERSION}'] or len(checksums)!=1:
        raise ValueError('Windows FFmpeg port has an unsupported source declaration')
    archives=[]
    for candidate in (vcpkg/'downloads').glob('*ffmpeg*'+sources['ffmpeg']['version']+'*.tar.*'):
        if not candidate.is_file():continue
        value=bounded(candidate,MAX_INPUT)
        if hashlib.sha512(value).hexdigest()==checksums[0]:archives.append((candidate,value))
    if len(archives)!=1:raise ValueError('Windows FFmpeg has no unique actually verified source download')
    downloaded,raw=archives[0]
    upstream=tar_files(raw)
    license_paths=[name for name in upstream if name.endswith('/COPYING.LGPLv2.1')]
    if len(license_paths)!=1:raise ValueError('Windows FFmpeg original upstream license is unavailable')
    license_=upstream[license_paths[0]]
    installed=bounded(prefix/'share/ffmpeg/copyright',2*1024*1024)
    license_md=upstream[license_paths[0].rsplit('/',1)[0]+'/LICENSE.md']
    copyright_line_endings=verify_windows_copyright(installed,license_,license_md)
    manifests=list((work/'installed/vcpkg/info').glob('ffmpeg_*_x64-windows-static.list'))
    if len(manifests)!=1:raise ValueError('actual Windows FFmpeg installation file inventory is ambiguous')
    installed_files=set(bounded(manifests[0],4*1024*1024).decode().splitlines())
    libraries,frameworks=link_closure(prefix,work,env,True)
    if frameworks or libraries-FFMPEG_LIBRARIES-WINDOWS_SYSTEM:
        raise ValueError('Windows media closure has an unreviewed nonplatform dependency')
    archives=[prefix/'lib'/(name+'.lib') for name in sorted(FFMPEG_LIBRARIES)]
    if any('x64-windows-static/lib/'+path.name not in installed_files for path in archives):
        raise ValueError('actual Windows native library is absent from its installation inventory')
    configurations=list((vcpkg/'buildtrees/ffmpeg').glob('x64-windows-static-rel/ffbuild/config.mak'))
    if len(configurations)!=1:
        configurations=list((vcpkg/'buildtrees/ffmpeg').glob('**/ffbuild/config.mak'))
        configurations=[path for path in configurations if 'rel' in path.as_posix() and not 'dbg' in path.as_posix()]
    if len(configurations)!=1:raise ValueError('actual Windows FFmpeg release build configuration is ambiguous')
    config=native_configuration(configurations[0])
    if config.get('CONFIG_SCHANNEL')!='yes' or config.get('CONFIG_OPENSSL')=='yes' or config.get('CONFIG_VERSION3')=='yes':
        raise ValueError('Windows media TLS or license configuration differs from the approved build')
    version=sources['ffmpeg']['version']
    source={'url':'https://github.com/ffmpeg/ffmpeg/archive/n'+version+'.tar.gz','sha256':hashlib.sha256(raw).hexdigest()}
    media=component(stage,'ffmpeg','FFmpeg',version,source,archives,
                    [('LGPL-2.1-or-later','COPYING.LGPLv2.1',license_),
                     ('FFmpeg source licensing document','LICENSE.md',license_md),
                     ('Actual vcpkg combined copyright','copyright',installed)],targets,inventory)
    inputs=[]
    for path in sorted((vcpkg/'ports/ffmpeg').iterdir()):
        if path.is_file():
            entry=put(stage,inventory+'/build-inputs/native/ffmpeg-port/'+path.name,bounded(path,4*1024*1024))
            inputs.append(entry)
    media['embedding']['source_files'].extend(inputs)
    proof={'format_version':1,'target':'x86_64-pc-windows-msvc','vcpkg_revision':revision,
           'source':source,'source_sha512':checksums[0],'configuration_sha256':release.digest(configurations[0]),
           'static_libraries':sorted(libraries),'provider_inputs':inputs,
           'copyright':{'generator':'https://raw.githubusercontent.com/microsoft/vcpkg/'+revision+'/scripts/cmake/vcpkg_install_copyright.cmake',
                        'installed_sha256':hashlib.sha256(installed).hexdigest(),'line_endings':copyright_line_endings,
                        'original_sources':[{'name':'COPYING.LGPLv2.1','sha256':hashlib.sha256(license_).hexdigest()},
                                            {'name':'LICENSE.md','sha256':hashlib.sha256(license_md).hexdigest()}]}}
    put(stage,inventory+'/build-inputs/native/provenance.json',(json.dumps(proof,sort_keys=True,indent=2)+'\n').encode())
    platform={'ref':'urn:platform:microsoft:schannel','type':'library','name':'Microsoft Schannel','version':'Windows',
              'source':{'url':'https://learn.microsoft.com/windows/win32/secauthn/secure-channel','sha256':None},
              'licenses':[],'delivery':'platform','files':[],'dependencies':[]}
    return [media,platform]
