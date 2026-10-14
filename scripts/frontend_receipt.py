"""Bind actual rendered npm modules and fonts to the compiled Server payload."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import time
import urllib.request

import release_sbom as sbom
from release_manifest import bounded

MAX_ARCHIVE=256*1024*1024
MAX_MODULES=16384
MAX_OUTPUTS=16384
MAX_CODE=4*1024*1024
MAX_EDGES=131072


def retain(stage,path,contents):
    """Publish an exact resource without replacing a link or existing data."""
    stage=sbom.physical_directory(stage)
    path=sbom.relative(path)
    if not isinstance(contents,bytes) or len(contents)>MAX_ARCHIVE:
        raise ValueError('runtime build material exceeds its bound')
    destination=stage/path
    current=stage
    for part in Path(path).parts[:-1]:
        current/=part
        try:current.mkdir(mode=0o755)
        except FileExistsError:pass
        info=current.lstat()
        if not stat.S_ISDIR(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:
            raise ValueError('runtime build material requires physical directories')
    try:
        descriptor=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_BINARY',0),0o600)
    except FileExistsError:
        if bounded(destination,MAX_ARCHIVE)!=contents:
            raise ValueError('runtime build material conflicts with an existing delivered resource')
        return destination
    with os.fdopen(descriptor,'wb') as output:
        output.write(contents)
        output.flush()
        os.fsync(output.fileno())
        if os.name=='nt':os.chmod(destination,0o644)
        else:os.fchmod(output.fileno(),0o644)
    return destination


def public_https(url,redirect=False):
    from urllib.parse import urlsplit
    parsed=urlsplit(url)
    # GitHub's public release assets redirect to expiring, queried HTTPS URLs.
    # The source URL is canonical; every actual transport hop must retain TLS.
    if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or (parsed.query and not redirect):
        raise ValueError('runtime source is not a public HTTPS distribution')


class HTTPSRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,request,response,code,message,headers,new_url):
        public_https(new_url,redirect=True)
        return super().redirect_request(request,response,code,message,headers,new_url)


def download(url,expected=None):
    public_https(url)
    result=bytearray();deadline=time.monotonic()+600
    with urllib.request.build_opener(HTTPSRedirects()).open(url,timeout=60) as response:
        public_https(response.geturl(),redirect=True)
        while True:
            if time.monotonic()>=deadline:
                raise TimeoutError('runtime source download exceeded its total time bound')
            chunk=response.read(min(65536,MAX_ARCHIVE+1-len(result)))
            if not chunk:break
            result.extend(chunk)
            if len(result)>MAX_ARCHIVE:
                raise ValueError('runtime source archive exceeds its bound')
    result=bytes(result)
    if expected is not None and hashlib.sha256(result).hexdigest()!=expected:
        raise ValueError('runtime upstream archive SHA-256 differs')
    return result


def output_inventory(entries,compiled=False):
    if not isinstance(entries,list) or not 1<=len(entries)<=MAX_OUTPUTS:
        raise ValueError('rendered output inventory is empty or exceeds its bound')
    result={}
    for item in entries:
        sbom.fields(item,['path','sha256'],['size','content_type'] if compiled else [])
        name=sbom.relative(item['path'])
        if name in result:
            raise ValueError('rendered output inventory repeats a path')
        if 'size' in item and (type(item['size']) is not int or not 0<=item['size']<=sbom.MAX_BYTES):
            raise ValueError('compiled resource has an invalid size')
        result[name]=sbom.sha(item['sha256'])
    return result


class Packages:
    def __init__(self,root):
        self.root=root
        lock=sbom.load(root/'package-lock.json')
        if lock.get('lockfileVersion')!=3:
            raise ValueError('runtime npm graph requires the exact current lock format')
        self.lock=lock['packages'];self.loaded={};self.archive_bytes=0;self.expanded_bytes=0

    def archive(self,path):
        path=sbom.relative(path)
        if path in self.loaded:return self.loaded[path]
        package=sbom.load(self.root/path/'package.json');lock=self.lock[path]
        if package['version']!=lock['version']:
            raise ValueError('rendered npm package differs from its locked version')
        archive=download(lock['resolved'])
        self.archive_bytes+=len(archive)
        if self.archive_bytes>MAX_ARCHIVE:
            raise ValueError('runtime npm source archives exceed their aggregate bound')
        algorithm,encoded=lock['integrity'].split('-',1)
        if algorithm not in ('sha256','sha512') or hashlib.new(algorithm,archive).digest()!=base64.b64decode(encoded,validate=True):
            raise ValueError('actual npm distribution differs from its lock integrity')
        files={};total=0;entries=0
        with tarfile.open(fileobj=io.BytesIO(archive),mode='r:gz') as contents:
            for item in contents:
                entries+=1
                if entries>MAX_MODULES:
                    raise ValueError('npm distribution entry count exceeds its bound')
                if item.isdir():
                    name=item.name.removesuffix('/')
                    if name!='package':
                        if not name.startswith('package/'):
                            raise ValueError('npm distribution contains an uncontrolled entry')
                        sbom.relative(name.removeprefix('package/'))
                    continue
                if not item.isfile() or not item.name.startswith('package/'):
                    raise ValueError('npm distribution contains an uncontrolled entry')
                name=sbom.relative(item.name.removeprefix('package/'))
                if type(item.size)is not int or item.size<0:
                    raise ValueError('npm distribution file size is invalid')
                total+=item.size
                if name in files or len(files)>=16384 or item.size>MAX_ARCHIVE or total>MAX_ARCHIVE or self.expanded_bytes+total>MAX_ARCHIVE:
                    raise ValueError('npm distribution exceeds its extraction bound')
                files[name]=contents.extractfile(item).read(item.size+1)
                if len(files[name])!=item.size:
                    raise ValueError('npm distribution file size differs')
        self.expanded_bytes+=total
        original=json.loads(files['package.json'],object_pairs_hook=unique_fields)
        if original['name']!=package['name'] or original['version']!=package['version']:
            raise ValueError('actual npm distribution identity differs from the rendered package')
        if original.get('license')!=package.get('license'):
            raise ValueError('rendered npm license metadata differs from its original distribution')
        result={'package':package,'files':files,'source':{'url':lock['resolved'],'sha256':hashlib.sha256(archive).hexdigest()}}
        self.loaded[path]=result;return result

    def owner(self,path):
        current=Path(path).parent
        while current!=Path('.'):
            name=current.as_posix()
            if name in self.lock and name.startswith('node_modules/'):
                return name
            current=current.parent
        raise ValueError('rendered third-party input has no exact npm lock owner')


def original_notices(package,stage,name):
    license_=package['package'].get('license')
    # Preserve the reviewed upstream dual-license declaration and both original
    # license documents rather than relabeling either document as one branch.
    if license_ not in ('MIT','Apache-2.0','BSD-2-Clause','BSD-3-Clause','ISC','(MPL-2.0 OR Apache-2.0)'):
        raise ValueError('rendered npm package '+package['package']['name']+' requires an explicitly reviewed upstream license')
    notices={path:content for path,content in package['files'].items()
        if '/' not in path and re.fullmatch(r'(LICENSE|LICENCE|COPYING|NOTICE|THIRD-PARTY-LICENSE)([._-].*)?',path,re.I)}
    if not any(re.match(r'LICENSE|LICENCE|COPYING',path,re.I) for path in notices):
        raise ValueError('rendered npm package '+package['package']['name']+' has no original upstream license text')
    result=[]
    for path,content in sorted(notices.items()):
        if not content.strip():raise ValueError('upstream runtime notice is empty')
        relative='share/licenses/frontend/'+name+'/'+path
        destination=retain(stage,relative,content)
        result.append({'name':license_,'path':relative,'sha256':sbom.digest(destination)})
    return result


def unique_fields(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('runtime source metadata repeats a field')
        result[key]=value
    return result


def rendered_components(source_root,root,stage,data,recorded,target_files):
    packages=Packages(root);owners={};sources={};outputs={};aliases={}
    if not isinstance(data['modules'],list) or not 1<=len(data['modules'])<=MAX_MODULES:
        raise ValueError('rendered module graph is empty or exceeds its bound')
    covered_outputs=set();edge_count=0
    for index,item in enumerate(data['modules']):
        sbom.fields(item,['path','sha256','files','imports'],['code','virtual_id','generated_runtime'])
        if not isinstance(item['files'],list) or not item['files'] or len(item['files'])>MAX_OUTPUTS or any(type(name)is not str or name not in recorded for name in item['files']) or len(set(item['files']))!=len(item['files']):
            raise ValueError('rendered module graph is not bound to the actual output set')
        if not isinstance(item['imports'],list) or len(item['imports'])>MAX_MODULES or any(type(child)is not int or not 0<=child<len(data['modules']) for child in item['imports']) or len(set(item['imports']))!=len(item['imports']):
            raise ValueError('rendered module graph is not bound to the actual output set')
        edge_count+=len(item['imports'])
        if edge_count>MAX_EDGES:
            raise ValueError('rendered module dependency edges exceed their aggregate bound')
        covered_outputs.update(item['files'])
        path=item['path']
        if path is None:
            virtual=item.get('virtual_id')
            if virtual not in ('\0vite/preload-helper.js','\0vite/modulepreload-polyfill.js','\0rolldown/runtime.js'):
                raise ValueError('rendered virtual runtime has no current source provider')
            owner='node_modules/rolldown' if virtual=='\0rolldown/runtime.js' else 'node_modules/vite'
            package=packages.archive(owner)
            if virtual=='\0rolldown/runtime.js':
                provider=item.get('generated_runtime')
                sbom.fields(provider,['provider','version','module'])
                if provider!={'provider':'rolldown','version':package['package']['version'],'module':virtual}:
                    raise ValueError('actual generated runtime provider differs from its receipt')
            elif 'generated_runtime' in item:
                raise ValueError('generated runtime provider differs from its virtual module')
            if type(item.get('code'))is not str or not item['code'] or len(item['code'].encode())>MAX_CODE:
                raise ValueError('generated runtime helper is empty or exceeds its bound')
            code=item['code'].encode()
            if hashlib.sha256(code).hexdigest()!=sbom.sha(item['sha256']) or str(root).encode() in code:
                raise ValueError('generated runtime helper differs or leaks a private build path')
            path='share/build-inputs/frontend/'+item['virtual_id'].removeprefix('\0').replace('/','-')
            destination=retain(stage,path,code)
            source={'path':path,'sha256':sbom.digest(destination)}
            # This generated helper is retained alongside its exact provider;
            # its source lives in the delivery, not the npm source tree.
            group=owner+'#generated';aliases[group]=owner
        else:
            if any(key in item for key in ('code','virtual_id','generated_runtime')):
                raise ValueError('physical runtime input cannot masquerade as a generated helper')
            path=sbom.relative(path)
            if sbom.digest(root/path)!=sbom.sha(item['sha256']):
                raise ValueError('actual rendered input changed after the build')
            if not path.startswith('node_modules/'):continue
            owner=packages.owner(path);package=packages.archive(owner)
            name=Path(path).relative_to(owner).as_posix()
            if package['files'].get(name) is None or hashlib.sha256(package['files'][name]).hexdigest()!=item['sha256']:
                raise ValueError('rendered npm input differs from its original distribution')
            group=owner
            source={'path':(root/path).relative_to(source_root).as_posix(),'sha256':item['sha256']}
        owners[index]=group;sources.setdefault(group,[]).append(source)
        outputs.setdefault(group,set()).update(item['files'])
    if any(name.endswith(('.js','.mjs','.cjs')) and name not in covered_outputs for name in recorded):
        raise ValueError('actual compiled JavaScript has no rendered module evidence')
    components=[];refs={}
    for owner in sources:
        package=packages.archive(owner.split('#',1)[0])
        name=package['package']['name'];version=package['package']['version']
        ref='urn:rendered-npm:'+name+':'+version+(':'+owner.split('#',1)[1] if '#' in owner else '')
        refs[owner]=ref
        notice=packages.archive(aliases.get(owner,owner.split('#',1)[0]))
        licenses=original_notices(notice,stage,name.replace('/','-'))
        targets=target_files(sorted(outputs[owner]))
        components.append({'ref':ref,'type':'library','name':name+(' generated runtime' if owner in aliases else ''),
            'version':version,'source':package['source'],'licenses':licenses,'delivery':'embedded','files':targets,
            'dependencies':[], 'embedding':{'kind':'compiled-resource','input_root':'stage' if '#' in owner else 'build',
                'source_files':sources[owner], 'target_files':targets}})
    by_ref={item['ref']:item for item in components}
    for index,owner in owners.items():
        pending=list(data['modules'][index]['imports']);visited={index};dependencies=set()
        while pending:
            child=pending.pop()
            if child in visited:continue
            visited.add(child)
            if child in owners and owners[child]!=owner:
                dependencies.add(refs[owners[child]])
            else:
                pending.extend(data['modules'][child]['imports'])
        by_ref[refs[owner]]['dependencies']=sorted(set(by_ref[refs[owner]]['dependencies'])|dependencies)
    return components,packages


def generate(source_root,stage,metadata,binary):
    source_root=Path(source_root).resolve(strict=True);stage=Path(stage).resolve(strict=True)
    specification=sbom.load(source_root/'xcss-web-build.json')
    directory=specification['web']['directory']
    if directory!='.':sbom.relative(directory)
    root=(source_root/directory).resolve(strict=True)
    if not root.is_relative_to(source_root):raise ValueError('runtime Web build root escaped the source')
    data=sbom.load(metadata);sbom.fields(data,['format_version','distribution','modules','outputs'])
    if type(data['format_version'])is not int or data['format_version']!=1:
        raise ValueError('rendered Web inventory has an unsupported version')
    distribution=root/sbom.relative(data['distribution'])
    actual=sbom.files(distribution)
    recorded=output_inventory(data['outputs'])
    if recorded!=actual:
        raise ValueError('rendered outputs differ from the actual compiled Web files')
    compiled=sbom.load(stage/'share/web-assets.json')
    sbom.fields(compiled,['format','files'])
    if compiled['format']!='web-assets-v1':raise ValueError('current compiled Web receipt is unavailable')
    compiled_files=output_inventory(compiled['files'],compiled=True)
    compiled_hashes=set(compiled_files.values())
    if recorded!=compiled_files or any('size' in item and item['size']!=(distribution/item['path']).stat().st_size for item in compiled['files']):
        raise ValueError('rendered Web output is not present in the actual compiled Server')
    target={'path':sbom.relative(binary),'sha256':sbom.digest(stage/binary),'archive_entry':None}
    components,packages=rendered_components(source_root,root,stage,data,recorded,lambda names:[target])
    sdk=packages.archive('node_modules/@xcss/web')
    provenance_raw=sdk['files']['dist/web-fonts/provenance.json']
    provenance=json.loads(provenance_raw,object_pairs_hook=unique_fields)
    provenance_path=root/'node_modules/@xcss/web/dist/web-fonts/provenance.json'
    if sbom.digest(provenance_path)!=hashlib.sha256(provenance_raw).hexdigest():
        raise ValueError('font source provenance differs from its original npm distribution')
    retain(stage,'share/build-inputs/frontend/font-provenance.json',provenance_raw)
    font_files=[]
    for name,expected in provenance['assets'].items():
        if not name.endswith('.woff2'):continue
        original=sdk['files']['dist/web-fonts/'+name]
        if hashlib.sha256(original).hexdigest()!=expected or expected not in compiled_hashes:
            raise ValueError('current complete font differs from its original source or compiled resource')
        path=root/'node_modules/@xcss/web/dist/web-fonts'/name
        if sbom.digest(path)!=expected:raise ValueError('compiled font input differs from its provenance')
        font_files.append({'path':path.relative_to(source_root).as_posix(),'sha256':expected})
    licenses=[]
    for name in ('OFL.txt','CJK-LICENSE.txt','NORMAL-LICENSE.txt'):
        content=sdk['files']['dist/web-fonts/'+name]
        if hashlib.sha256(content).hexdigest()!=provenance['assets'][name]:raise ValueError('font license differs from its provenance')
        path='share/licenses/frontend/maple-font/'+name;destination=retain(stage,path,content)
        licenses.append({'name':'SIL Open Font License 1.1','path':path,'sha256':sbom.digest(destination)})
    if not font_files:
        raise ValueError('complete font component has no actual compiled font inputs')
    font_files.append({'path':provenance_path.relative_to(source_root).as_posix(),'sha256':sbom.digest(provenance_path)})
    cjk_source={'url':provenance['cjk']['upstream'].replace('/tag/','/download/')+'/'+provenance['cjk']['archive'],'sha256':provenance['cjk']['sha256']}
    for original in (provenance['latin'],cjk_source):
        download(original['url'],original['sha256'])
    cjk_ref='urn:maple-font:cjk:'+sbom.sha(cjk_source['sha256'])
    components.append({'ref':cjk_ref,'type':'data','name':'Maple Mono CJK font inputs',
        'version':provenance['cjk']['upstream'].rsplit('/tag/',1)[-1],'source':cjk_source,
        'licenses':[item for item in licenses if item['path'].endswith('/CJK-LICENSE.txt')],'delivery':'embedded','files':[target],'dependencies':[],
        'embedding':{'kind':'compiled-resource','input_root':'build','source_files':font_files,'target_files':[target]}})
    components.append({'ref':'urn:maple-font:complete:'+provenance['source_commit'],'type':'data','name':'Maple Mono complete fonts',
        'version':provenance['source_version'],'source':{'url':provenance['latin']['url'],'sha256':provenance['latin']['sha256']},
        'licenses':licenses,'delivery':'embedded','files':[target],'dependencies':[cjk_ref],
        'embedding':{'kind':'compiled-resource','input_root':'build','source_files':font_files,'target_files':[target]}})
    external=stage/'share/external-components.json';receipt=sbom.load(external)
    receipt['components'].extend(components)
    external.write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n');external.chmod(0o644)
    return components
