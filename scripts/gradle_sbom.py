#!/usr/bin/env python3
"""Inventory the actual resolved Android release runtime graph and upstream licenses."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

MAX_ARTIFACT=128*1024*1024
MAX_DOCUMENT=2*1024*1024
MAX_COMPONENTS=2048
MAX_PARENT_DEPTH=16
MAX_GRAPH_BYTES=512*1024*1024


def checksum(value):
    return hashlib.sha256(value).hexdigest()


def https(url):
    if not isinstance(url,str) or len(url)>4096 or any(ord(character)<32 or ord(character)==127 for character in url):
        raise ValueError('runtime source URL is invalid')
    parsed=urllib.parse.urlsplit(url)
    if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('runtime material must have a public HTTPS source')
    return url


def bytes_regular(path,maximum):
    before=path.lstat()
    if not stat.S_ISREG(before.st_mode) or path.is_symlink() or before.st_nlink!=1 or before.st_size>maximum or getattr(before,'st_file_attributes',0)&getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',0):
        raise ValueError('Gradle artifact is not a bounded physical file')
    def identity(info):
        return (info.st_dev,info.st_ino,info.st_mode,info.st_nlink,info.st_uid,info.st_gid,
                info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    descriptor=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0)|getattr(os,'O_BINARY',0))
    try:
        if identity(os.fstat(descriptor))!=identity(before):raise ValueError('Gradle artifact changed before inventory')
        value=bytearray()
        while chunk:=os.read(descriptor,min(65536,maximum+1-len(value))):
            value.extend(chunk)
            if len(value)>maximum:raise ValueError('Gradle artifact exceeds its byte bound')
        if len(value)!=before.st_size or identity(os.fstat(descriptor))!=identity(before) or identity(path.lstat())!=identity(before):
            raise ValueError('Gradle artifact changed during inventory')
        return bytes(value)
    finally:os.close(descriptor)


class PublicRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,request,fp,code,message,headers,newurl):
        https(newurl)
        return super().redirect_request(request,fp,code,message,headers,newurl)


def fetch(url,maximum):
    opener=urllib.request.build_opener(PublicRedirect())
    with opener.open(https(url),timeout=30) as response:
        value=response.read(maximum+1)
    if len(value)>maximum:raise ValueError('runtime upstream material exceeds its bound')
    return value


def fields(value,required):
    if not isinstance(value,dict) or set(value)!=set(required):
        raise ValueError('Gradle export does not match its current contract')


def coordinate(value):
    fields(value,['id','group','name','version','artifacts','dependencies'])
    for key in ('group','name','version'):
        if not isinstance(value[key],str) or not re.fullmatch('[A-Za-z0-9_.+-]{1,256}',value[key]):
            raise ValueError('invalid selected Maven coordinate')
        if value[key] in ('.','..') or (key=='group' and any(not part or part in ('.','..') for part in value[key].split('.'))):
            raise ValueError('selected Maven coordinate contains a redirected path segment')
    identity=':'.join(value[key] for key in ('group','name','version'))
    if value['id']!=identity or any(marker in value['version'] for marker in ('SNAPSHOT','LATEST','RELEASE')):
        raise ValueError('runtime coordinate must resolve to an immutable published artifact')
    return identity


def maven_url(repository,group,name,version,filename):
    https(repository)
    if any(not isinstance(value,str) or not re.fullmatch('[A-Za-z0-9_.+-]{1,256}',value) or value in ('.','..') for value in (group,name,version,filename)) or any(not part for part in group.split('.')):
        raise ValueError('Maven source path must use exact selected coordinate segments')
    return https(repository.rstrip('/')+'/'+group.replace('.','/')+'/'+name+'/'+version+'/'+filename)


def upstream_artifact(item,artifact,repositories,download):
    fields(artifact,['path','sha256','filename'])
    if not re.fullmatch('[0-9a-f]{64}',artifact['sha256']) or not re.fullmatch(r'[A-Za-z0-9_.+-]+\.(?:aar|jar)',artifact['filename']):
        raise ValueError('runtime artifact must be an exact AAR/JAR receipt')
    path=Path(artifact['path'])
    local=bytes_regular(path,MAX_ARTIFACT)
    if checksum(local)!=artifact['sha256']:
        raise ValueError('resolved Gradle artifact changed before inventory')
    for repository in repositories:
        url=maven_url(repository,item['group'],item['name'],item['version'],artifact['filename'])
        try:remote=download(url,MAX_ARTIFACT)
        except urllib.error.HTTPError as error:
            if error.code==404:continue
            raise
        if checksum(remote)==artifact['sha256']:
            return remote,url,repository
    raise ValueError('no declared Maven repository contains the exact resolved runtime artifact')


def pom_license(group,name,version,repository,download,visited=()):
    identity=(group,name,version)
    if len(visited)>=MAX_PARENT_DEPTH or identity in visited:
        raise ValueError('Maven license parent graph is cyclic or exceeds its bound')
    url=maven_url(repository,group,name,version,name+'-'+version+'.pom')
    raw=download(url,MAX_DOCUMENT)
    declarations=raw.replace(b'\x00',b'').upper()
    if b'<!DOCTYPE' in declarations or b'<!ENTITY' in declarations:
        raise ValueError('Maven license metadata contains an unsupported declaration')
    root=ET.fromstring(raw)
    if root.tag.rsplit('}',1)[-1]!='project':raise ValueError('Maven metadata is not a project POM')
    def node(element,key):
        children=[child for child in element if child.tag.rsplit('}',1)[-1]==key]
        if len(children)>1:raise ValueError('Maven metadata repeats an identity or license field')
        return children[0] if children else None
    def text(element,key):
        child=node(element,key)
        return child.text.strip() if child is not None and child.text else None
    properties={}
    container=node(root,'properties')
    if container is not None:
        properties={child.tag.rsplit('}',1)[-1]:child.text.strip() for child in container if child.text}
        if len(properties)!=len(list(container)):raise ValueError('Maven metadata properties are repeated or empty')
    properties.update({'project.groupId':group,'project.artifactId':name,'project.version':version,
                       'pom.groupId':group,'pom.artifactId':name,'pom.version':version})
    def resolved(value):
        if value is None:return None
        for _ in range(MAX_PARENT_DEPTH):
            updated=re.sub(r'\$\{([^}]+)\}',lambda match:properties.get(match[1],match[0]),value)
            if updated==value:break
            value=updated
        if '${' in value:raise ValueError('Maven license properties could not be resolved')
        return value
    parent=node(root,'parent')
    actual_coordinates=[resolved(text(root,'groupId') or (text(parent,'groupId') if parent is not None else None)),
                        resolved(text(root,'artifactId')),
                        resolved(text(root,'version') or (text(parent,'version') if parent is not None else None))]
    if actual_coordinates!=[group,name,version]:
        raise ValueError('Maven license POM identity differs from the actual selected runtime coordinates')
    licenses=node(root,'licenses')
    if licenses is not None:
        result=[]
        for license_ in licenses:
            if license_.tag.rsplit('}',1)[-1]!='license':raise ValueError('invalid Maven license declaration')
            label=resolved(text(license_,'name'));location=resolved(text(license_,'url'))
            if not label or not location:raise ValueError('runtime license is missing its actual upstream text source')
            # TLS reaches the same explicit license authority; no substitute
            # template or guessed license identifier is introduced.
            if location.startswith('http://'):location='https://'+location[7:]
            result.append((label,https(location)))
        if result:return result,[(url,checksum(raw))]
    if parent is None:raise ValueError('resolved runtime artifact has no upstream license declaration')
    parent_coordinates=[resolved(text(parent,key)) for key in ('groupId','artifactId','version')]
    if any(value is None or not re.fullmatch('[A-Za-z0-9_.+-]{1,256}',value) for value in parent_coordinates):
        raise ValueError('Maven license parent coordinates are unresolved')
    inherited,sources=pom_license(*parent_coordinates,repository,download,(*visited,identity))
    return inherited,[(url,checksum(raw)),*sources]


def archive_notices(raw,charge=lambda size:None):
    result=[];expanded=0
    def inspect(value,prefix,depth):
        nonlocal expanded
        with zipfile.ZipFile(io.BytesIO(value)) as archive:
            entries=archive.infolist()
            if len(entries)>16384 or len({entry.filename for entry in entries})!=len(entries):
                raise ValueError('runtime archive has ambiguous or excessive entries')
            for entry in entries:
                if entry.is_dir():continue
                name=entry.filename.rsplit('/',1)[-1]
                if name.lower() in ('license','license.txt','license.md','notice','notice.txt','copying','copying.txt'):
                    if entry.file_size>MAX_DOCUMENT:raise ValueError('runtime notice exceeds its bound')
                    if stat.S_ISLNK(entry.external_attr>>16):raise ValueError('runtime notice cannot be a symbolic link')
                    expanded+=entry.file_size
                    if expanded>8*1024*1024:raise ValueError('expanded runtime notices exceed the per-artifact bound')
                    charge(entry.file_size)
                    result.append((prefix+entry.filename,archive.read(entry)))
                elif depth==0 and entry.filename=='classes.jar':
                    if entry.file_size>MAX_ARTIFACT:raise ValueError('runtime classes archive exceeds its bound')
                    if stat.S_ISLNK(entry.external_attr>>16):raise ValueError('runtime classes archive cannot be a symbolic link')
                    charge(entry.file_size)
                    inspect(archive.read(entry),prefix+'classes.jar!/',depth+1)
    inspect(raw,'',0)
    return result


def produce(export,stage,product,version,revision,*,download=fetch):
    actual_download=download;total=0;deadline=time.monotonic()+1200
    def charge(size):
        nonlocal total
        total+=size
        if total>MAX_GRAPH_BYTES:raise ValueError('Gradle runtime material exceeds its aggregate byte bound')
    def download(url,maximum):
        if time.monotonic()>=deadline:raise TimeoutError('Gradle upstream inventory exceeded its time bound')
        value=actual_download(url,maximum)
        if not isinstance(value,bytes) or len(value)>maximum:raise ValueError('Gradle upstream material exceeds its byte bound')
        charge(len(value))
        return value
    fields(export,['format_version','configuration','root','repositories','components'])
    fields(export['root'],['id','dependencies'])
    if type(export['format_version']) is not int or export['format_version']!=1 or export['configuration']!='releaseRuntimeClasspath' or not re.fullmatch('[0-9a-f]{40}',revision):
        raise ValueError('Gradle inventory is not bound to the current release runtime configuration')
    if not isinstance(export['components'],list) or len(export['components'])>MAX_COMPONENTS or not export['repositories']:
        raise ValueError('runtime graph exceeds its contract or has no public source repository')
    if not isinstance(export['repositories'],list) or not isinstance(export['root']['id'],str) or not export['root']['id']:
        raise ValueError('runtime repository/root metadata is invalid')
    repositories=[https(repository) for repository in export['repositories']]
    resolved={coordinate(item):item for item in export['components']}
    if len(resolved)!=len(export['components']):raise ValueError('runtime graph repeats a selected component')
    for item in [export['root'],*resolved.values()]:
        children=item['dependencies']
        if not isinstance(children,list) or len(children)!=len(set(children)) or not set(children)<=resolved.keys():
            raise ValueError('resolved runtime graph is not closed and unique')
    seen=set();pending=list(export['root']['dependencies'])
    while pending:
        key=pending.pop()
        if key in seen:continue
        seen.add(key);pending.extend(resolved[key]['dependencies'])
    if seen!=resolved.keys():raise ValueError('Gradle runtime graph contains disconnected build or development material')
    stage=Path(stage).resolve(strict=True)
    share=stage/'share';share.mkdir(parents=True,exist_ok=True)
    licenses=share/'android-licenses';licenses.mkdir(exist_ok=True)
    components=[];refs={}
    for identity,item in sorted(resolved.items()):
        if not item['artifacts']:raise ValueError('runtime component has no resolved build artifact')
        ref='pkg:maven/'+item['group']+'/'+item['name']+'@'+item['version']
        refs[identity]=ref
        origin=[];license_records=[];pom_sources=[]
        folder=licenses/checksum(identity.encode());folder.mkdir(exist_ok=False)
        for index,artifact in enumerate(item['artifacts']):
            raw,url,repository=upstream_artifact(item,artifact,repositories,download)
            origin.append({'url':url,'sha256':artifact['sha256'],'filename':artifact['filename']})
            declared,sources=pom_license(item['group'],item['name'],item['version'],repository,download)
            pom_sources.extend(sources)
            for number,(label,location) in enumerate(declared):
                value=download(location,MAX_DOCUMENT)
                if not value.strip():raise ValueError('upstream runtime license text is empty')
                destination=folder/('artifact-'+str(index)+'-license-'+str(number)+'.txt')
                destination.write_bytes(value)
                license_records.append({'license':{'name':label,'properties':[
                    {'name':'license-file','value':destination.relative_to(stage).as_posix()},
                    {'name':'license-sha256','value':checksum(value)},
                    {'name':'license-source','value':location}]}})
            for number,(name,value) in enumerate(archive_notices(raw,charge)):
                destination=folder/('artifact-'+str(index)+'-notice-'+str(number)+'.txt')
                destination.write_bytes(value)
                license_records.append({'license':{'name':'Upstream '+name,'properties':[
                    {'name':'license-file','value':destination.relative_to(stage).as_posix()},
                    {'name':'license-sha256','value':checksum(value)}]}})
        components.append({'type':'library','bom-ref':ref,'name':item['name'],'group':item['group'],
            'version':item['version'],'purl':ref,'scope':'required','licenses':license_records,
            'externalReferences':[{'type':'distribution','url':value['url'],'hashes':[
                {'alg':'SHA-256','content':value['sha256']}]} for value in origin],
            'properties':[{'name':'resolved-runtime-artifacts','value':json.dumps(origin,sort_keys=True)},
                          {'name':'maven-license-metadata','value':json.dumps(sorted(set(pom_sources)))}]})
    root='urn:gradle-runtime:'+product+':'+version+':'+revision+':releaseRuntimeClasspath'
    bom={'bomFormat':'CycloneDX','specVersion':'1.5','version':1,
         'metadata':{'component':{'type':'application','name':product+'-android-runtime','version':version,'bom-ref':root},
                     'properties':[{'name':'source_revision','value':revision},{'name':'configuration','value':export['configuration']}]},
         'components':components,'dependencies':[{'ref':root,'dependsOn':sorted(refs[key] for key in export['root']['dependencies'])},
            *[{'ref':refs[key],'dependsOn':sorted(refs[child] for child in item['dependencies'])} for key,item in sorted(resolved.items())]]}
    destination=share/'android-runtime-sbom.cdx.json'
    destination.write_text(json.dumps(bom,sort_keys=True,ensure_ascii=False,indent=2)+'\n')
    return destination


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--export',required=True,type=Path);parser.add_argument('--stage',required=True,type=Path)
    parser.add_argument('--product',required=True);parser.add_argument('--version',required=True)
    parser.add_argument('--source-revision',required=True)
    args=parser.parse_args()
    def unique(pairs):
        result={}
        for name,value in pairs:
            if name in result:raise ValueError('runtime export repeats a JSON object field')
            result[name]=value
        return result
    produce(json.loads(bytes_regular(args.export,8*1024*1024),object_pairs_hook=unique),
            args.stage,args.product,args.version,args.source_revision)


if __name__=='__main__':main()
