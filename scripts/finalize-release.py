#!/usr/bin/env python3
"""Archive and independently recheck one complete SHA256-bound tool delivery."""
import argparse
import gzip
import io
import os
from pathlib import Path
import sys
import tarfile
import tempfile

sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import release_manifest
import release_sbom
from sbom import run

TARGET='x86_64-unknown-linux-gnu'


def verify(stage,revision,version):
    stage=release_sbom.physical_directory(stage)
    document=release_manifest.verify(stage)
    expected=release_manifest.identity('xssi',version,revision,TARGET)
    if document['identity']!=expected:raise ValueError('tool archive identity differs from its expected source')
    provenance=release_sbom.load(stage/'share/build-provenance.json')
    if any(provenance.get(key)!=value for key,value in expected.items()) or provenance.get('helper_sha256')!=release_sbom.digest(stage/'libexec/setup'):
        raise ValueError('tool archive differs from its actual compiled helper provenance')
    environment={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','TZ':'UTC'}
    if run([str(stage/'libexec/setup'),'--version'],stage,environment,maximum=4096,timeout=10)!=('setup '+version+'\n').encode():
        raise ValueError('tool archive helper version differs from its release identity')
    return document


def finalize(stage,output,revision,version):
    stage=release_sbom.physical_directory(stage)
    expected=verify(stage,revision,version)
    output=release_sbom.physical_directory(output)
    stem='xssi-'+version+'-linux-x86_64'
    archive=output/(stem+'.tar.gz');checksum=output/(stem+'.tar.gz.sha256')
    if archive.exists() or archive.is_symlink() or checksum.exists() or checksum.is_symlink():
        raise ValueError('tool publisher refuses to overwrite an existing release asset')
    with archive.open('xb') as raw:
        with gzip.GzipFile(fileobj=raw,mode='wb',filename='',mtime=0) as compressed:
            with tarfile.open(fileobj=compressed,mode='w',format=tarfile.PAX_FORMAT) as tar:
                names=[stage,*sorted(stage.rglob('*'))]
                for source in names:
                    name=stem if source==stage else stem+'/'+source.relative_to(stage).as_posix()
                    info=tar.gettarinfo(str(source),arcname=name)
                    if not(info.isfile() or info.isdir()):raise ValueError('tool archive contains an uncontrolled object')
                    info.uid=info.gid=0;info.uname=info.gname='';info.mtime=0
                    if info.isfile():tar.addfile(info,io.BytesIO(release_manifest.bounded(source,release_sbom.MAX_BYTES)))
                    else:tar.addfile(info)
        raw.flush();os.fsync(raw.fileno())
    archive.chmod(0o644)
    with tempfile.TemporaryDirectory(prefix='xssi-final-release-') as temporary:
        extracted=Path(temporary);count=0;total=0;seen=set()
        with tarfile.open(archive,'r:gz') as tar:
            for member in tar:
                count+=1;total+=member.size
                name=release_sbom.relative(member.name)
                if count>release_sbom.MAX_FILES+256 or total>release_sbom.MAX_BYTES or member.size<0 or name in seen or not(name==stem or name.startswith(stem+'/')) or not(member.isfile() or member.isdir()):
                    raise ValueError('actual tool archive is unsafe or exceeds its bound')
                seen.add(name);tar.extract(member,extracted,filter='data')
        if verify(extracted/stem,revision,version)!=expected:
            raise ValueError('actual extracted tool archive differs from the verified delivery')
    if release_manifest.verify(stage)!=expected:
        raise ValueError('tool delivery changed during archive publication')
    with checksum.open('xb') as out:
        out.write((release_sbom.digest(archive)+'  '+archive.name+'\n').encode());out.flush();os.fsync(out.fileno())
    checksum.chmod(0o644)
    return archive


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--source-revision',required=True)
    parser.add_argument('--version',required=True)
    args=parser.parse_args();finalize(args.stage,args.output,args.source_revision,args.version)


if __name__=='__main__':main()
