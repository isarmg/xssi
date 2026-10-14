"""Bind a static site's actual rendered runtime and font sources to its files."""
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

import frontend_receipt as frontend
import release_sbom as sbom


def generate(source_root, stage, metadata, product, revision):
    source_root=sbom.physical_directory(source_root)
    stage=sbom.physical_directory(stage)
    sbom.text(product,128)
    if not re.fullmatch('[0-9a-f]{40}',revision):
        raise ValueError('static runtime requires an immutable source revision')
    data=sbom.load(metadata)
    sbom.fields(data,['format_version','distribution','modules','outputs'])
    if type(data['format_version'])is not int or data['format_version']!=1:
        raise ValueError('static runtime inventory version is unsupported')
    distribution=source_root/sbom.relative(data['distribution'])
    recorded=frontend.output_inventory(data['outputs'])
    if recorded!=sbom.files(distribution) or recorded!=sbom.files(stage):
        raise ValueError('static delivered files differ from the actual rendered output')
    def bindings(names):
        return [{'path':name,'sha256':recorded[name],'archive_entry':None} for name in names]
    components,_=frontend.rendered_components(source_root,source_root,stage,data,recorded,bindings)
    provenance_path=source_root/'public/fonts/provenance.json'
    provenance=sbom.load(provenance_path)
    sbom.fields(provenance,['format_version','repository','fonts'])
    if type(provenance['format_version'])is not int or provenance['format_version']!=1:
        raise ValueError('static font provenance version is unsupported')
    repository=urlsplit(provenance['repository'])
    if repository.scheme!='https' or repository.netloc!='github.com' or not re.fullmatch('/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',repository.path) or repository.query or repository.fragment:
        raise ValueError('static font source must identify its current public repository')
    if not isinstance(provenance['fonts'],list) or not 1<=len(provenance['fonts'])<=256:
        raise ValueError('static font provenance is empty or exceeds its bound')
    font_paths=set()
    for font in provenance['fonts']:
        sbom.fields(font,['path','name','version','source_path','license','original_download_url'])
        name=sbom.relative(font['path']);original=sbom.relative(font['source_path'])
        if name in font_paths or name not in recorded or Path(name).suffix.lower() not in sbom.FONT_SUFFIXES or original!='public/'+name:
            raise ValueError('static font source and delivered identity differ')
        font_paths.add(name)
        sbom.text(font['name']);sbom.text(font['version'])
        if font['original_download_url'] is not None:
            raise ValueError('static font provenance must preserve the declared unknown original download')
        expected=sbom.digest(source_root/original)
        if expected!=recorded[name]:
            raise ValueError('static font bytes changed between source and delivery')
        url='https://raw.githubusercontent.com'+repository.path+'/'+revision+'/'+original
        frontend.download(url,expected)
        license_=font['license'];sbom.fields(license_,['name','path'])
        if license_['name']!='OFL-1.1':
            raise ValueError('static font license requires an explicitly reviewed source')
        license_path=sbom.relative(license_['path'])
        if license_path not in recorded or sbom.digest(source_root/'public'/license_path)!=recorded[license_path]:
            raise ValueError('static font original license differs from the delivered text')
        frontend.download('https://raw.githubusercontent.com'+repository.path+'/'+revision+'/public/'+license_path,recorded[license_path])
        components.append({'ref':'urn:static-font:'+expected,'type':'data','name':font['name'],
            'version':font['version'],'source':{'url':url,'sha256':expected},
            'licenses':[{'name':'SIL Open Font License 1.1','path':license_path,'sha256':recorded[license_path]}],
            'delivery':'file','files':bindings([name]),'dependencies':[]})
    if font_paths!={name for name in recorded if Path(name).suffix.lower() in sbom.FONT_SUFFIXES}:
        raise ValueError('static font provenance does not cover the actual delivered fonts')
    frontend.retain(stage,'share/build-inputs/frontend/rendered.json',
                    (json.dumps(data,sort_keys=True,indent=2)+'\n').encode())
    receipt={'format_version':1,'runtime_roots':[],'components':components}
    frontend.retain(stage,'share/external-components.json',
                    (json.dumps(receipt,sort_keys=True,indent=2)+'\n').encode())
    return components
