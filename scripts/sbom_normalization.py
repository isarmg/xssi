"""Normalize real CycloneDX output without leaking private build paths."""
import copy
from pathlib import PurePosixPath, PureWindowsPath
import re
from urllib.parse import parse_qs, unquote


def reachable(metadata,root_id):
    nodes={node['id']:node for node in metadata['resolve']['nodes']}
    compile_time={item['id'] for item in metadata['packages']
                  if any('proc-macro' in target.get('kind',[]) for target in item.get('targets',[]))}
    if len(nodes)!=len(metadata['resolve']['nodes']):raise ValueError('duplicate Cargo resolve node')
    found={root_id};pending=[root_id]
    while pending:
        node=nodes[pending.pop()]
        for dependency in node['deps']:
            kinds=dependency['dep_kinds']
            if not kinds or any(kind['kind'] is None for kind in kinds):
                if dependency['pkg'] not in found and dependency['pkg'] not in compile_time:
                    found.add(dependency['pkg']);pending.append(dependency['pkg'])
    return found


def decoded(value):
    values=[value]
    for _ in range(16):
        current=unquote(values[-1])
        if current==values[-1]:return values
        values.append(current)
    if unquote(values[-1])!=values[-1]:raise ValueError('excessively encoded SBOM value')
    return values


def selected_metadata(metadata, selection):
    """Restrict metadata to the separately queried package/target/feature tree.

    Metadata unites workspace features. Its full graph remains source identity
    evidence; Cargo's selected normal tree decides the runtime graph recorded
    here. This does not replace the final binary and file inventory checks.
    """
    if set(selection) != {'root','ids','edges'} or not isinstance(selection['ids'],list):
        raise ValueError('invalid selected Cargo graph authority')
    ids=set(selection['ids'])
    packages={item['id']:item for item in metadata['packages']}
    nodes={item['id']:item for item in metadata['resolve']['nodes']}
    edges=selection['edges'];root=selection['root']
    if (not ids or len(ids)!=len(selection['ids']) or len(ids)>4096
        or len(packages)!=len(metadata['packages']) or len(nodes)!=len(metadata['resolve']['nodes'])
        or root not in ids or not ids<=packages.keys() or not ids<=nodes.keys() or set(edges)!=ids):
        raise ValueError('selected Cargo graph lacks a closed unique source identity')
    for identifier,children in edges.items():
        if not isinstance(children,list) or len(children)!=len(set(children)) or not set(children)<=ids:
            raise ValueError('invalid selected Cargo dependency edge')
        if any('proc-macro' in target.get('kind',[]) for target in packages[identifier].get('targets',[])):
            raise ValueError('selected runtime graph contains a procedural macro')
        allowed={dependency['pkg'] for dependency in nodes[identifier]['deps']
                 if not dependency['dep_kinds'] or any(kind['kind'] is None for kind in dependency['dep_kinds'])}
        if not set(children)<=allowed:raise ValueError('selected tree edge differs from normal Cargo metadata')
    reached={root};pending=[root]
    while pending:
        for child in edges[pending.pop()]:
            if child not in reached:reached.add(child);pending.append(child)
    if reached!=ids:raise ValueError('selected Cargo runtime graph has disconnected packages')
    output=copy.deepcopy(metadata)
    output['packages']=[item for item in output['packages'] if item['id'] in ids]
    output['resolve']['root']=root
    output['resolve']['nodes']=[item for item in output['resolve']['nodes'] if item['id'] in ids]
    for node in output['resolve']['nodes']:
        node['deps']=[dependency for dependency in node['deps'] if dependency['pkg'] in edges[node['id']]]
        node['dependencies']=[identifier for identifier in node.get('dependencies',[]) if identifier in edges[node['id']]]
    return output


def normalize(bom,metadata,root_name,local_revisions,build_roots):
    if bom.get('bomFormat')!='CycloneDX' or bom.get('specVersion')!='1.5' or type(bom.get('version')) is not int or bom['version']!=1:
        raise ValueError('unsupported CycloneDX document')
    packages={item['id']:item for item in metadata['packages']}
    if len(packages)!=len(metadata['packages']) or len(packages)>4096:raise ValueError('invalid Cargo package count')
    roots=[item for item in packages.values() if item['name']==root_name and item['source'] is None]
    if len(roots)!=1:raise ValueError('Cargo metadata has no unique selected root')
    root=roots[0]
    identifiers={}
    local_packages={}
    for identifier,item in packages.items():
        if item['source'] is not None:continue
        revision=local_revisions.get(identifier,'')
        if not re.fullmatch(r'[0-9a-f]{40}',revision):raise ValueError('local Cargo source is not bound to a Git revision')
        stable=f"pkg:cargo/{item['name']}@{item['version']}?source_revision={revision}"
        identity=(item['name'],item['version'])
        if identity in local_packages:raise ValueError('ambiguous local package identity')
        identifiers[identifier]=stable;local_packages[identity]=stable
    def scan(value):
        for candidate in decoded(value):
            lower=candidate.lower()
            if ('path+file:' in lower or 'download_url=file:' in lower or 'file://' in lower or lower.startswith('file:')
                or any(str(root) in candidate for root in build_roots)
                or PurePosixPath(candidate).is_absolute() or PureWindowsPath(candidate).is_absolute()
                or re.search(r"(?:^|[\s\"'=(#])/(?:home|mnt|root|tmp|var/tmp)/",candidate)):
                raise ValueError('SBOM contains a private local path')
        return value
    def walk(value,key=''):
        if isinstance(value,list):return [walk(item,key) for item in value]
        if isinstance(value,dict):return {name:walk(item,name) for name,item in value.items()}
        if not isinstance(value,str):return value
        for identifier,stable in identifiers.items():
            if value==identifier or value.startswith(identifier+' '):return scan(stable+value[len(identifier):])
        if key=='purl':
            body,separator,fragment=value.partition('#')
            for (name,version),stable in local_packages.items():
                prefix=f'pkg:cargo/{name}@{version}?'
                if body.startswith(prefix):
                    query=parse_qs(body[len(prefix):],strict_parsing=True)
                    urls=query.get('download_url',[])
                    if len(urls)==1 and urls[0].lower().startswith('file:'):
                        for candidate in decoded(fragment):
                            if (PurePosixPath(candidate).is_absolute() or PureWindowsPath(candidate).is_absolute()
                                or '..' in PurePosixPath(candidate).parts or '\\' in candidate
                                or any(ord(character)<32 or ord(character)==127 for character in candidate)):
                                raise ValueError('unsafe SBOM target fragment')
                        return scan(stable+(separator+fragment if separator else ''))
        return scan(value)
    # The mature producer can include dependencies enabled by another workspace
    # member. Remove that independently excluded material before scanning the
    # selected components; its local paths are neither published nor attributed
    # to this product. Selected component fields still receive the full scan.
    runtime_ids=reachable(metadata,root['id'])
    selected=copy.deepcopy(bom)
    selected['components']=[item for item in selected.get('components',[]) if item.get('bom-ref') in runtime_ids]
    selected['dependencies']=[{'ref':node['ref'],'dependsOn':[child for child in node.get('dependsOn',[]) if child in runtime_ids]}
                              for node in selected.get('dependencies',[]) if node['ref'] in runtime_ids]
    output=walk(selected)
    component=output['metadata']['component']
    root_id=identifiers[root['id']]
    if component.get('name')!=root_name or component.get('version')!=root['version'] or component.get('bom-ref')!=root_id or component.get('purl')!=root_id:
        raise ValueError('SBOM root differs from the resolved source')
    refs=set()
    def components(items):
        for item in items:
            identifier=item.get('bom-ref')
            if not isinstance(identifier,str) or not identifier or identifier in refs:raise ValueError('duplicate or missing SBOM component reference')
            refs.add(identifier)
            components(item.get('components',[]))
    components([component,*output.get('components',[])])
    dependency_refs=set()
    dependencies={}
    for node in output.get('dependencies',[]):
        identifier=node['ref']
        children=node.get('dependsOn',[])
        if identifier in dependency_refs or identifier not in refs or len(children)!=len(set(children)) or not set(children)<=refs:
            raise ValueError('SBOM dependency references are not closed and unique')
        dependency_refs.add(identifier)
        dependencies[identifier]=set(children)
    if root_id not in dependency_refs:raise ValueError('SBOM has no dependency root')
    required={identifiers.get(identifier,identifier) for identifier in runtime_ids}
    if not required<=refs:raise ValueError('SBOM omits a resolved runtime dependency')
    reached={root_id};pending=[root_id]
    while pending:
        for child in dependencies.get(pending.pop(),set()):
            if child not in reached:reached.add(child);pending.append(child)
    if not required<=reached:raise ValueError('SBOM disconnects a resolved runtime dependency')
    runtime_edges={}
    for node in metadata['resolve']['nodes']:
        identifier=identifiers.get(node['id'],node['id'])
        if identifier not in required:continue
        children={identifiers.get(dependency['pkg'],dependency['pkg']) for dependency in node['deps']
                  if dependency['pkg'] in runtime_ids
                  and (not dependency['dep_kinds'] or any(kind['kind'] is None for kind in dependency['dep_kinds']))}
        if not children<=dependencies.get(identifier,set()):raise ValueError('SBOM omits a resolved runtime dependency edge')
        runtime_edges[identifier]=children
    def runtime_components(items):
        result=[]
        for item in items:
            if item['bom-ref'] in required:
                item['components']=runtime_components(item.get('components',[]))
                if not item['components']:item.pop('components')
                result.append(item)
        return result
    output['components']=runtime_components(output.get('components',[]))
    component['components']=runtime_components(component.get('components',[]))
    if not component['components']:
        component.pop('components')
    output['dependencies']=[{'ref':identifier,'dependsOn':sorted(children)}
                            for identifier,children in sorted(runtime_edges.items())]
    output['metadata']['properties']=[*output['metadata'].get('properties',[]),
        {'name':'dependency-scope','value':'resolved normal runtime dependencies for the selected target and features'}]
    return output
