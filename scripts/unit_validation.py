"""One installed systemd contract, checked before stopping any writer."""
from pathlib import Path


def template_bytes(template,root,product):
    escaped=str(root).replace('\\','\\\\').replace('"','\\"').replace('%','%%')
    return template.replace(b'@ROOT@',escaped.encode()).replace(b'@USER@',('isarmg-'+product).encode())


def writable_bytes(paths,readonly_paths=()):
    def render(values,minimum):
        if not isinstance(values,(list,tuple)) or not minimum<=len(values)<=128:
            raise ValueError('invalid declared path count')
        quoted=[]
        for value in values:
            path=Path(value)
            if not path.is_absolute() or path==Path('/') or '..' in path.parts or any(ord(character)<32 or ord(character)==127 for character in str(value)):
                raise ValueError('invalid declared systemd path')
            quoted.append('"'+str(path).replace('\\','\\\\').replace('"','\\"').replace('%','%%')+'"')
        return ' '.join(quoted)
    writable=render(paths,1)
    readonly=render(readonly_paths,0)
    return ('[Service]\nReadWritePaths=\nReadWritePaths='+writable+'\nReadOnlyPaths=\nReadOnlyPaths='+readonly+'\n').encode()


def loaded_paths(name,observation):
    if len(observation)>64*1024:raise ValueError('unit observation exceeds its bound')
    properties={}
    for line in observation.decode('utf-8').splitlines():
        key,value=line.split('=',1)
        if key in properties:raise ValueError('duplicate unit observation')
        properties[key]=value
    unit=Path('/etc/systemd/system')/name
    dropin=unit.with_name(unit.name+'.d')/'state.conf'
    if properties!={'LoadState':'loaded','FragmentPath':str(unit),'DropInPaths':str(dropin),'NeedDaemonReload':'no'}:
        raise ValueError('loaded systemd unit differs from the installed contract')
    return unit,dropin


def match_bytes(root,product,template,writable_paths,actual_unit,actual_writable,readonly_paths=()):
    if actual_unit!=template_bytes(template,root,product) or actual_writable!=writable_bytes(writable_paths,readonly_paths):
        raise ValueError('installed systemd configuration differs from the verified source and current root')
