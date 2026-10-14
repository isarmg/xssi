"""Render controlled product unit templates during release packaging."""
def write(tool,stage,product):
    server='bin/'+product
    templates=[(product+'.service','server.service.in')]
    if product=='xcos':templates.append(('xcos-mediamtx.service','media.service.in'))
    for name,template in templates:
        text=(tool/'templates'/template).read_text().replace('@PRODUCT@',product).replace('@SERVER@',server)
        if product=='xcos' and template=='server.service.in':
            text=text.replace('After=network-online.target\n','After=network-online.target xcos-mediamtx.service\nRequires=xcos-mediamtx.service\n')
        (stage/'share/systemd'/name).write_text(text)
