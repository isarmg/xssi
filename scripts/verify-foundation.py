#!/usr/bin/env python3
"""Verify the actual helper against its exact official foundation policy."""
import os
from pathlib import Path
import re
import tempfile
import tomllib

import sbom


def verify(root):
    root=Path(root).resolve(strict=True)
    cargo=tomllib.loads((root/'Cargo.toml').read_text())
    dependency=cargo['dependencies']['xcsc']
    if (dependency.get('git')!='https://github.com/isarmg/xcsc.git'
            or not re.fullmatch('[0-9a-f]{40}',dependency.get('rev',''))
            or not re.fullmatch(r'=(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)',dependency.get('version',''))
            or dependency.get('features')!=['offline-maintenance']):
        raise ValueError('helper must use the exact official offline-maintenance source')
    revision=dependency['rev']
    with tempfile.TemporaryDirectory(prefix='xssi-foundation-policy-') as temporary:
        source=Path(temporary).resolve(strict=True)
        environment=os.environ.copy()
        environment['GIT_TERMINAL_PROMPT']='0'
        for arguments in (["git","init","--quiet"],
                          ["git","fetch","--quiet","--depth=1",dependency['git'],revision],
                          ["git","checkout","--quiet","--detach","FETCH_HEAD"]):
            sbom.run(arguments,source,environment,maximum=65536,timeout=180)
        actual=sbom.run(['git','rev-parse','HEAD'],source,environment,maximum=128,timeout=10).decode().strip()
        if actual!=revision:
            raise ValueError('fetched foundation source differs from declared commit')
        result=sbom.run(['python3',str(source/'scripts/check-xcsc.py'),'--product-root',str(root)],
                        source,environment,maximum=65536,timeout=60)
        print(result.decode().strip())


if __name__=='__main__':
    verify(Path(__file__).resolve().parents[1])
