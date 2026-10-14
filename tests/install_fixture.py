"""Test-only temporary installation adapter; never included in release payloads."""
import argparse
import importlib.util
from pathlib import Path
import sys


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--installer',type=Path,default=Path(__file__).resolve().parents[1]/'scripts/install.py')
    for name in ('package','root','config'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--username',default='admin')
    parser.add_argument('--configuration-file',action='append',default=[])
    args=parser.parse_args();source=args.installer
    args.fixture=True;args.package=args.package.absolute()
    specification=importlib.util.spec_from_file_location('install',source)
    module=importlib.util.module_from_spec(specification);sys.modules['install']=module
    specification.loader.exec_module(module)
    try:module.install(args)
    except Exception:
        print('Temporary fixture installation failed.',file=sys.stderr)
        raise SystemExit(1)


if __name__=='__main__':main()
