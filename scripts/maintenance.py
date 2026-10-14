#!/usr/bin/env python3
"""Explicit offline check/reset/media configuration, never upgrade or uninstall."""
import argparse
import os
import json
import uuid
from pathlib import Path
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import package
import writer_control
import material_store
from install import ServiceIdentityError, controlled_chain, coordinator_lock, credential_input, directory, require_root, sealed_setup, service_identity

def stopped_writers(manifest):
    return writer_control.require_stopped([writer['name'] for writer in manifest['services']])

def run(args):
    root=package.private_chain(args.root.absolute())
    require_root();controlled_chain(root)
    config=args.config.absolute() if args.config else root/'config/config.json'
    if config!=root/'config/config.json':raise ValueError('config must identify ROOT/config/config.json')
    lock=coordinator_lock(root)
    try:
        manifest=package.verify(root,installed=True)
        product=manifest['identity']['product']
        if product not in package.PRODUCTS:raise ValueError('unsupported product')
        if args.operation=='collect':
            if args.operation_id or args.username or args.minimum_age_seconds is None or args.keep_completed is None:raise ValueError('collection requires an explicit retention policy without write-operation arguments')
            print(json.dumps(material_store.collect(root,lock,args.minimum_age_seconds,args.keep_completed,args.execute),sort_keys=True))
            return
        if args.execute or args.minimum_age_seconds is not None or args.keep_completed is not None:raise ValueError('retention parameters only apply to explicit collection')
        entry=next(e for e in manifest['files'] if e['path']==manifest['setup'])
        identity=service_identity(product,False,create=False)
        common=['--product',product,'--root',str(root),'--config',str(config),'--json','--service-uid',str(identity[0]),'--service-gid',str(identity[1])]
        arguments=common+[args.operation];password=None
        if args.operation=='admin-reset':
            if not args.username:raise ValueError('admin-reset requires explicit username')
            arguments+=['--username',args.username]
            if not args.operation_id:password=credential_input()
        record=None;stopped=None
        if args.operation=='check':
            if args.operation_id:raise ValueError('check cannot resume a write operation')
            stopped=stopped_writers(manifest)
        else:
            parent=root/'maintenance/operations';directory(parent,0o700)
            operation=args.operation_id or str(uuid.uuid4())
            parsed=uuid.UUID(operation)
            if parsed.version!=4 or str(parsed)!=operation:raise ValueError('operation ID must be canonical UUIDv4')
            work=parent/operation
            if args.operation_id:
                package.private_chain(work)
                material_record,work=material_store.begin(root,'maintenance',lock,operation)
                record=work/'startup-control.json'
                services=[e['name'] for e in manifest['services']]
                control=writer_control.inspect_control(record)
                if control['services']!=services:raise ValueError('maintenance writer set differs from its record')
                if control['phase'] in ('restore-startup-intent','startup-restored'):
                    # The write and its check finished before this phase. Only
                    # finish cleanup; never replay a reset or request new secrets.
                    writer_control.restore_startup(record)
                    material_store.complete(root,material_record,lock,{'startup-control.json'})
                    print(json.dumps({'status':'maintenance_startup_restored','operation_id':operation}))
                    return
                if args.operation=='admin-reset':password=credential_input()
                writer_control.resume_control(record,services)
            else:
                material_record,work=material_store.begin(root,'maintenance',lock,operation)
                record=work/'startup-control.json'
                writer_control.control_writers([e['name'] for e in manifest['services']],record)
        output=sealed_setup(root/manifest['setup'],entry['sha256'],arguments,None,password,tool_lock_fd=lock)
        if stopped is not None:
            writer_control.require_stopped([writer['name'] for writer in manifest['services']],before=stopped)
        if record:
            sealed_setup(root/manifest['setup'],entry['sha256'],common+['check'],None,tool_lock_fd=lock)
            writer_control.restore_startup(record)
            material_store.complete(root,material_record,lock,{'startup-control.json'})
        print(output.decode().strip())
    finally:os.close(lock)

def main():
    parser=package.MachineParser()
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--config',type=Path)
    parser.add_argument('--json',action='store_true')
    parser.add_argument('--operation-id')
    parser.add_argument('operation',choices=['check','admin-reset','regenerate-media','collect'])
    parser.add_argument('--minimum-age-seconds',type=int)
    parser.add_argument('--keep-completed',type=int)
    parser.add_argument('--execute',action='store_true')
    parser.add_argument('--username')
    args=parser.parse_args()
    try:run(args)
    except ServiceIdentityError as failure:
        if args.json:print(json.dumps({'error':{'code':'SERVICE_IDENTITY_INVALID','message':str(failure),'retryable':False}}))
        else:print(str(failure),file=sys.stderr)
        raise SystemExit(1)
    except Exception:
        message='Offline maintenance failed; inspect ROOT/maintenance/operations and the recorded startup controls before resuming the same operation.'
        if args.json:print(json.dumps({'error':{'code':'MAINTENANCE_FAILED','message':message,'retryable':False}}))
        else:print(message,file=sys.stderr)
        raise SystemExit(1)

if __name__=='__main__':main()
