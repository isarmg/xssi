#!/usr/bin/env bash
set -euo pipefail
[[ $# == 3 ]] || { echo 'Usage: build-package.sh PRODUCT SOURCE_ROOT STAGE' >&2; exit 2; }
product="$1"
source_root="$(cd -- "$2" && pwd -P)"
stage="$3"
case "$product" in xcos|xczs|xocs|xscs|xsos|xszs) ;; *) exit 2 ;; esac
[[ "$stage" = /* && -d "$stage" ]] || { echo 'Stage must be an existing absolute directory.' >&2; exit 1; }
: "${XSSI_IDENTITY_FILE:?Pass exact identity JSON from this product build}"
: "${XSSI_SCHEMA_FILE:?Pass exact schema JSON from this product build}"
tool_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
unset XSSI_BUILD_METADATA_DIR
python3 "$tool_root/scripts/build-helper.py" --product "$product" --source-root "$source_root" \
  --identity "$XSSI_IDENTITY_FILE" --stage "$stage"
install -d -m 0755 "$stage/libexec" "$stage/share/systemd"
if [[ -d "$stage/config" ]]; then
  install -d -m 0755 "$stage/share/config"
  for sample in "$stage/config/"*.example; do
    [[ -f "$sample" && ! -L "$sample" ]] || continue
    mv -- "$sample" "$stage/share/config/"
  done
  rmdir -- "$stage/config"
fi
python3 - "$tool_root" "$stage" "$product" <<'PY'
import pathlib,sys
tool,stage=pathlib.Path(sys.argv[1]),pathlib.Path(sys.argv[2])
sys.path.insert(0,str(tool/'scripts'))
import unit_templates
unit_templates.write(tool,stage,sys.argv[3])
PY
for entry in install.sh upgrade.sh maintenance.sh; do install -m 0755 "$tool_root/$entry" "$stage/$entry"; done
for entry in package.py material_store.py writer_control.py unit_validation.py install.py upgrade.py maintenance.py; do install -m 0644 "$tool_root/scripts/$entry" "$stage/libexec/$entry"; done
python3 - "$tool_root" "$stage" "$XSSI_IDENTITY_FILE" "$source_root" <<'PYFINAL'
import os,pathlib,sys
sys.path.insert(0,str(pathlib.Path(sys.argv[1])/'scripts'))
import frontend_receipt,package,release_sbom
stage=pathlib.Path(sys.argv[2]);identity=package.loads(pathlib.Path(sys.argv[3]).read_bytes())
source=pathlib.Path(sys.argv[4]);metadata=pathlib.Path(os.environ['XSSI_FRONTEND_METADATA_FILE'])
frontend_receipt.generate(source,stage,metadata,'bin/'+identity['product'])
if identity['product']=='xcos':
    import mediamtx_receipt
    components=mediamtx_receipt.record(source,stage,pathlib.Path(os.environ['XSSI_MEDIA_ARCHIVE']))
    receipt=stage/'share/external-components.json';data=release_sbom.load(receipt)
    data['components'].extend(components)
    import json
    receipt.write_text(json.dumps(data,sort_keys=True,indent=2)+'\n');receipt.chmod(0o644)
release_sbom.finalize(stage,[stage/'share/server-sbom.cdx.json',stage/'share/setup-sbom.cdx.json'],
                     stage/'share/external-components.json',identity['product'],identity['version'],
                     identity['source_revision'],identity['target'],build_input_root=source)
PYFINAL
arguments=(finalize "$stage" --identity "$XSSI_IDENTITY_FILE" --schema "$XSSI_SCHEMA_FILE")
python3 "$tool_root/scripts/package.py" "${arguments[@]}"
