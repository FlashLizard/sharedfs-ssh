#!/bin/sh
# Shared entry point: bash deploy.sh server|client|start|stop|status ...
set -eu
deployment_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$deployment_dir/deploy.py" "$@"
