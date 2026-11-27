#!/bin/sh
# Shared entry point: bash deploy.sh [--python /absolute/path] COMMAND ...
set -eu
deployment_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

supported_python() {
    "$1" -I -S -c 'import sys; sys.exit(sys.version_info < (3, 9))' >/dev/null 2>&1
}

if [ "${1-}" = --python ]; then
    python=${2-}
    case "$python" in
        /*) ;;
        *) printf '%s\n' 'deploy: --python requires an absolute path to Python 3.9 or newer' >&2; exit 1 ;;
    esac
    if ! supported_python "$python"; then
        printf 'deploy: cannot run Python 3.9 or newer at %s\n' "$python" >&2
        exit 1
    fi
    shift 2
    exec "$python" "$deployment_dir/deploy.py" "$@"
fi

for name in python3 python3.15 python3.14 python3.13 python3.12 python3.11 python3.10 python3.9; do
    if python=$(command -v "$name") && supported_python "$python"; then
        exec "$python" "$deployment_dir/deploy.py" "$@"
    fi
done

printf '%s\n' 'deploy: Python 3.9 or newer is required and was not found on PATH.' \
    'Install a supported Python or run: bash deploy.sh --python /absolute/path/to/python3 COMMAND ...' >&2
exit 1
