#!/bin/sh
# Launch CdpNeighbor on Linux / Raspberry Pi.
# Re-runs itself through sudo because AF_PACKET needs CAP_NET_RAW.
set -eu

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SELF=$DIR/$(basename -- "$0")

if [ "$(id -u)" -ne 0 ]; then
    echo "AF_PACKET needs root; asking for sudo ..."
    exec sudo -- "$SELF" "$@"
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 not found. Install it with your package manager." >&2
    exit 2
fi

exec python3 "$DIR/cdp_advertiser_linux.py" "$@"
