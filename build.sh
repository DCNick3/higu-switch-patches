#!/bin/bash

set -e

MAIN_UNCOMPRESSED_NSO="$(realpath main_uncompressed)"

if [ ! -f "$MAIN_UNCOMPRESSED_NSO" ]; then
  echo "Can't find uncompressed 'main' executable file"
  echo "See README.md for more info"
  exit 1
fi

./build_wps.sh "$MAIN_UNCOMPRESSED_NSO" higu_debug_patchset.wps higu_patchset
