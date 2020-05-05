#!/bin/bash

set -e
DIR="$(dirname "$(realpath "$0")")"
HELPER="$DIR/patch_helper.py"

TMP_WPF="$(mktemp --suffix=.wpf)"
clean_up () {
    ARG=$?
    rm "$TMP_WPF"
    exit $ARG
} 
trap clean_up EXIT

NSO_FILE="$1"
WPS_FILE="$2"
OUT_DIR_NAME="$3"

DIRNAME="$(realpath "$(dirname "$WPS_FILE")")"

mkdir -p "$OUT_DIR_NAME"

# Run a C preprocessor on the WPS file
cpp -E -P -nostdinc -o "$TMP_WPF" $CPP_OPTIONS "$WPS_FILE"
# Compile it to the IPS patchset
"$HELPER" "$NSO_FILE" "$TMP_WPF" "$OUT_DIR_NAME" "$DIRNAME"
