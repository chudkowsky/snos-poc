#!/bin/bash

# commit taken: 6d99011f6ef2a3dc178f7c8db4f0ddc6e836f303
CAIRO_VER="0.14.0"

if ! command -v cairo-compile >/dev/null; then
    echo "please start cairo($CAIRO_VER) dev environment"
    exit 1
fi

if ! command -v starknet-compile-deprecated >/dev/null; then
    echo "please start cairo($CAIRO_VER) dev environment"
    exit 1
fi

echo -e "\ninitializing cairo-lang($CAIRO_VER)...\n"
git submodule update --init

FETCHED_CAIRO_VER="$(cat cairo-lang/src/starkware/cairo/lang/VERSION)"

if [ "$CAIRO_VER" != "$FETCHED_CAIRO_VER" ]; then
    echo "incorrect cairo ver($FETCHED_CAIRO_VER) expecting $CAIRO_VER"
    exit 1
fi

# compile os with debug info
cairo-compile --debug_info_with_source cairo-lang/src/starkware/starknet/core/os/os.cairo --output build/os_debug.json --cairo_path cairo-lang/src
cairo-compile cairo-lang/src/starkware/starknet/core/os/os.cairo --output build/os_${CAIRO_VER//./_}.json --cairo_path cairo-lang/src
