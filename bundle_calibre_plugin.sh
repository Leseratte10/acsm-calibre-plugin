#!/usr/bin/env bash

# Copyright (c) 2021-2026 Leseratte10
# This file is part of the ACSM Input Plugin by Leseratte10
# ACSM Input Plugin for Calibre / acsm-calibre-plugin
#
# For more information, see: 
# https://github.com/Leseratte10/acsm-calibre-plugin

set -e

sed_i() {
    # Added by @vasi in PR #88 because MacOS and FreeBSD don't support "sed -i".

    script="$1"
    path="$2"
    tmpfile="$path.tmp"
    sed "$script" "$path" > "$tmpfile"
    mv "$tmpfile" "$path"
}


rm -rf calibre-plugin-tmp || /bin/true

cp -r calibre-plugin calibre-plugin-tmp

pushd calibre-plugin-tmp
pushd keyextract

# Compile C programs: 
make

base64 < decrypt_win32.exe > decrypt_win32_b64.txt
base64 < decrypt_win64.exe > decrypt_win64_b64.txt

# Base64-encode binaries and place them inside decryptor.py: 
sed_i "/@@@CALIBRE_DECRYPTOR_WIN32_B64@@@/ {
    r decrypt_win32_b64.txt
    d
}" ../keyextractDecryptor.py

sed_i "/@@@CALIBRE_DECRYPTOR_WIN64_B64@@@/ {
    r decrypt_win64_b64.txt
    d
}" ../keyextractDecryptor.py

rm decrypt_win32_b64.txt decrypt_win64_b64.txt
rm decrypt_win32.exe decrypt_win64.exe

popd

# Delete unnecessary files
rm -rf __pycache__ customcrypto/__pycache__ customcrypto/customcrypto/__pycache__ customcrypto/tests customcrypto/readme_internal.md
rm -f *.pyc 

# Copy LICENSE and README.md so it'll be included in the ZIP.
cp ../LICENSE LICENSE
cp ../README.md README.md

# Create ZIP file from calibre-plugin folder.
rm -f ../calibre-plugin.zip
zip -r ../calibre-plugin.zip *

popd
rm -rf calibre-plugin-tmp

