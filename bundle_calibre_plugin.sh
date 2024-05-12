#!/usr/bin/env bash

# Copyright (c) 2021-2023 Leseratte10
# This file is part of the ACSM Input Plugin by Leseratte10
# ACSM Input Plugin for Calibre / acsm-calibre-plugin
#
# For more information, see: 
# https://github.com/Leseratte10/acsm-calibre-plugin

sed_i() {
    script="$1"
    path="$2"
    tmpfile="$path.tmp"
    sed "$script" "$path" > "$tmpfile"
    mv "$tmpfile" "$path"
}


[ ! -f calibre-plugin/asn1crypto.zip ] && ./package_modules.sh
[ ! -f calibre-plugin/oscrypto.zip ] && ./package_modules.sh

rm -rf calibre-plugin-tmp || /bin/true

cp -r calibre-plugin calibre-plugin-tmp

pushd calibre-plugin-tmp
pushd keyextract

# Compile C programs: 
make

base64 decrypt_win32.exe > decrypt_win32_b64.txt
base64 decrypt_win64.exe > decrypt_win64_b64.txt

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

# Delete cache
rm -r __pycache__
rm *.pyc

# Set module ID. This needs to be changed if any of the module ZIPs change.
echo -n "2023-12-19-01" > module_id.txt

# Copy LICENSE and README.md so it'll be included in the ZIP.
cp ../LICENSE LICENSE
cp ../README.md README.md

shopt -s globstar
echo "Injecting Python2 compat code ..."
for file in **/*.py;
do
    #echo $file
    # Inject Python2 compat code:
    sed_i '/#@@CALIBRE_COMPAT_CODE@@/ {
        r __calibre_compat_code.py
        d
    }' $file

done



# Create ZIP file from calibre-plugin folder.
zip -r ../calibre-plugin.zip *

popd
rm -rf calibre-plugin-tmp

