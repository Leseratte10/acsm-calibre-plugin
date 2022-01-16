#!/bin/bash

[ ! -f calibre-plugin/asn1crypto.zip ] && ./package_modules.sh
[ ! -f calibre-plugin/oscrypto.zip ] && ./package_modules.sh

pushd calibre-plugin
pushd keyextract

# Compile C programs: 
make

popd

# Delete cache
rm -r __pycache__

# Set module ID. This needs to be changed if any of the module ZIPs change.
echo -n "2021-12-19-03" > module_id.txt

# Copy LICENSE and README.md so it'll be included in the ZIP.
cp ../LICENSE LICENSE
cp ../README.md README.md

# Create ZIP file from calibre-plugin folder.
zip -r ../calibre-plugin.zip *

popd

