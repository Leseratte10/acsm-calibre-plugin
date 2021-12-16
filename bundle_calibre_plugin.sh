#!/bin/bash

[ ! -f calibre-plugin/cryptography.zip ] && ./package_modules.sh
[ ! -f calibre-plugin/rsa.zip ] && ./package_modules.sh
[ ! -f calibre-plugin/asn1crypto.zip ] && ./package_modules.sh
[ ! -f calibre-plugin/oscrypto.zip ] && ./package_modules.sh
[ ! -f calibre-plugin/pyasn1.zip ] && ./package_modules.sh

pushd calibre-plugin
pushd keyextract

# Compile C programs: 
make

popd

# Set module ID. This needs to be changed if any of the module ZIPs change.
echo -n "2021-12-15-01" > module_id.txt

# Copy LICENSE so it'll be included in the ZIP.
cp ../LICENSE LICENSE

# Create ZIP file from calibre-plugin folder.
zip -r ../calibre-plugin.zip *

popd

