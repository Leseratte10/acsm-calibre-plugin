#!/bin/bash

[ ! -f calibre-plugin/asn1crypto.zip ] && ./package_modules.sh
[ ! -f calibre-plugin/oscrypto.zip ] && ./package_modules.sh

rm -rf calibre-plugin-tmp || /bin/true

cp -r calibre-plugin calibre-plugin-tmp

pushd calibre-plugin-tmp
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

shopt -s globstar
echo "Injecting Python2 compat code ..."
for file in **/*.py;
do
    #echo $file
    # Inject Python2 compat code:
    sed '/#@@CALIBRE_COMPAT_CODE@@/ {
        r __calibre_compat_code.py
        d
    }' -i $file

done



# Create ZIP file from calibre-plugin folder.
zip -r ../calibre-plugin.zip *

popd
rm -rf calibre-plugin-tmp

