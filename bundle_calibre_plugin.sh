#!/bin/bash

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
sed "/@@@CALIBRE_DECRYPTOR_WIN32_B64@@@/ {
    r decrypt_win32_b64.txt
    d
}" -i ../keyextractDecryptor.py

sed "/@@@CALIBRE_DECRYPTOR_WIN64_B64@@@/ {
    r decrypt_win64_b64.txt
    d
}" -i ../keyextractDecryptor.py

rm decrypt_win32_b64.txt decrypt_win64_b64.txt
rm decrypt_win32.exe decrypt_win64.exe

popd

# Delete cache
rm -r __pycache__
rm *.pyc

# Set module ID. This needs to be changed if any of the module ZIPs change.
echo -n "2022-07-28-01" > module_id.txt

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

