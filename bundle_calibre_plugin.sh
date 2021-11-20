#!/bin/bash

[ ! -f calibre-plugin/cryptography.zip ] && ./package_modules.sh
[ ! -f calibre-plugin/rsa.zip ] && ./package_modules.sh
[ ! -f calibre-plugin/asn1crypto.zip ] && ./package_modules.sh
[ ! -f calibre-plugin/oscrypto.zip ] && ./package_modules.sh
[ ! -f calibre-plugin/pyasn1.zip ] && ./package_modules.sh

pushd calibre-plugin
pushd key-wine

# Compile: 
make

popd

zip -r ../calibre-plugin.zip *

popd

