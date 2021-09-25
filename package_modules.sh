#!/bin/bash

pushd calibre-plugin

wget https://github.com/Leseratte10/acsm-calibre-plugin/releases/download/config/asn1crypto.zip -O asn1crypto.zip
wget https://github.com/Leseratte10/acsm-calibre-plugin/releases/download/config/cryptography.zip -O cryptography.zip
wget https://github.com/Leseratte10/acsm-calibre-plugin/releases/download/config/oscrypto.zip -O oscrypto.zip
wget https://github.com/Leseratte10/acsm-calibre-plugin/releases/download/config/pyasn1.zip -O pyasn1.zip
wget https://github.com/Leseratte10/acsm-calibre-plugin/releases/download/config/rsa.zip -O rsa.zip

popd

