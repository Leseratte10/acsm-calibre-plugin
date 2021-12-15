#!/bin/bash

pushd calibre-plugin

wget https://github.com/Leseratte10/acsm-calibre-plugin/releases/download/config/asn1crypto_1.4.0.zip -O asn1crypto.zip
wget https://github.com/Leseratte10/acsm-calibre-plugin/releases/download/config/cryptography_36.0.1.zip -O cryptography.zip
wget https://github.com/Leseratte10/acsm-calibre-plugin/releases/download/config/oscrypto_1.2.1.zip -O oscrypto.zip
wget https://github.com/Leseratte10/acsm-calibre-plugin/releases/download/config/pyasn1_0.4.8.zip -O pyasn1.zip
wget https://github.com/Leseratte10/acsm-calibre-plugin/releases/download/config/rsa_4.8.zip -O rsa.zip

popd

