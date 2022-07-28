#!/bin/bash

pushd calibre-plugin

# As the latest oscrypto release (1.3.0) does not yet support OpenSSL3, we'll have to download a forked version ...
# See https://github.com/wbond/oscrypto/pull/61 for more information.

wget https://github.com/Leseratte10/acsm-calibre-plugin/releases/download/config/asn1crypto_1.5.1.zip -O asn1crypto.zip
wget https://github.com/Leseratte10/acsm-calibre-plugin/releases/download/config/oscrypto_1.3.0_fork_fe39273cc5020.zip -O oscrypto.zip

popd

