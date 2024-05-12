#!/usr/bin/env bash

# Copyright (c) 2021-2023 Leseratte10
# This file is part of the ACSM Input Plugin by Leseratte10
# ACSM Input Plugin for Calibre / acsm-calibre-plugin
#
# For more information, see: 
# https://github.com/Leseratte10/acsm-calibre-plugin

pushd calibre-plugin

# As the latest oscrypto release (1.3.0) does not yet support OpenSSL3, we'll have to download a forked version ...
# See https://github.com/wbond/oscrypto/pull/61 for more information.

wget https://github.com/Leseratte10/acsm-calibre-plugin/releases/download/config/asn1crypto_1.5.1.zip -O asn1crypto.zip
wget https://github.com/Leseratte10/acsm-calibre-plugin/releases/download/config/oscrypto_1.3.0_fork_2023-12-19.zip -O oscrypto.zip

popd

