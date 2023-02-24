#!/bin/bash

# Copyright (c) 2021-2023 Leseratte10
# This file is part of the ACSM Input Plugin by Leseratte10
# ACSM Input Plugin for Calibre / acsm-calibre-plugin
#
# For more information, see: 
# https://github.com/Leseratte10/acsm-calibre-plugin

rm -rf calibre-plugin-tmp || /bin/true

mkdir calibre-plugin-tmp
cp migration_plugin/* calibre-plugin-tmp/
cp LICENSE calibre-plugin-tmp/

pushd calibre-plugin-tmp

# Create ZIP file from calibre-plugin folder.
zip -r ../calibre-migration-plugin.zip *

popd
rm -rf calibre-plugin-tmp

