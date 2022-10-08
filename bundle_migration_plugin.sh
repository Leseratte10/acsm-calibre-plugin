#!/bin/bash

rm -rf calibre-plugin-tmp || /bin/true

mkdir calibre-plugin-tmp
cp migration_plugin/* calibre-plugin-tmp/
cp LICENSE calibre-plugin-tmp/

pushd calibre-plugin-tmp

# Create ZIP file from calibre-plugin folder.
zip -r ../calibre-migration-plugin.zip *

popd
rm -rf calibre-plugin-tmp

