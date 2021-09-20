#!/bin/bash

[ ! -f libgourou_bundle_release.tar.xz ] && ./package_sources.sh

cp libgourou_bundle_release.tar.xz calibre-plugin/

pushd calibre-plugin

zip -r ../calibre-plugin.zip *

popd

rm calibre-plugin/libgourou_bundle_release.tar.xz