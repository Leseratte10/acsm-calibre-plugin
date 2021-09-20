#!/bin/bash

rm -rf libgourou

git clone git://soutade.fr/libgourou.git
pushd libgourou

# Pugixml
git clone https://github.com/zeux/pugixml.git lib/pugixml
pushd lib/pugixml
git checkout latest
popd

# Base64
git clone https://gist.github.com/f0fd86b6c73063283afe550bc5d77594.git lib/base64

# uPDFParser
git clone git://soutade.fr/updfparser.git lib/updfparser



popd
rm -f libgourou_bundle_raw.tar.xz 2>/dev/null
XZ_OPT=-9 tar -Jcvf libgourou_bundle_raw.tar.xz libgourou
pushd libgourou

# Delete unnecessary stuff from release archive so the file stays small.
rm -rf ./.git/
rm -rf ./lib/*/.git/
rm -rf ./lib/pugixml/docs/

# Now patch the setup file: 

echo "#!/bin/bash" > scripts/setup.sh
echo "pushd lib/updfparser" >> scripts/setup.sh
echo "make BUILD_STATIC=1 BUILD_SHARED=0" >> scripts/setup.sh
echo "popd" >> scripts/setup.sh

popd

rm -f libgourou_bundle_release.tar.xz 2>/dev/null
XZ_OPT=-9 tar -Jcvf libgourou_bundle_release.tar.xz libgourou