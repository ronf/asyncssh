#!/bin/bash
#
# Build and install libsodum 1.0.10
#
git clone git://github.com/jedisct1/libsodium.git
cd libsodium
git checkout tags/1.0.10
./autogen.sh
./configure
make && sudo make install
sudo ldconfig
