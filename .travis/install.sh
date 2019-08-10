#!/bin/bash

if [[ $TRAVIS_OS_NAME == 'osx' ]]; then
    export CPPFLAGS="-I/usr/local/opt/openssl/include"
    export LDFLAGS="-L/usr/local/opt/openssl/lib -L/usr/local/opt/libffi/lib"
    export PATH="$HOME/.pyenv/bin:/usr/local/opt/openssl/bin:$PATH"

    brew update
    brew install libffi libsodium
    eval "$(pyenv init -)"
    pyenv install $PYENV_VERSION
    pyenv global $PYENV_VERSION
    pyenv rehash
else
    git clone git://github.com/jedisct1/libsodium.git
    cd libsodium
    ./autogen.sh
    ./configure
    make && sudo make install
    sudo ldconfig
fi

pip install tox
