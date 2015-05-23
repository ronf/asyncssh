# Copyright (c) 2014-2015 by Ron Frederick <ronf@timeheart.net>.
# All rights reserved.
#
# This program and the accompanying materials are made available under
# the terms of the Eclipse Public License v1.0 which accompanies this
# distribution and is available at:
#
#     http://www.eclipse.org/legal/epl-v10.html
#
# Contributors:
#     Ron Frederick - initial implementation, API, and documentation

"""A shim around PyCrypto for RSA public and private keys"""

import random

from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


class _RSAKey:
    def __getattr__(self, name):
        return getattr(self._key, name)


class RSAPrivateKey(_RSAKey):
    def __init__(self, n, e, d, p, q):
        self._key = RSA.construct((n, e, d, p, q))

    def sign(self, data):
        return PKCS1_v1_5.new(self._key).sign(SHA.new(data))


class RSAPublicKey(_RSAKey):
    def __init__(self, n, e):
        self._key = RSA.construct((n, e))

    def verify(self, data, sig):
        return PKCS1_v1_5.new(self._key).verify(SHA.new(data), sig)
