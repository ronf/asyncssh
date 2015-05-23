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

"""A shim around PyCrypto for DSA public and private keys"""

from Crypto.Hash import SHA
from Crypto.PublicKey import DSA

from ...misc import randrange


class _DSAKey:
    def __getattr__(self, name):
        return getattr(self._key, name)


class DSAPrivateKey(_DSAKey):
    def __init__(self, p, q, g, y, x):
        self._key = DSA.construct((y, g, p, q, x))

    def sign(self, data):
        k = randrange(2, self._key.q)
        return self._key.sign(SHA.new(data).digest(), k)


class DSAPublicKey(_DSAKey):
    def __init__(self, p, q, g, y):
        self._key = DSA.construct((y, g, p, q))

    def verify(self, data, sig):
        return self._key.verify(SHA.new(data).digest(), sig)
