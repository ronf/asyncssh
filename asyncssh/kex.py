# Copyright (c) 2013-2014 by Ron Frederick <ronf@timeheart.net>.
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

"""SSH key exchange handlers"""

from .packet import *

_kex_algs = []
_kex_handlers = {}


class Kex(SSHPacketHandler):
    """Parent class for key exchange handlers"""

    def __init__(self, alg, conn, hash):
        self.algorithm = alg

        self._conn = conn
        self._hash = hash

    def compute_key(self, k, h, x, session_id, keylen):
        """Compute keys from output of key exchange"""

        key = b''
        while len(key) < keylen:
            hash = self._hash()
            hash.update(MPInt(k))
            hash.update(h)
            hash.update(key if key else x + session_id)
            key += hash.digest()

        return key[:keylen]


def register_kex_alg(alg, handler, hash, *args):
    """Register a key exchange algorithm"""

    _kex_algs.append(alg)
    _kex_handlers[alg] = (handler, hash, args)

def get_kex_algs():
    """Return a list of available key exchange algorithms"""

    return _kex_algs

def lookup_kex_alg(conn, alg):
    """Look up a key exchange algorithm

       The function looks up a key exchange algorithm and returns a
       handler which can perform that type of key exchange.

    """

    handler, hash, args = _kex_handlers[alg]
    return handler(alg, conn, hash, *args)
