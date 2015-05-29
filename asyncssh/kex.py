# Copyright (c) 2013-2015 by Ron Frederick <ronf@timeheart.net>.
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

from .packet import MPInt, SSHPacketHandler

_kex_algs = []
_kex_handlers = {}


class Kex(SSHPacketHandler):
    """Parent class for key exchange handlers"""

    def __init__(self, alg, conn, hash_alg):
        self.algorithm = alg

        self._conn = conn
        self._hash_alg = hash_alg

    def compute_key(self, k, h, x, session_id, keylen):
        """Compute keys from output of key exchange"""

        key = b''
        while len(key) < keylen:
            hash_obj = self._hash_alg()
            hash_obj.update(MPInt(k))
            hash_obj.update(h)
            hash_obj.update(key if key else x + session_id)
            key += hash_obj.digest()

        return key[:keylen]


def register_kex_alg(alg, handler, hash_alg, *args):
    """Register a key exchange algorithm"""

    _kex_algs.append(alg)
    _kex_handlers[alg] = (handler, hash_alg, args)


def get_kex_algs():
    """Return a list of available key exchange algorithms"""

    return _kex_algs


def get_kex(conn, alg):
    """Return a key exchange handler

       The function looks up a key exchange algorithm and returns a
       handler which can perform that type of key exchange.

    """

    handler, hash_alg, args = _kex_handlers[alg]
    return handler(alg, conn, hash_alg, *args)
