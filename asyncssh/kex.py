# Copyright (c) 2013 by Ron Frederick <ronf@timeheart.net>.
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

from .constants import *
from .misc import *
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


def register_kex_algorithm(alg, handler, hash, args):
    """Register a key exchange algorithm"""

    _kex_algs.append(alg)
    _kex_handlers[alg] = (handler, hash, args)

def get_kex_algs():
    """Return a list of available key exchange algorithms"""

    return _kex_algs

def choose_kex_algorithm(conn, peer_kex_algs):
    """Choose the key exchange algorithm to use"""

    if conn.is_client():
        client_algs = _kex_algs
        server_algs = peer_kex_algs
    else:
        client_algs = peer_kex_algs
        server_algs = _kex_algs

    for alg in client_algs:
        if alg in server_algs:
            handler, hash, args = _kex_handlers[alg]
            return handler(alg, conn, hash, *args)

    raise SSHError(DISC_KEY_EXCHANGE_FAILED,
                   'No matching key exchange algorithm found')
