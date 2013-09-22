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

"""SSH message authentication handlers"""

import hmac
from hashlib import md5, sha1, sha256, sha512

from .constants import *
from .misc import *
from .packet import *

_mac_algs = []
_mac_sizes = {}
_mac_handlers = {}

class _MAC:
    """Parent class for SSH message authentication handlers"""

    def __init__(self, alg, hash, hash_size, key):
        self._hash = hash
        self._hash_size = hash_size
        self._key = key

    def sign(self, data):
        """Compute a signature for a message"""

        sig = hmac.new(self._key, data, self._hash).digest()
        return sig[:self._hash_size]

    def verify(self, data, sig):
        """Verify the signature of a message"""

        return self.sign(data) == sig

def register_mac_algorithm(alg, hash, key_size, hash_size):
    """Register a MAC algorithm"""

    _mac_algs.append(alg)
    _mac_sizes[alg] = (key_size, hash_size)
    _mac_handlers[alg] = (hash, hash_size)

def get_mac_algs():
    """Return a list of available MAC algorithms"""

    return [alg + b'-etm@openssh.com' for alg in _mac_algs] + _mac_algs

def choose_mac_algorithm(conn, peer_mac_algs):
    """Choose the MAC algorithm to use
    
       This function returns the MAC algorithm to use and the number of
       bytes of data needed for its key.
    """

    if conn.is_client():
        client_algs = get_mac_algs()
        server_algs = peer_mac_algs
    else:
        client_algs = peer_mac_algs
        server_algs = get_mac_algs()

    for alg in client_algs:
        if alg in server_algs:
            if alg.endswith(b'-etm@openssh.com'):
                alg = alg[:-16]
                etm = True
            else:
                etm = False

            key_size, hash_size = _mac_sizes[alg]
            return alg, key_size, hash_size, etm

    raise SSHError(DISC_KEY_EXCHANGE_FAILED,
                   'No matching MAC algorithm found')

def get_mac(alg, key):
    """Return an instance of a MAC generator

       This function returns a MAC object initialized with the specified
       kev that can be used for data signing and verification.

    """

    hash, hash_size = _mac_handlers[alg]
    return _MAC(alg, hash, hash_size, key)

register_mac_algorithm(b'hmac-sha2-256',    sha256, 32, 32)
register_mac_algorithm(b'hmac-sha2-512',    sha512, 64, 64)
register_mac_algorithm(b'hmac-sha1',        sha1,   20, 20)
register_mac_algorithm(b'hmac-md5',         md5,    16, 16)
register_mac_algorithm(b'hmac-sha2-256-96', sha256, 32, 12)
register_mac_algorithm(b'hmac-sha2-512-96', sha512, 64, 12)
register_mac_algorithm(b'hmac-sha1-96',     sha1,   20, 12)
register_mac_algorithm(b'hmac-md5-96',      md5,    16, 12)
