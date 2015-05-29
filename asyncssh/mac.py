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

"""SSH message authentication handlers"""

import hmac
from hashlib import md5, sha1, sha256, sha512


_ETM = b'-etm@openssh.com'

_mac_algs = []
_mac_params = {}
_mac_handlers = {}


class _MAC:
    """Parent class for SSH message authentication handlers"""

    def __init__(self, hash_alg, hash_size, key):
        self._hash_alg = hash_alg
        self._hash_size = hash_size
        self._key = key

    def sign(self, data):
        """Compute a signature for a message"""

        sig = hmac.new(self._key, data, self._hash_alg).digest()
        return sig[:self._hash_size]

    def verify(self, data, sig):
        """Verify the signature of a message"""

        return self.sign(data) == sig


def register_mac_alg(alg, hash_alg, key_size, hash_size):
    """Register a MAC algorithm"""

    _mac_algs.append(alg)
    _mac_params[alg] = (key_size, hash_size, False)
    _mac_params[alg + _ETM] = (key_size, hash_size, True)
    _mac_handlers[alg] = (hash_alg, hash_size)
    _mac_handlers[alg + _ETM] = (hash_alg, hash_size)


def get_mac_algs():
    """Return a list of available MAC algorithms"""

    return [alg + _ETM for alg in _mac_algs] + _mac_algs


def get_mac_params(alg):
    """Get parameters of a MAC algorithm

       This function returns the key and hash sizes of a MAC algorithm and
       whether or not to compute the MAC before or after encryption.

    """

    return _mac_params[alg]


def get_mac(alg, key):
    """Return a MAC handler

       This function returns a MAC object initialized with the specified
       kev that can be used for data signing and verification.

    """

    hash_alg, hash_size = _mac_handlers[alg]
    return _MAC(hash_alg, hash_size, key)

# pylint: disable=bad-whitespace

register_mac_alg(b'hmac-sha2-256',    sha256, 32, 32)
register_mac_alg(b'hmac-sha2-512',    sha512, 64, 64)
register_mac_alg(b'hmac-sha1',        sha1,   20, 20)
register_mac_alg(b'hmac-md5',         md5,    16, 16)
register_mac_alg(b'hmac-sha2-256-96', sha256, 32, 12)
register_mac_alg(b'hmac-sha2-512-96', sha512, 64, 12)
register_mac_alg(b'hmac-sha1-96',     sha1,   20, 12)
register_mac_alg(b'hmac-md5-96',      md5,    16, 12)
