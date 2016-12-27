# Copyright (c) 2013-2016 by Ron Frederick <ronf@timeheart.net>.
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

from .packet import UInt32, UInt64

try:
    from .crypto import umac64, umac128
    _umac_available = True
except ImportError: # pragma: no cover
    _umac_available = False


_OPENSSH = b'@openssh.com'
_ETM = b'-etm' + _OPENSSH

_mac_algs = []
_mac_params = {}
_mac_handlers = {}


class _HMAC:
    """Parent class for HMAC-based SSH message authentication handlers"""

    def __init__(self, key, hash_size, hash_alg):
        self._key = key
        self._hash_size = hash_size
        self._hash_alg = hash_alg

    def sign(self, seq, packet):
        """Compute a signature for a message"""

        data = UInt32(seq) + packet
        sig = hmac.new(self._key, data, self._hash_alg).digest()
        return sig[:self._hash_size]

    def verify(self, seq, packet, sig):
        """Verify the signature of a message"""

        return self.sign(seq, packet) == sig


class _UMAC:
    """Parent class for UMAC-based SSH message authentication handlers"""

    def __init__(self, key, hash_size, umac_alg):
        # pylint: disable=unused-argument

        self._key = key
        self._umac_alg = umac_alg

    def sign(self, seq, packet):
        """Compute a signature for a message"""

        return self._umac_alg(self._key, packet, UInt64(seq)).digest()

    def verify(self, seq, packet, sig):
        """Verify the signature of a message"""

        return self.sign(seq, packet) == sig


def register_mac_alg(alg, key_size, hash_size, etm, mac_alg, *args):
    """Register a MAC algorithm"""

    _mac_algs.append(alg)
    _mac_params[alg] = (key_size, hash_size, etm)
    _mac_handlers[alg] = (mac_alg, hash_size, args)


def get_mac_algs():
    """Return a list of available MAC algorithms"""

    return _mac_algs


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

    mac_alg, hash_size, args = _mac_handlers[alg]
    return mac_alg(key, hash_size, *args)


# pylint: disable=bad-whitespace

if _umac_available: # pragma: no branch
    register_mac_alg(b'umac-64' + _ETM,      16,  8, True,  _UMAC, umac64)
    register_mac_alg(b'umac-128' + _ETM,     16, 16, True,  _UMAC, umac128)

register_mac_alg(b'hmac-sha2-256' + _ETM,    32, 32, True,  _HMAC, sha256)
register_mac_alg(b'hmac-sha2-512' + _ETM,    64, 64, True,  _HMAC, sha512)
register_mac_alg(b'hmac-sha1' + _ETM,        20, 20, True,  _HMAC, sha1)
register_mac_alg(b'hmac-md5' + _ETM,         16, 16, True,  _HMAC, md5)
register_mac_alg(b'hmac-sha2-256-96' + _ETM, 32, 12, True,  _HMAC, sha256)
register_mac_alg(b'hmac-sha2-512-96' + _ETM, 64, 12, True,  _HMAC, sha512)
register_mac_alg(b'hmac-sha1-96' + _ETM,     20, 12, True,  _HMAC, sha1)
register_mac_alg(b'hmac-md5-96' + _ETM,      16, 12, True,  _HMAC, md5)

if _umac_available: # pragma: no branch
    register_mac_alg(b'umac-64' + _OPENSSH,  16,  8, False, _UMAC, umac64)
    register_mac_alg(b'umac-128' + _OPENSSH, 16, 16, False, _UMAC, umac128)

register_mac_alg(b'hmac-sha2-256',           32, 32, False, _HMAC, sha256)
register_mac_alg(b'hmac-sha2-512',           64, 64, False, _HMAC, sha512)
register_mac_alg(b'hmac-sha1',               20, 20, False, _HMAC, sha1)
register_mac_alg(b'hmac-md5',                16, 16, False, _HMAC, md5)
register_mac_alg(b'hmac-sha2-256-96',        32, 12, False, _HMAC, sha256)
register_mac_alg(b'hmac-sha2-512-96',        64, 12, False, _HMAC, sha512)
register_mac_alg(b'hmac-sha1-96',            20, 12, False, _HMAC, sha1)
register_mac_alg(b'hmac-md5-96',             16, 12, False, _HMAC, md5)
