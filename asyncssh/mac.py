# Copyright (c) 2013-2018 by Ron Frederick <ronf@timeheart.net>.
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
_mac_handler = {}
_mac_params = {}


class MAC:
    """Parent class for SSH message authentication handlers"""

    def __init__(self, key, hash_size):
        self._key = key
        self._hash_size = hash_size

    def sign(self, seq, packet):
        """Compute a signature for a message"""

        raise NotImplementedError

    def verify(self, seq, packet, sig):
        """Verify the signature of a message"""

        raise NotImplementedError


class _NullMAC(MAC):
    """Null message authentication handler"""

    def sign(self, seq, packet):
        """Compute a signature for a message"""

        return b''

    def verify(self, seq, packet, sig):
        """Verify the signature of a message"""

        return sig == b''


class _HMAC(MAC):
    """HMAC-based message authentication handler"""

    def __init__(self, key, hash_size, hash_alg):
        super().__init__(key, hash_size)
        self._hash_alg = hash_alg

    def sign(self, seq, packet):
        """Compute a signature for a message"""

        data = UInt32(seq) + packet
        sig = hmac.new(self._key, data, self._hash_alg).digest()
        return sig[:self._hash_size]

    def verify(self, seq, packet, sig):
        """Verify the signature of a message"""

        return self.sign(seq, packet) == sig


class _UMAC(MAC):
    """UMAC-based message authentication handler"""

    def __init__(self, key, hash_size, umac_alg):
        super().__init__(key, hash_size)
        self._umac_alg = umac_alg

    def sign(self, seq, packet):
        """Compute a signature for a message"""

        return self._umac_alg(self._key, packet, UInt64(seq)).digest()

    def verify(self, seq, packet, sig):
        """Verify the signature of a message"""

        return self.sign(seq, packet) == sig


def register_mac_alg(mac_alg, key_size, hash_size, etm, handler, args):
    """Register a MAC algorithm"""

    if mac_alg:
        _mac_algs.append(mac_alg)

    _mac_handler[mac_alg] = (handler, hash_size, args)
    _mac_params[mac_alg] = (key_size, hash_size, etm)


def get_mac_algs():
    """Return a list of available MAC algorithms"""

    return _mac_algs


def get_mac_params(mac_alg):
    """Get parameters of a MAC algorithm

       This function returns the key and hash sizes of a MAC algorithm and
       whether or not to compute the MAC before or after encryption.

    """

    return _mac_params[mac_alg]


def get_mac(mac_alg, key):
    """Return a MAC handler

       This function returns a MAC object initialized with the specified
       key that can be used for data signing and verification.

    """

    handler, hash_size, args = _mac_handler[mac_alg]
    return handler(key, hash_size, *args)


# pylint: disable=bad-whitespace

_mac_algs_list = (
    (b'',                         0,  0, False, _NullMAC, ()),
)

if _umac_available: # pragma: no branch
    _mac_algs_list += (
        (b'umac-64' + _ETM,      16,  8, True,  _UMAC,    (umac64,)),
        (b'umac-128' + _ETM,     16, 16, True,  _UMAC,    (umac128,)))

_mac_algs_list += (
    (b'hmac-sha2-256' + _ETM,    32, 32, True,  _HMAC,    (sha256,)),
    (b'hmac-sha2-512' + _ETM,    64, 64, True,  _HMAC,    (sha512,)),
    (b'hmac-sha1' + _ETM,        20, 20, True,  _HMAC,    (sha1,)),
    (b'hmac-md5' + _ETM,         16, 16, True,  _HMAC,    (md5,)),
    (b'hmac-sha2-256-96' + _ETM, 32, 12, True,  _HMAC,    (sha256,)),
    (b'hmac-sha2-512-96' + _ETM, 64, 12, True,  _HMAC,    (sha512,)),
    (b'hmac-sha1-96' + _ETM,     20, 12, True,  _HMAC,    (sha1,)),
    (b'hmac-md5-96' + _ETM,      16, 12, True,  _HMAC,    (md5,)))

if _umac_available: # pragma: no branch
    _mac_algs_list += (
        (b'umac-64' + _OPENSSH,  16,  8, False, _UMAC,    (umac64,)),
        (b'umac-128' + _OPENSSH, 16, 16, False, _UMAC,    (umac128,)))

_mac_algs_list += (
    (b'hmac-sha2-256',           32, 32, False, _HMAC,    (sha256,)),
    (b'hmac-sha2-512',           64, 64, False, _HMAC,    (sha512,)),
    (b'hmac-sha1',               20, 20, False, _HMAC,    (sha1,)),
    (b'hmac-md5',                16, 16, False, _HMAC,    (md5,)),
    (b'hmac-sha2-256-96',        32, 12, False, _HMAC,    (sha256,)),
    (b'hmac-sha2-512-96',        64, 12, False, _HMAC,    (sha512,)),
    (b'hmac-sha1-96',            20, 12, False, _HMAC,    (sha1,)),
    (b'hmac-md5-96',             16, 12, False, _HMAC,    (md5,)))

for _alg, _key_size, _hash_size, _etm, _mac_alg, _args in _mac_algs_list:
    register_mac_alg(_alg, _key_size, _hash_size, _etm, _mac_alg, _args)
