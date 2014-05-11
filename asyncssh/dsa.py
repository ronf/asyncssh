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

"""DSA public key encryption handler based on PyCrypto"""

import random

from Crypto.Hash import SHA
from Crypto.PublicKey import DSA

from .asn1 import *
from .misc import *
from .packet import *
from .public_key import *


class _DSAKey(SSHKey):
    """Handler for DSA public key encryption"""

    algorithm = b'ssh-dss'
    pem_name = b'DSA'
    pkcs8_oid = ObjectIdentifier('1.2.840.10040.4.1')

    def __init__(self, key):
        self._key = key

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self._key == other._key

    def __hash__(self):
        return hash((self._key.p, self._key.q, self._key.g, self._key.y,
                     self._key.x if hasattr(self, 'x') else None))

    @classmethod
    def decode_pkcs1_private(cls, key_data):
        if (isinstance(key_data, tuple) and len(key_data) == 6 and
            all_ints(key_data) and key_data[0] == 0):
            _, p, q, g, y, x = key_data
            return cls(DSA.construct((y, g, p, q, x)))
        else:
            raise KeyImportError('Invalid DSA private key')

    @classmethod
    def decode_pkcs1_public(cls, key_data):
        if (isinstance(key_data, tuple) and len(key_data) == 5 and
            all_ints(key_data) and key_data[0] == 0):
            _, p, q, g, y = key_data
            return cls(DSA.construct((y, g, p, q)))
        else:
            raise KeyImportError('Invalid DSA public key')

    @classmethod
    def decode_pkcs8_private(cls, alg_params, data):
        try:
            x = der_decode(data)
        except ASN1DecodeError:
            x = None

        if len(alg_params) == 3 and all_ints(alg_params) and isinstance(x, int):
            p, q, g = alg_params
            y = pow(g, x, p)
            return cls(DSA.construct((y, g, p, q, x)))
        else:
            raise KeyImportError('Invalid DSA private key')

    @classmethod
    def decode_pkcs8_public(cls, alg_params, data):
        try:
            y = der_decode(data)
        except ASN1DecodeError:
            y = None

        if len(alg_params) == 3 and all_ints(alg_params) and isinstance(y, int):
            p, q, g = alg_params
            return cls(DSA.construct((y, g, p, q)))
        else:
            raise KeyImportError('Invalid DSA public key')

    @classmethod
    def decode_ssh_public(cls, packet):
        try:
            p = packet.get_mpint()
            q = packet.get_mpint()
            g = packet.get_mpint()
            y = packet.get_mpint()
            packet.check_end()

            return cls(DSA.construct((y, g, p, q)))
        except DisconnectError:
            # Fall through and return a key import error
            pass

        raise KeyImportError('Invalid DSA public key')

    def encode_pkcs1_private(self):
        if not self._key.has_private():
            raise KeyExportError('Key is not private')

        return (0, self._key.p, self._key.q, self._key.g,
                self._key.y, self._key.x)

    def encode_pkcs1_public(self):
        return (0, self._key.p, self._key.q, self._key.g, self._key.y)

    def encode_pkcs8_private(self):
        if not self._key.has_private():
            raise KeyExportError('Key is not private')

        return (self._key.p, self._key.q, self._key.g), der_encode(self._key.x)

    def encode_pkcs8_public(self):
        return (self._key.p, self._key.q, self._key.g), der_encode(self._key.y)

    def encode_ssh_public(self):
        return b''.join((String(self.algorithm), MPInt(self._key.p),
                         MPInt(self._key.q), MPInt(self._key.g),
                         MPInt(self._key.y)))

    def sign(self, data):
        if not self._key.has_private():
            raise ValueError('Private key needed for signing')

        k = random.randrange(2, self._key.q)
        r, s = self._key.sign(SHA.new(data).digest(), k)
        sig = r.to_bytes(20, 'big') + s.to_bytes(20, 'big')
        return b''.join((String(self.algorithm), String(sig)))

    def verify(self, data, sig):
        sig = SSHPacket(sig)

        if sig.get_string() != self.algorithm:
            return False

        sig = sig.get_string()
        return self._key.verify(SHA.new(data).digest(),
                                (int.from_bytes(sig[:20], 'big'),
                                 int.from_bytes(sig[20:], 'big')))


register_public_key_alg(_DSAKey)
