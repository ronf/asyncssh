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

"""DSA public key encryption handler"""

from .asn1 import *
from .crypto import *
from .logging import *
from .misc import *
from .packet import *
from .public_key import *


class _DSAKey(SSHKey):
    """Handler for DSA public key encryption"""

    algorithm = b'ssh-dss'
    pem_name = b'DSA'
    pkcs8_oid = ObjectIdentifier('1.2.840.10040.4.1')

    def __init__(self, key, private):
        self._key = key
        self._private = private

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self._key.p == other._key.p and
                self._key.q == other._key.q and
                self._key.g == other._key.g and
                self._key.y == other._key.y and
                ((self._private and self._key.x) ==
                 (other._private and other._key.x)))

    def __hash__(self):
        return hash((self._key.p, self._key.q, self._key.g, self._key.y,
                     self._key.x if hasattr(self, 'x') else None))

    @classmethod
    def make_private(cls, *args):
        return cls(DSAPrivateKey(*args), True)

    @classmethod
    def make_public(cls, *args):
        return cls(DSAPublicKey(*args), False)

    @classmethod
    def decode_pkcs1_private(cls, key_data):
        if (isinstance(key_data, tuple) and len(key_data) == 6 and
            all_ints(key_data) and key_data[0] == 0):
            return key_data[1:]
        else:
            return None

    @classmethod
    def decode_pkcs1_public(cls, key_data):
        if (isinstance(key_data, tuple) and len(key_data) == 4 and
            all_ints(key_data)):
            y, p, q, g = key_data
            return p, q, g, y
        else:
            return None

    @classmethod
    def decode_pkcs8_private(cls, alg_params, data):
        x = der_decode(data)

        if len(alg_params) == 3 and all_ints(alg_params) and isinstance(x, int):
            p, q, g = alg_params
            y = pow(g, x, p)
            return p, q, g, y, x
        else:
            return None

    @classmethod
    def decode_pkcs8_public(cls, alg_params, data):
        y = der_decode(data)

        if len(alg_params) == 3 and all_ints(alg_params) and isinstance(y, int):
            p, q, g = alg_params
            return p, q, g, y
        else:
            return None

    @classmethod
    def decode_ssh_private(cls, packet):
        p = packet.get_mpint()
        q = packet.get_mpint()
        g = packet.get_mpint()
        y = packet.get_mpint()
        x = packet.get_mpint()

        return p, q, g, y, x

    @classmethod
    def decode_ssh_public(cls, packet):
        p = packet.get_mpint()
        q = packet.get_mpint()
        g = packet.get_mpint()
        y = packet.get_mpint()

        return p, q, g, y

    def encode_pkcs1_private(self):
        if not self._private:
            raise KeyExportError('Key is not private')

        return (0, self._key.p, self._key.q, self._key.g,
                self._key.y, self._key.x)

    def encode_pkcs1_public(self):
        return (self._key.y, self._key.p, self._key.q, self._key.g)

    def encode_pkcs8_private(self):
        if not self._private:
            raise KeyExportError('Key is not private')

        return (self._key.p, self._key.q, self._key.g), der_encode(self._key.x)

    def encode_pkcs8_public(self):
        return (self._key.p, self._key.q, self._key.g), der_encode(self._key.y)

    def encode_ssh_private(self):
        if not self._private:
            raise KeyExportError('Key is not private')

        return b''.join((String(self.algorithm), MPInt(self._key.p),
                         MPInt(self._key.q), MPInt(self._key.g),
                         MPInt(self._key.y), MPInt(self._key.x)))

    def encode_ssh_public(self):
        return b''.join((String(self.algorithm), MPInt(self._key.p),
                         MPInt(self._key.q), MPInt(self._key.g),
                         MPInt(self._key.y)))

    def sign(self, data):
        if not self._private:
            raise ValueError('Private key needed for signing')

        r, s = self._key.sign(data)
        return b''.join((String(self.algorithm), String(r.to_bytes(20, 'big') +
                                                        s.to_bytes(20, 'big'))))

    def verify(self, data, sig):
        sig = SSHPacket(sig)

        if sig.get_string() != self.algorithm:
            return False

        sig = sig.get_string()
        return self._key.verify(data, (int.from_bytes(sig[:20], 'big'),
                                       int.from_bytes(sig[20:], 'big')))


register_public_key_alg(b'ssh-dss', _DSAKey)

register_certificate_alg(b'ssh-dss-cert-v01@openssh.com',
                         _DSAKey, SSHCertificateV01)
register_certificate_alg(b'ssh-dss-cert-v00@openssh.com',
                         _DSAKey, SSHCertificateV00)
