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

"""RSA public key encryption handler"""

from .asn1 import *
from .crypto import *
from .logging import *
from .misc import *
from .packet import *
from .public_key import *


class _RSAKey(SSHKey):
    """Handler for RSA public key encryption"""

    algorithm = b'ssh-rsa'
    pem_name = b'RSA'
    pkcs8_oid = ObjectIdentifier('1.2.840.113549.1.1.1')

    def __init__(self, key, private):
        self._key = key
        self._private = private

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self._key.n == other._key.n and
                self._key.e == other._key.e and
                ((self._private and self._key.d) ==
                 (other._private and other._key.d)))

    def __hash__(self):
        return hash((self._key.n, self._key.e,
                     self._key.d if hasattr(self, 'd') else None,
                     self._key.p if hasattr(self, 'p') else None,
                     self._key.q if hasattr(self, 'q') else None))

    @classmethod
    def make_private(cls, *args):
        return cls(RSAPrivateKey(*args), True)

    @classmethod
    def make_public(cls, *args):
        return cls(RSAPublicKey(*args), False)

    @classmethod
    def decode_pkcs1_private(cls, key_data):
        if (isinstance(key_data, tuple) and all_ints(key_data) and
            len(key_data) >= 9):
            return key_data[1:6]
        else:
            return None

    @classmethod
    def decode_pkcs1_public(cls, key_data):
        if (isinstance(key_data, tuple) and all_ints(key_data) and
            len(key_data) == 2):
            return key_data
        else:
            return None

    @classmethod
    def decode_pkcs8_private(cls, alg_params, data):
        if alg_params is None:
            return cls.decode_pkcs1_private(der_decode(data))
        else:
            return None

    @classmethod
    def decode_pkcs8_public(cls, alg_params, data):
        if alg_params is None:
            return cls.decode_pkcs1_public(der_decode(data))
        else:
            return None

    @classmethod
    def decode_ssh_private(cls, packet):
        n = packet.get_mpint()
        e = packet.get_mpint()
        d = packet.get_mpint()
        iqmp = packet.get_mpint()
        p = packet.get_mpint()
        q = packet.get_mpint()

        return n, e, d, p, q

    @classmethod
    def decode_ssh_public(cls, packet):
        e = packet.get_mpint()
        n = packet.get_mpint()

        return n, e

    def encode_pkcs1_private(self):
        if not self._private:
            raise KeyExportError('Key is not private')

        return (0, self._key.n, self._key.e, self._key.d,
                self._key.p, self._key.q,
                self._key.d % (self._key.p - 1),
                self._key.d % (self._key.q - 1),
                mod_inverse(self._key.q, self._key.p))

    def encode_pkcs1_public(self):
        return self._key.n, self._key.e

    def encode_pkcs8_private(self):
        return None, der_encode(self.encode_pkcs1_private())

    def encode_pkcs8_public(self):
        return None, der_encode(self.encode_pkcs1_public())

    def encode_ssh_private(self):
        if not self._private:
            raise KeyExportError('Key is not private')

        return b''.join((String(self.algorithm), MPInt(self._key.n),
                         MPInt(self._key.e), MPInt(self._key.d),
                         MPInt(mod_inverse(self._key.q, self._key.p)),
                         MPInt(self._key.p), MPInt(self._key.q)))

    def encode_ssh_public(self):
        return b''.join((String(self.algorithm), MPInt(self._key.e),
                         MPInt(self._key.n)))

    def sign(self, data):
        if not self._private:
            raise ValueError('Private key needed for signing')

        sig = self._key.sign(data)
        return b''.join((String(self.algorithm), String(sig)))

    def verify(self, data, sig):
        sig = SSHPacket(sig)

        if sig.get_string() != self.algorithm:
            return False

        sig = sig.get_string()
        return self._key.verify(data, sig)


register_public_key_alg(b'ssh-rsa', _RSAKey)

register_certificate_alg(b'ssh-rsa-cert-v01@openssh.com',
                         _RSAKey, SSHCertificateV01)
register_certificate_alg(b'ssh-rsa-cert-v00@openssh.com',
                         _RSAKey, SSHCertificateV00)
