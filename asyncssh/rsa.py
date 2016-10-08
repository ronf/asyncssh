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

"""RSA public key encryption handler"""

from .asn1 import ASN1DecodeError, ObjectIdentifier, der_encode, der_decode
from .crypto import RSAPrivateKey, RSAPublicKey
from .misc import all_ints
from .packet import MPInt, String, PacketDecodeError, SSHPacket
from .public_key import SSHKey, SSHCertificateV01
from .public_key import KeyExportError
from .public_key import register_public_key_alg, register_certificate_alg

# Short variable names are used here, matching names in the spec
# pylint: disable=invalid-name


class _RSAKey(SSHKey):
    """Handler for RSA public key encryption"""

    algorithm = b'ssh-rsa'
    pem_name = b'RSA'
    pkcs8_oid = ObjectIdentifier('1.2.840.113549.1.1.1')
    sig_algorithms = (b'rsa-sha2-256', b'rsa-sha2-512', b'ssh-rsa')

    def __init__(self, key):
        super().__init__()

        self._key = key

    def __eq__(self, other):
        # This isn't protected access - both objects are _RSAKey instances
        # pylint: disable=protected-access

        return (isinstance(other, type(self)) and
                self._key.n == other._key.n and
                self._key.e == other._key.e and
                self._key.d == other._key.d)

    def __hash__(self):
        return hash((self._key.n, self._key.e, self._key.d,
                     self._key.p, self._key.q))

    @classmethod
    def generate(cls, algorithm, *, key_size=2048, exponent=65537):
        """Generate a new RSA private key"""

        # pylint: disable=unused-argument

        return cls(RSAPrivateKey.generate(key_size, exponent))

    @classmethod
    def make_private(cls, *args):
        """Construct an RSA private key"""

        return cls(RSAPrivateKey.construct(*args))

    @classmethod
    def make_public(cls, *args):
        """Construct an RSA public key"""

        return cls(RSAPublicKey.construct(*args))

    @classmethod
    def decode_pkcs1_private(cls, key_data):
        """Decode a PKCS#1 format RSA private key"""

        if (isinstance(key_data, tuple) and all_ints(key_data) and
                len(key_data) >= 9):
            return key_data[1:9]
        else:
            return None

    @classmethod
    def decode_pkcs1_public(cls, key_data):
        """Decode a PKCS#1 format RSA public key"""

        if (isinstance(key_data, tuple) and all_ints(key_data) and
                len(key_data) == 2):
            return key_data
        else:
            return None

    @classmethod
    def decode_pkcs8_private(cls, alg_params, data):
        """Decode a PKCS#8 format RSA private key"""

        if alg_params is not None:
            return None

        try:
            key_data = der_decode(data)
        except ASN1DecodeError:
            return None

        return cls.decode_pkcs1_private(key_data)

    @classmethod
    def decode_pkcs8_public(cls, alg_params, data):
        """Decode a PKCS#8 format RSA public key"""

        if alg_params is not None:
            return None

        try:
            key_data = der_decode(data)
        except ASN1DecodeError:
            return None

        return cls.decode_pkcs1_public(key_data)

    @classmethod
    def decode_ssh_private(cls, packet):
        """Decode an SSH format RSA private key"""

        n = packet.get_mpint()
        e = packet.get_mpint()
        d = packet.get_mpint()
        iqmp = packet.get_mpint()
        p = packet.get_mpint()
        q = packet.get_mpint()

        return n, e, d, p, q, d % (p-1), d % (q-1), iqmp

    @classmethod
    def decode_ssh_public(cls, packet):
        """Decode an SSH format RSA public key"""

        e = packet.get_mpint()
        n = packet.get_mpint()

        return n, e

    def encode_pkcs1_private(self):
        """Encode a PKCS#1 format RSA private key"""

        if not self._key.d:
            raise KeyExportError('Key is not private')

        return (0, self._key.n, self._key.e, self._key.d, self._key.p,
                self._key.q, self._key.dmp1, self._key.dmq1, self._key.iqmp)

    def encode_pkcs1_public(self):
        """Encode a PKCS#1 format RSA public key"""

        return self._key.n, self._key.e

    def encode_pkcs8_private(self):
        """Encode a PKCS#8 format RSA private key"""

        return None, der_encode(self.encode_pkcs1_private())

    def encode_pkcs8_public(self):
        """Encode a PKCS#8 format RSA public key"""

        return None, der_encode(self.encode_pkcs1_public())

    def encode_ssh_private(self):
        """Encode an SSH format RSA private key"""

        if not self._key.d:
            raise KeyExportError('Key is not private')

        return b''.join((MPInt(self._key.n), MPInt(self._key.e),
                         MPInt(self._key.d), MPInt(self._key.iqmp),
                         MPInt(self._key.p), MPInt(self._key.q)))

    def encode_ssh_public(self):
        """Encode an SSH format RSA public key"""

        return b''.join((MPInt(self._key.e), MPInt(self._key.n)))

    def encode_agent_cert_private(self):
        """Encode RSA certificate private key data for agent"""

        if not self._key.d:
            raise KeyExportError('Key is not private')

        return b''.join((MPInt(self._key.d), MPInt(self._key.iqmp),
                         MPInt(self._key.p), MPInt(self._key.q)))

    def sign(self, data, algorithm):
        """Return a signature of the specified data using this key"""

        if not self._key.d:
            raise ValueError('Private key needed for signing')

        if algorithm not in self.sig_algorithms:
            raise ValueError('Unrecognized signature algorithm')

        sig = self._key.sign(data, algorithm)
        return b''.join((String(algorithm), String(sig)))

    def verify(self, data, sig):
        """Verify a signature of the specified data using this key"""

        try:
            packet = SSHPacket(sig)

            algorithm = packet.get_string()

            if algorithm not in self.sig_algorithms:
                return False

            sig = packet.get_string()
            packet.check_end()

            return self._key.verify(data, sig, algorithm)
        except PacketDecodeError:
            return False


register_public_key_alg(b'ssh-rsa', _RSAKey)

register_certificate_alg(1, b'ssh-rsa', b'ssh-rsa-cert-v01@openssh.com',
                         _RSAKey, SSHCertificateV01)
