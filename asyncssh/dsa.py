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

"""DSA public key encryption handler"""

from .asn1 import ASN1DecodeError, ObjectIdentifier, der_encode, der_decode
from .crypto import DSAPrivateKey, DSAPublicKey
from .misc import all_ints
from .packet import MPInt, String, PacketDecodeError, SSHPacket
from .public_key import SSHKey, SSHCertificateV01
from .public_key import KeyExportError
from .public_key import register_public_key_alg, register_certificate_alg

# Short variable names are used here, matching names in the spec
# pylint: disable=invalid-name


class _DSAKey(SSHKey):
    """Handler for DSA public key encryption"""

    algorithm = b'ssh-dss'
    pem_name = b'DSA'
    pkcs8_oid = ObjectIdentifier('1.2.840.10040.4.1')
    sig_algorithms = (b'ssh-dss',)

    def __init__(self, key):
        super().__init__()

        self._key = key

    def __eq__(self, other):
        # This isn't protected access - both objects are _DSAKey instances
        # pylint: disable=protected-access

        return (isinstance(other, type(self)) and
                self._key.p == other._key.p and
                self._key.q == other._key.q and
                self._key.g == other._key.g and
                self._key.y == other._key.y and
                self._key.x == other._key.x)

    def __hash__(self):
        return hash((self._key.p, self._key.q, self._key.g,
                     self._key.y, self._key.x))

    @classmethod
    def generate(cls, algorithm):
        """Generate a new DSA private key"""

        # pylint: disable=unused-argument

        return cls(DSAPrivateKey.generate(key_size=1024))

    @classmethod
    def make_private(cls, *args):
        """Construct a DSA private key"""

        return cls(DSAPrivateKey.construct(*args))

    @classmethod
    def make_public(cls, *args):
        """Construct a DSA public key"""

        return cls(DSAPublicKey.construct(*args))

    @classmethod
    def decode_pkcs1_private(cls, key_data):
        """Decode a PKCS#1 format DSA private key"""

        if (isinstance(key_data, tuple) and len(key_data) == 6 and
                all_ints(key_data) and key_data[0] == 0):
            return key_data[1:]
        else:
            return None

    @classmethod
    def decode_pkcs1_public(cls, key_data):
        """Decode a PKCS#1 format DSA public key"""

        if (isinstance(key_data, tuple) and len(key_data) == 4 and
                all_ints(key_data)):
            y, p, q, g = key_data
            return p, q, g, y
        else:
            return None

    @classmethod
    def decode_pkcs8_private(cls, alg_params, data):
        """Decode a PKCS#8 format DSA private key"""

        try:
            x = der_decode(data)
        except ASN1DecodeError:
            return None

        if (isinstance(alg_params, tuple) and len(alg_params) == 3 and
                all_ints(alg_params) and isinstance(x, int)):
            p, q, g = alg_params
            y = pow(g, x, p)
            return p, q, g, y, x
        else:
            return None

    @classmethod
    def decode_pkcs8_public(cls, alg_params, data):
        """Decode a PKCS#8 format DSA public key"""

        try:
            y = der_decode(data)
        except ASN1DecodeError:
            return None

        if (isinstance(alg_params, tuple) and len(alg_params) == 3 and
                all_ints(alg_params) and isinstance(y, int)):
            p, q, g = alg_params
            return p, q, g, y
        else:
            return None

    @classmethod
    def decode_ssh_private(cls, packet):
        """Decode an SSH format DSA private key"""

        p = packet.get_mpint()
        q = packet.get_mpint()
        g = packet.get_mpint()
        y = packet.get_mpint()
        x = packet.get_mpint()

        return p, q, g, y, x

    @classmethod
    def decode_ssh_public(cls, packet):
        """Decode an SSH format DSA public key"""

        p = packet.get_mpint()
        q = packet.get_mpint()
        g = packet.get_mpint()
        y = packet.get_mpint()

        return p, q, g, y

    def encode_pkcs1_private(self):
        """Encode a PKCS#1 format DSA private key"""

        if not self._key.x:
            raise KeyExportError('Key is not private')

        return (0, self._key.p, self._key.q, self._key.g,
                self._key.y, self._key.x)

    def encode_pkcs1_public(self):
        """Encode a PKCS#1 format DSA public key"""

        return (self._key.y, self._key.p, self._key.q, self._key.g)

    def encode_pkcs8_private(self):
        """Encode a PKCS#8 format DSA private key"""

        if not self._key.x:
            raise KeyExportError('Key is not private')

        return (self._key.p, self._key.q, self._key.g), der_encode(self._key.x)

    def encode_pkcs8_public(self):
        """Encode a PKCS#8 format DSA public key"""

        return (self._key.p, self._key.q, self._key.g), der_encode(self._key.y)

    def encode_ssh_private(self):
        """Encode an SSH format DSA private key"""

        if not self._key.x:
            raise KeyExportError('Key is not private')

        return b''.join((MPInt(self._key.p), MPInt(self._key.q),
                         MPInt(self._key.g), MPInt(self._key.y),
                         MPInt(self._key.x)))

    def encode_ssh_public(self):
        """Encode an SSH format DSA public key"""

        return b''.join((MPInt(self._key.p), MPInt(self._key.q),
                         MPInt(self._key.g), MPInt(self._key.y)))

    def encode_agent_cert_private(self):
        """Encode DSA certificate private key data for agent"""

        if not self._key.x:
            raise KeyExportError('Key is not private')

        return MPInt(self._key.x)

    def sign(self, data, algorithm):
        """Return a signature of the specified data using this key"""

        if not self._key.x:
            raise ValueError('Private key needed for signing')

        if algorithm not in self.sig_algorithms:
            raise ValueError('Unrecognized signature algorithm')

        r, s = self._key.sign(data)
        return b''.join((String(algorithm),
                         String(r.to_bytes(20, 'big') +
                                s.to_bytes(20, 'big'))))

    def verify(self, data, sig):
        """Verify a signature of the specified data using this key"""

        try:
            packet = SSHPacket(sig)

            if packet.get_string() not in self.sig_algorithms:
                return False

            sig = packet.get_string()
            packet.check_end()

            if len(sig) != 40:
                return False

            r = int.from_bytes(sig[:20], 'big')
            s = int.from_bytes(sig[20:], 'big')

            return self._key.verify(data, (r, s))
        except PacketDecodeError:
            return False


register_public_key_alg(b'ssh-dss', _DSAKey)

register_certificate_alg(1, b'ssh-dss', b'ssh-dss-cert-v01@openssh.com',
                         _DSAKey, SSHCertificateV01)
