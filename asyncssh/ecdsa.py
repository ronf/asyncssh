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

"""ECDSA public key encryption handler"""

from .asn1 import ASN1DecodeError, BitString, ObjectIdentifier, TaggedDERObject
from .asn1 import der_encode, der_decode
from .crypto import lookup_ec_curve_by_params
from .crypto import ECDSAPrivateKey, ECDSAPublicKey
from .packet import MPInt, String, SSHPacket, PacketDecodeError
from .public_key import SSHKey, SSHCertificateV01
from .public_key import KeyImportError, KeyExportError
from .public_key import register_public_key_alg, register_certificate_alg

# OID for EC prime fields
PRIME_FIELD = ObjectIdentifier('1.2.840.10045.1.1')

# Short variable names are used here, matching names in the spec
# pylint: disable=invalid-name

_alg_oids = {}
_alg_oid_map = {}


class _ECKey(SSHKey):
    """Handler for elliptic curve public key encryption"""

    pem_name = b'EC'
    pkcs8_oid = ObjectIdentifier('1.2.840.10045.2.1')

    def __init__(self, key):
        super().__init__()

        self.algorithm = b'ecdsa-sha2-' + key.curve_id
        self.sig_algorithms = (self.algorithm,)
        self._alg_oid = _alg_oids[key.curve_id]
        self._key = key

    def __eq__(self, other):
        # This isn't protected access - both objects are _ECKey instances
        # pylint: disable=protected-access

        return (isinstance(other, type(self)) and
                self._key.curve_id == other._key.curve_id and
                self._key.x == other._key.x and
                self._key.y == other._key.y and
                self._key.d == other._key.d)

    def __hash__(self):
        return hash((self._key.curve_id, self._key.x,
                     self._key.y, self._key.d))

    @classmethod
    def _lookup_curve(cls, alg_params):
        """Look up an EC curve matching the specified parameters"""

        if isinstance(alg_params, ObjectIdentifier):
            try:
                curve_id = _alg_oid_map[alg_params]
            except KeyError:
                raise KeyImportError('Unknown elliptic curve OID %s',
                                     alg_params) from None
        elif (isinstance(alg_params, tuple) and len(alg_params) >= 5 and
              alg_params[0] == 1 and isinstance(alg_params[1], tuple) and
              len(alg_params[1]) == 2 and alg_params[1][0] == PRIME_FIELD and
              isinstance(alg_params[2], tuple) and len(alg_params[2]) >= 2 and
              isinstance(alg_params[3], bytes) and
              isinstance(alg_params[2][0], bytes) and
              isinstance(alg_params[2][1], bytes) and
              isinstance(alg_params[4], int)):
            p = alg_params[1][1]
            a = int.from_bytes(alg_params[2][0], 'big')
            b = int.from_bytes(alg_params[2][1], 'big')
            point = alg_params[3]
            n = alg_params[4]

            try:
                curve_id = lookup_ec_curve_by_params(p, a, b, point, n)
            except ValueError as exc:
                raise KeyImportError(str(exc)) from None
        else:
            raise KeyImportError('Invalid EC curve parameters')

        return curve_id

    @classmethod
    def generate(cls, algorithm):
        """Generate a new EC private key"""

        # Strip 'ecdsa-sha2-' prefix of algorithm to get curve_id
        return cls(ECDSAPrivateKey.generate(algorithm[11:]))

    @classmethod
    def make_private(cls, curve_id, private_key, public_key):
        """Construct an EC private key"""

        if isinstance(private_key, bytes):
            private_key = int.from_bytes(private_key, 'big')

        return cls(ECDSAPrivateKey.construct(curve_id, public_key,
                                             private_key))

    @classmethod
    def make_public(cls, curve_id, public_key):
        """Construct an EC public key"""

        return cls(ECDSAPublicKey.construct(curve_id, public_key))

    @classmethod
    def decode_pkcs1_private(cls, key_data):
        """Decode a PKCS#1 format EC private key"""

        if (isinstance(key_data, tuple) and len(key_data) > 2 and
                key_data[0] == 1 and isinstance(key_data[1], bytes) and
                isinstance(key_data[2], TaggedDERObject) and
                key_data[2].tag == 0):
            alg_params = key_data[2].value
            private_key = key_data[1]

            if (len(key_data) > 3 and
                    isinstance(key_data[3], TaggedDERObject) and
                    key_data[3].tag == 1 and
                    isinstance(key_data[3].value, BitString) and
                    key_data[3].value.unused == 0):
                public_key = key_data[3].value.value
            else:
                public_key = None

            return cls._lookup_curve(alg_params), private_key, public_key
        else:
            return None

    @classmethod
    def decode_pkcs1_public(cls, key_data):
        """Decode a PKCS#1 format EC public key"""

        # pylint: disable=unused-argument
        raise KeyImportError('PKCS#1 not supported for EC public keys')

    @classmethod
    def decode_pkcs8_private(cls, alg_params, data):
        """Decode a PKCS#8 format EC private key"""

        try:
            key_data = der_decode(data)
        except ASN1DecodeError:
            key_data = None

        if (isinstance(key_data, tuple) and len(key_data) > 1 and
                key_data[0] == 1 and isinstance(key_data[1], bytes)):
            private_key = key_data[1]

            if (len(key_data) > 2 and
                    isinstance(key_data[2], TaggedDERObject) and
                    key_data[2].tag == 1 and
                    isinstance(key_data[2].value, BitString) and
                    key_data[2].value.unused == 0):
                public_key = key_data[2].value.value
            else:
                public_key = None

            return cls._lookup_curve(alg_params), private_key, public_key
        else:
            return None

    @classmethod
    def decode_pkcs8_public(cls, alg_params, key_data):
        """Decode a PKCS#8 format EC public key"""

        if isinstance(alg_params, ObjectIdentifier):
            return cls._lookup_curve(alg_params), key_data
        else:
            return None

    @classmethod
    def decode_ssh_private(cls, packet):
        """Decode an SSH format EC private key"""

        curve_id = packet.get_string()
        public_key = packet.get_string()
        private_key = packet.get_mpint()

        return curve_id, private_key, public_key

    @classmethod
    def decode_ssh_public(cls, packet):
        """Decode an SSH format EC public key"""

        curve_id = packet.get_string()
        public_key = packet.get_string()

        return curve_id, public_key

    def encode_public_tagged(self):
        """Encode an EC public key blob as a tagged bitstring"""

        return TaggedDERObject(1, BitString(self._key.public_value))

    def encode_pkcs1_private(self):
        """Encode a PKCS#1 format EC private key"""

        if not self._key.private_value:
            raise KeyExportError('Key is not private')

        return (1, self._key.private_value,
                TaggedDERObject(0, self._alg_oid),
                self.encode_public_tagged())

    def encode_pkcs1_public(self):
        """Encode a PKCS#1 format EC public key"""

        raise KeyExportError('PKCS#1 is not supported for EC public keys')

    def encode_pkcs8_private(self):
        """Encode a PKCS#8 format EC private key"""

        if not self._key.private_value:
            raise KeyExportError('Key is not private')

        return self._alg_oid, der_encode((1, self._key.private_value,
                                          self.encode_public_tagged()))

    def encode_pkcs8_public(self):
        """Encode a PKCS#8 format EC public key"""

        return self._alg_oid, self._key.public_value

    def encode_ssh_private(self):
        """Encode an SSH format EC private key"""

        if not self._key.d:
            raise KeyExportError('Key is not private')

        return b''.join((String(self._key.curve_id),
                         String(self._key.public_value),
                         MPInt(self._key.d)))

    def encode_ssh_public(self):
        """Encode an SSH format EC public key"""

        return b''.join((String(self._key.curve_id),
                         String(self._key.public_value)))

    def encode_agent_cert_private(self):
        """Encode ECDSA certificate private key data for agent"""

        if not self._key.d:
            raise KeyExportError('Key is not private')

        return MPInt(self._key.d)

    def sign(self, data, algorithm):
        """Return a signature of the specified data using this key"""

        if not self._key.private_value:
            raise ValueError('Private key needed for signing')

        if algorithm not in self.sig_algorithms:
            raise ValueError('Unrecognized signature algorithm')

        r, s = self._key.sign(data)
        return b''.join((String(algorithm), String(MPInt(r) + MPInt(s))))

    def verify(self, data, sig):
        """Verify a signature of the specified data using this key"""

        try:
            packet = SSHPacket(sig)

            if packet.get_string() not in self.sig_algorithms:
                return False

            sig = packet.get_string()
            packet.check_end()

            packet = SSHPacket(sig)
            r = packet.get_mpint()
            s = packet.get_mpint()
            packet.check_end()

            return self._key.verify(data, (r, s))
        except PacketDecodeError:
            return False


for _curve_id, _oid in ((b'nistp521', '1.3.132.0.35'),
                        (b'nistp384', '1.3.132.0.34'),
                        (b'nistp256', '1.2.840.10045.3.1.7')):
    _algorithm = b'ecdsa-sha2-' + _curve_id
    _cert_algorithm = _algorithm + b'-cert-v01@openssh.com'

    _oid = ObjectIdentifier(_oid)
    _alg_oids[_curve_id] = _oid
    _alg_oid_map[_oid] = _curve_id

    register_public_key_alg(_algorithm, _ECKey, (_algorithm,))
    register_certificate_alg(1, _algorithm, _cert_algorithm,
                             _ECKey, SSHCertificateV01)
