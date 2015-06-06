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

"""EC public key encryption handler"""

from hashlib import sha256, sha384, sha512

from .asn1 import ASN1DecodeError, BitString, ObjectIdentifier, TaggedDERObject
from .asn1 import der_encode, der_decode

from .constants import DISC_KEY_EXCHANGE_FAILED, DISC_PROTOCOL_ERROR

from .kex import Kex, register_kex_alg

from .misc import DisconnectError, mod_inverse, randrange

from .packet import Byte, MPInt, String, SSHPacket

from .public_key import SSHKey, SSHCertificateV01
from .public_key import KeyImportError, KeyExportError
from .public_key import register_public_key_alg, register_certificate_alg

_domain_map = {}
_domain_oid_map = {}
_domain_param_map = {}

# OID for EC prime fields
PRIME_FIELD = ObjectIdentifier('1.2.840.10045.1.1')

# pylint: disable=bad-whitespace

# SSH KEX ECDH message values
MSG_KEX_ECDH_INIT  = 30
MSG_KEX_ECDH_REPLY = 31

# pylint: enable=bad-whitespace

# Short variable names are used here, matching names in the spec
# pylint: disable=invalid-name


class _PrimeCurve:
    """An elliptic curve over a prime finite field F(p)"""

    def __init__(self, p, a, b):
        self.p = p
        self.a = a
        self.b = b
        self.keylen = (p.bit_length() + 7) // 8

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self.p == other.p and
                self.a % self.p == other.a % other.p and
                self.b % self.p == other.b % other.p)

    def __hash__(self):
        return hash((self.p, self.a % self.p, self.b % self.p))


class _PrimePoint:
    """A point on an elliptic curve over a prime finite field F(p)"""

    def __init__(self, curve, x, y):
        self.curve = curve
        self.x = x
        self.y = y

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self.curve == other.curve and
                self.x == other.x and self.y == other.y)

    def __hash__(self):
        return hash((self.curve, self.x, self.y))

    def __bool__(self):
        return self.curve is not None

    def __neg__(self):
        """Negate an elliptic curve point"""

        if self.y:
            return _PrimePoint(self.curve, self.x, self.curve.p - self.y)
        else:
            return self

    def __add__(self, other):
        """Add two elliptic curve points"""

        if self.curve is None:
            return other
        elif other.curve is None:
            return self
        elif self.curve != other.curve:
            raise ValueError('Can\'t add points from different curves')

        p = self.curve.p

        if self.x == other.x:
            if (self.y + other.y) % p == 0:
                return _INFINITY
            else:
                l = ((3 * self.x * self.x + self.curve.a) *
                     mod_inverse(2 * self.y, p)) % p
        else:
            l = ((other.y - self.y) * mod_inverse(other.x - self.x, p)) % p

        x = (l * l - self.x - other.x) % p
        y = (l * (self.x - x) - self.y) % p
        return _PrimePoint(self.curve, x, y)

    def __sub__(self, other):
        """Subtract one elliptic curve point from another"""

        return self + (-other)

    def __rmul__(self, k):
        """Multiply an elliptic curve point by a scalar value"""

        result = _INFINITY
        P = self

        while k:
            if k & 1:
                if k & 2:
                    result -= P
                    while k & 2:
                        k >>= 1
                        P += P
                    k |= 2
                else:
                    result += P

            k >>= 1
            P += P

        return result

    @classmethod
    def construct(cls, curve, x, y):
        """Construct an elliptic curve point from a curve and x, y values"""

        if (0 <= x < curve.p and 0 <= y < curve.p and
                (y*y - (x*x*x + curve.a*x + curve.b)) % curve.p == 0):
            return cls(curve, x, y)
        else:
            raise ValueError('Point not on curve')

    @classmethod
    def decode(cls, curve, data):
        """Decode an octet string into an elliptic curve point"""

        if data == b'\x00':
            return _INFINITY
        elif data.startswith(b'\x04'):
            keylen = curve.keylen
            if len(data) == 2*keylen + 1:
                return cls.construct(curve,
                                     int.from_bytes(data[1:keylen+1], 'big'),
                                     int.from_bytes(data[keylen+1:], 'big'))
            else:
                raise ValueError('Invalid point data length')
        else:
            raise ValueError('Unsupported point type')

    def encode(self):
        """Encode an elliptic curve point as an octet string"""

        if self.curve is None:
            return b'\x00'
        else:
            keylen = self.curve.keylen
            return (b'\x04' + self.x.to_bytes(keylen, 'big') +
                    self.y.to_bytes(keylen, 'big'))


# Define the point "infinity" which exists on all elliptic curves
_INFINITY = _PrimePoint(None, None, None)


class _KexECDH(Kex):
    """Handler for elliptic curve Diffie-Hellman key exchange"""

    def __init__(self, alg, conn, hash_alg, G, n):
        super().__init__(alg, conn, hash_alg)

        while True:
            self._d = randrange(2, n)
            self._Q = self._d * G

            if self._Q:
                break

        if conn.is_client():
            self._Qc = self._Q.encode()
            self._conn.send_packet(Byte(MSG_KEX_ECDH_INIT), String(self._Qc))
        else:
            self._Qs = self._Q.encode()

    def _compute_hash(self, host_key_data, k):
        """Compute a hash of key information associated with the connection"""

        hash_obj = self._hash_alg()
        hash_obj.update(self._conn.get_hash_prefix())
        hash_obj.update(String(host_key_data))
        hash_obj.update(String(self._Qc))
        hash_obj.update(String(self._Qs))
        hash_obj.update(MPInt(k))
        return hash_obj.digest()

    def _process_init(self, pkttype, packet):
        """Process an ECDH init message"""

        # pylint: disable=unused-argument

        if self._conn.is_client():
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Unexpected kex init msg')

        self._Qc = packet.get_string()
        packet.check_end()

        try:
            P = self._d * _PrimePoint.decode(self._Q.curve, self._Qc)
            if not P:
                raise DisconnectError(DISC_PROTOCOL_ERROR,
                                      'Invalid kex init msg')
        except ValueError:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Invalid kex init msg') from None

        host_key, host_key_data = self._conn.get_server_host_key()

        k = P.x
        h = self._compute_hash(host_key_data, k)
        sig = host_key.sign(h)

        self._conn.send_packet(Byte(MSG_KEX_ECDH_REPLY), String(host_key_data),
                               String(self._Qs), String(sig))

        self._conn.send_newkeys(k, h)

    def _process_reply(self, pkttype, packet):
        """Process an ECDH reply message"""

        # pylint: disable=unused-argument

        if self._conn.is_server():
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Unexpected kex reply msg')

        host_key_data = packet.get_string()
        self._Qs = packet.get_string()
        sig = packet.get_string()
        packet.check_end()

        host_key = self._conn.validate_server_host_key(host_key_data)

        try:
            P = self._d * _PrimePoint.decode(self._Q.curve, self._Qs)
            if not P:
                raise DisconnectError(DISC_PROTOCOL_ERROR,
                                      'Invalid kex reply msg')
        except ValueError:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Invalid kex reply msg') from None

        k = P.x
        h = self._compute_hash(host_key_data, k)
        if not host_key.verify(h, sig):
            raise DisconnectError(DISC_KEY_EXCHANGE_FAILED,
                                  'Key exchange hash mismatch')

        self._conn.send_newkeys(k, h)

    packet_handlers = {
        MSG_KEX_ECDH_INIT:  _process_init,
        MSG_KEX_ECDH_REPLY: _process_reply
    }


class _ECKey(SSHKey):
    """Handler for elliptic curve public key encryption"""

    pem_name = b'EC'
    pkcs8_oid = ObjectIdentifier('1.2.840.10045.2.1')

    def __init__(self, domain, private_key, public_key):
        algorithm, alg_id, alg_oid, hash_alg, G, n = domain

        d = None
        Q = None

        if private_key:
            if isinstance(private_key, bytes):
                d = int.from_bytes(private_key, 'big')
            else:
                d = private_key

            if not 0 < d < n:
                raise KeyImportError('Invalid private key')

        if public_key:
            try:
                Q = _PrimePoint.decode(G.curve, public_key)

                if not Q or n * Q:
                    raise KeyImportError('Invalid public key')
            except ValueError:
                raise KeyImportError('Invalid public key') from None

        if d:
            if Q:
                if d * G != Q:
                    raise KeyImportError('Public and private key don\'t match')
            else:
                Q = d * G
        elif not Q:
            raise KeyImportError('No keys specified')

        self.algorithm = algorithm
        self._alg_id = alg_id
        self._alg_oid = alg_oid
        self._hash_alg = hash_alg
        self._G = G
        self._n = n
        self._d = d
        self._Q = Q

    def __eq__(self, other):
        # This isn't protected access - both objects are _ECKey instances
        # pylint: disable=protected-access

        return (isinstance(other, self.__class__) and
                self._d == other._d and self._Q == other._Q)

    def __hash__(self):
        return hash(self._Q)

    @classmethod
    def _lookup_domain(cls, alg_params):
        """Look up an EC domain matching the specified algorithm parameters"""

        if isinstance(alg_params, ObjectIdentifier):
            domain = _domain_oid_map.get(alg_params)
            if not domain:
                raise KeyImportError('Unknown EC curve OID: %s' % alg_params)
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

            G = _PrimePoint.decode(_PrimeCurve(p, a, b), alg_params[3])
            n = alg_params[4]

            domain = _domain_map[b'nistp256']
            domain = _domain_param_map.get((G, n))
            if not domain:
                raise KeyImportError('Unknown EC curve parameters')
        else:
            raise KeyImportError('Invalid EC curve parameters')

        return domain

    @classmethod
    def make_private(cls, domain, private_key, public_key):
        """Construct an EC private key"""

        return cls(domain, private_key, public_key)

    @classmethod
    def make_public(cls, domain, public_key):
        """Construct an EC public key"""

        return cls(domain, None, public_key)

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

            domain = cls._lookup_domain(alg_params)

            return domain, private_key, public_key
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

            if (isinstance(key_data[2], TaggedDERObject) and
                    key_data[2].tag == 1 and
                    isinstance(key_data[2].value, BitString) and
                    key_data[2].value.unused == 0):
                public_key = key_data[2].value.value
            else:
                public_key = None

            domain = cls._lookup_domain(alg_params)

            return domain, private_key, public_key
        else:
            return None

    @classmethod
    def decode_pkcs8_public(cls, alg_params, key_data):
        """Decode a PKCS#8 format EC public key"""

        if isinstance(alg_params, ObjectIdentifier):
            domain = _domain_oid_map.get(alg_params)
            if not domain:
                raise KeyImportError('Unknown curve OID: %s' % alg_params)

            return domain, key_data
        else:
            return None

    @classmethod
    def decode_ssh_private(cls, packet):
        """Decode an SSH format EC private key"""

        curve_id = packet.get_string()
        public_key = packet.get_string()
        private_key = packet.get_mpint()

        domain = _domain_map.get(curve_id)
        if not domain:
            raise KeyImportError('Unknown curve name: %s' %
                                 curve_id.decode('ascii'))

        return domain, private_key, public_key

    @classmethod
    def decode_ssh_public(cls, packet):
        """Decode an SSH format EC public key"""

        curve_id = packet.get_string()
        public_key = packet.get_string()

        domain = _domain_map.get(curve_id)
        if not domain:
            raise KeyImportError('Unknown curve name: %s' %
                                 curve_id.decode('ascii'))

        return domain, public_key

    def encode_private(self):
        """Encode an EC private key blob"""

        return self._d.to_bytes((self._n.bit_length() + 7) // 8, 'big')

    def encode_public(self):
        """Encode an EC public key blob"""

        return TaggedDERObject(1, BitString(self._Q.encode()))

    def encode_pkcs1_private(self):
        """Encode a PKCS#1 format EC private key"""

        if not self._d:
            raise KeyExportError('Key is not private')

        return (1, self.encode_private(), TaggedDERObject(0, self._alg_oid),
                self.encode_public())

    def encode_pkcs1_public(self):
        """Encode a PKCS#1 format EC public key"""

        raise KeyExportError('PKCS#1 is not supported for EC public keys')

    def encode_pkcs8_private(self):
        """Encode a PKCS#8 format EC private key"""

        if not self._d:
            raise KeyExportError('Key is not private')

        return self._alg_oid, der_encode((1, self.encode_private(),
                                          self.encode_public()))

    def encode_pkcs8_public(self):
        """Encode a PKCS#8 format EC public key"""

        return self._alg_oid, self._Q.encode()

    def encode_ssh_private(self):
        """Encode an SSH format EC private key"""

        if not self._d:
            raise KeyExportError('Key is not private')

        return b''.join((String(self.algorithm), String(self._alg_id),
                         String(self._Q.encode()), MPInt(self._d)))

    def encode_ssh_public(self):
        """Encode an SSH format EC public key"""

        return b''.join((String(self.algorithm), String(self._alg_id),
                         String(self._Q.encode())))

    def sign(self, data):
        """Return a signature of the specified data using this key"""

        if not self._d:
            raise ValueError('Private key needed for signing')

        while True:
            n = self._n
            k = randrange(2, n)
            e = int.from_bytes(self._hash_alg(data).digest(), 'big')

            try:
                r = (k * self._G).x % n
                if not r:
                    continue

                s = (mod_inverse(k, n) * ((e + r*self._d) % n)) % n
                if s:
                    break
            except ValueError:
                # If k has no inverse, try again with a different k
                pass

        sig = MPInt(r) + MPInt(s)
        return b''.join((String(self.algorithm), String(sig)))

    def verify(self, data, sig):
        """Verify a signature of the specified data using this key"""

        sig = SSHPacket(sig)

        if sig.get_string() != self.algorithm:
            return False

        sig = SSHPacket(sig.get_string())
        r = sig.get_mpint()
        s = sig.get_mpint()

        n = self._n
        e = int.from_bytes(self._hash_alg(data).digest(), 'big')

        try:
            s1 = mod_inverse(s, n)
            u1 = (e * s1) % n
            u2 = (r * s1) % n

            return (u1 * self._G + u2 * self._Q).x == r
        except ValueError:
            return False


def register_prime_domain(curve_id, oid, hash_alg, p, a, b, Gx, Gy, n):
    """Register an elliptic curve prime domain

       This function registers an elliptic curve prime domain by
       specifying the SSH identifier for the curve, the OID used to
       identify the curve in PKCS#1 and PKCS#8 private and public keys,
       the hash algorithm used to hash messages, and the set of domain
       parameters describing the curve, generator point, and order.

    """

    oid = ObjectIdentifier(oid)

    if p % 2 == 0 or (4*a*a*a + 27*b*b) % p == 0:
        raise ValueError('Invalid curve parameters')

    G = _PrimePoint.construct(_PrimeCurve(p, a, b), Gx, Gy)

    if n * G:
        raise ValueError('Invalid order for curve %s' %
                         curve_id.decode('ascii'))

    pb = p % n
    for b in range(100):
        if pb == 1:
            raise ValueError('Invalid prime for curve %s' %
                             curve_id.decode('ascii'))

        pb = (pb * p) % n

    algorithm = b'ecdsa-sha2-' + curve_id
    domain = (algorithm, curve_id, oid, hash_alg, G, n)
    _domain_map[curve_id] = domain
    _domain_oid_map[oid] = domain
    _domain_param_map[(G, n)] = domain

    register_public_key_alg(algorithm, _ECKey)

    register_certificate_alg(algorithm + b'-cert-v01@openssh.com',
                             _ECKey, SSHCertificateV01)

    register_kex_alg(b'ecdh-sha2-' + curve_id, _KexECDH, hash_alg, G, n)

# pylint: disable=line-too-long

register_prime_domain(b'nistp521', '1.3.132.0.35', sha512,
                      6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151,
                      -3,
                      0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00,
                      0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
                      0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650,
                      6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449)

register_prime_domain(b'nistp384', '1.3.132.0.34', sha384,
                      39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319,
                      -3,
                      0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
                      0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
                      0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f,
                      39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643)

register_prime_domain(b'nistp256', '1.2.840.10045.3.1.7', sha256,
                      115792089210356248762697446949407573530086143415290314195533631308867097853951,
                      -3,
                      0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
                      0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
                      0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
                      115792089210356248762697446949407573529996955224135760342422259061068512044369)
