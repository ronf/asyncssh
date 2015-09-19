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

"""Elliptic curve public key encryption primitives"""

from ..misc import mod_inverse

_curve_params = {}
_curve_param_map = {}

# Short variable names are used here, matching names in the spec
# pylint: disable=invalid-name


class PrimeCurve:
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


class PrimePoint:
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
            return PrimePoint(self.curve, self.x, self.curve.p - self.y)
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
        return PrimePoint(self.curve, x, y)

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

        if x is None and y is None:
            return _INFINITY
        elif (0 <= x < curve.p and 0 <= y < curve.p and
              (y*y - (x*x*x + curve.a*x + curve.b)) % curve.p == 0):
            return cls(curve, x, y)
        else:
            raise ValueError('Point not on curve')

    @classmethod
    def decode(cls, curve, data):
        """Decode an octet string into an elliptic curve point"""

        return cls.construct(curve, *decode_ec_point(curve.keylen, data))

    def encode(self):
        """Encode an elliptic curve point as an octet string"""

        return encode_ec_point(self.curve.keylen, self.x, self.y)


# Define the point "infinity" which exists on all elliptic curves
_INFINITY = PrimePoint(None, None, None)


def register_prime_curve(curve_id, p, a, b, Gx, Gy, n):
    """Register an elliptic curve prime domain

       This function registers an elliptic curve prime domain by
       specifying the SSH identifier for the curve, the OID used to
       identify the curve in PKCS#1 and PKCS#8 private and public keys,
       and the set of parameters describing the curve, generator point,
       and order.

    """

    if p % 2 == 0 or (4*a*a*a + 27*b*b) % p == 0:
        raise ValueError('Invalid curve parameters')

    G = PrimePoint.construct(PrimeCurve(p, a, b), Gx, Gy)

    if n * G:
        raise ValueError('Invalid order for curve %s' % curve_id.decode())

    pb = p % n
    for b in range(100):
        if pb == 1:
            raise ValueError('Invalid prime for curve %s' % curve_id.decode())

        pb = (pb * p) % n

    _curve_params[curve_id] = (G, n)
    _curve_param_map[G, n] = curve_id


def decode_ec_point(keylen, data):
    """Decode an octet string into an elliptic curve point"""

    if data == b'\x00':
        return None, None
    elif data.startswith(b'\x04'):
        if len(data) == 2*keylen + 1:
            return (int.from_bytes(data[1:keylen+1], 'big'),
                    int.from_bytes(data[keylen+1:], 'big'))
        else:
            raise ValueError('Invalid elliptic curve point data length')
    else:
        raise ValueError('Unsupported elliptic curve point type')


def encode_ec_point(keylen, x, y):
    """Encode an elliptic curve point as an octet string"""

    if x is None:
        return b'\x00'
    else:
        return b'\x04' + x.to_bytes(keylen, 'big') + y.to_bytes(keylen, 'big')


def get_ec_curve_params(curve_id):
    """Return the parameters for a named elliptic curve

       This function looks up an elliptic curve by name and returns the
       curve's generator point and order.

    """

    try:
        return _curve_params[curve_id]
    except KeyError:
        raise ValueError('Unknown EC curve %s' % curve_id.decode())


def lookup_ec_curve_by_params(p, a, b, point, n):
    """Look up an elliptic curve by its parameters

       This function looks up an elliptic curve by its parameters
       and returns the curve's name.

    """

    try:
        G = PrimePoint.decode(PrimeCurve(p, a, b), point)
        return _curve_param_map[G, n]
    except (KeyError, ValueError):
        raise ValueError('Unknown elliptic curve parameters')


# pylint: disable=line-too-long

register_prime_curve(b'nistp521',
                     6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151,
                     -3,
                     0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00,
                     0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
                     0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650,
                     6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449)

register_prime_curve(b'nistp384',
                     39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319,
                     -3,
                     0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
                     0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
                     0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f,
                     39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643)

register_prime_curve(b'nistp256',
                     115792089210356248762697446949407573530086143415290314195533631308867097853951,
                     -3,
                     0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
                     0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
                     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
                     115792089210356248762697446949407573529996955224135760342422259061068512044369)
