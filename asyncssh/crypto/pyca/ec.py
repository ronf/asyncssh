# Copyright (c) 2015 by Ron Frederick <ronf@timeheart.net>.
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

"""A shim around PyCA for elliptic curve keys and key exchange"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512
from cryptography.hazmat.primitives.asymmetric import ec

from ...asn1 import der_encode, der_decode

# Short variable names are used here, matching names in the spec
# pylint: disable=invalid-name

_curves = {b'nistp256': (ec.SECP256R1, SHA256),
           b'nistp384': (ec.SECP384R1, SHA384),
           b'nistp521': (ec.SECP521R1, SHA512)}


class _ECKey:
    """Base class for shim around PyCA for EC keys"""

    def __init__(self, curve_id, pub, priv=None):
        self._curve_id = curve_id
        self._pub = pub
        self._priv = priv

    @classmethod
    def lookup_curve(cls, curve_id):
        """Look up curve and hash algorithm"""

        try:
            return _curves[curve_id]
        except KeyError: # pragma: no cover, other curves not registered
            raise ValueError('Unknown EC curve %s' %
                             curve_id.decode()) from None

    @property
    def curve_id(self):
        """Return the EC curve name"""

        return self._curve_id

    @property
    def x(self):
        """Return the EC public x coordinate"""

        return self._pub.x

    @property
    def y(self):
        """Return the EC public y coordinate"""

        return self._pub.y

    @property
    def d(self):
        """Return the EC private value as an integer"""

        return self._priv.private_value if self._priv else None

    @property
    def public_value(self):
        """Return the EC public point value encoded as a byte string"""

        return self._pub.encode_point()

    @property
    def private_value(self):
        """Return the EC private value encoded as a byte string"""

        if self._priv:
            keylen = (self._pub.curve.key_size + 7) // 8
            return self._priv.private_value.to_bytes(keylen, 'big')
        else:
            return None


class ECDSAPrivateKey(_ECKey):
    """A shim around PyCA for ECDSA private keys"""

    def __init__(self, curve_id, hash_alg, pub, priv, priv_key):
        super().__init__(curve_id, pub, priv)
        self._hash_alg = hash_alg
        self._priv_key = priv_key

    @classmethod
    def construct(cls, curve_id, public_value, private_value):
        """Construct an ECDSA private key"""

        curve, hash_alg = cls.lookup_curve(curve_id)
        pub = ec.EllipticCurvePublicNumbers.from_encoded_point(curve(),
                                                               public_value)
        priv = ec.EllipticCurvePrivateNumbers(private_value, pub)
        priv_key = priv.private_key(backend)

        return cls(curve_id, hash_alg, pub, priv, priv_key)

    @classmethod
    def generate(cls, curve_id):
        """Generate a new ECDSA private key"""

        curve, hash_alg = cls.lookup_curve(curve_id)
        priv_key = ec.generate_private_key(curve, backend)
        priv = priv_key.private_numbers()
        pub = priv.public_numbers

        return cls(curve_id, hash_alg, pub, priv, priv_key)

    def sign(self, data):
        """Sign a block of data"""

        return der_decode(self._priv_key.sign(data,
                                              ec.ECDSA(self._hash_alg())))


class ECDSAPublicKey(_ECKey):
    """A shim around PyCA for ECDSA public keys"""

    def __init__(self, curve_id, hash_alg, pub, pub_key):
        super().__init__(curve_id, pub)
        self._hash_alg = hash_alg
        self._pub_key = pub_key

    @classmethod
    def construct(cls, curve_id, public_value):
        """Construct an ECDSA public key"""

        curve, hash_alg = cls.lookup_curve(curve_id)
        pub = ec.EllipticCurvePublicNumbers.from_encoded_point(curve(),
                                                               public_value)
        pub_key = pub.public_key(backend)

        return cls(curve_id, hash_alg, pub, pub_key)

    def verify(self, data, sig):
        """Verify the signature on a block of data"""

        try:
            self._pub_key.verify(der_encode(sig), data,
                                 ec.ECDSA(self._hash_alg()))
            return True
        except InvalidSignature:
            return False


class ECDH:
    """A shim around PyCA for ECDH key exchange"""

    def __init__(self, curve_id):
        try:
            curve, _ = _curves[curve_id]
        except KeyError: # pragma: no cover, other curves not registered
            raise ValueError('Unknown EC curve %s' %
                             curve_id.decode()) from None

        self._priv_key = ec.generate_private_key(curve, backend)

    def get_public(self):
        """Return the public key to send in the handshake"""

        pub = self._priv_key.private_numbers().public_numbers
        return pub.encode_point()

    def get_shared(self, peer_public):
        """Return the shared key from the peer's public key"""

        peer_key = ec.EllipticCurvePublicNumbers.from_encoded_point(
            self._priv_key.curve, peer_public).public_key(backend)

        shared_key = self._priv_key.exchange(ec.ECDH(), peer_key)

        return int.from_bytes(shared_key, 'big')
