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

from ...asn1 import der_encode, der_decode
from ..ec import decode_ec_point, encode_ec_point

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512
from cryptography.hazmat.primitives.asymmetric import ec

# Short variable names are used here, matching names in the spec
# pylint: disable=invalid-name

_curves = {b'nistp256': (ec.SECP256R1, SHA256),
           b'nistp384': (ec.SECP384R1, SHA384),
           b'nistp521': (ec.SECP521R1, SHA512)}


class _ECKey:
    """Base class for shim around PyCA for EC keys"""

    def __init__(self, curve_id, public_value=None, private_value=None):
        try:
            curve, hash_alg = _curves[curve_id]
        except KeyError: # pragma: no cover, other curves not registered
            raise ValueError('Unknown EC curve %s' %
                             curve_id.decode()) from None

        self._curve_id = curve_id
        self._keylen = (curve.key_size + 7) // 8
        self._hash_alg = hash_alg

        x, y = decode_ec_point(self._keylen, public_value)
        self._pub = ec.EllipticCurvePublicNumbers(x, y, curve())

        if private_value:
            self._priv = ec.EllipticCurvePrivateNumbers(private_value,
                                                        self._pub)
            self._priv_key = self._priv.private_key(backend)
        else:
            self._priv = None
            self._pub_key = self._pub.public_key(backend)

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

        return encode_ec_point(self._keylen, self.x, self.y)

    @property
    def private_value(self):
        """Return the EC private value encoded as a byte string"""

        return self.d.to_bytes(self._keylen, 'big') if self.d else None


class ECDSAPrivateKey(_ECKey):
    """A shim around PyCA for ECDSA private keys"""

    def sign(self, data):
        """Sign a block of data"""

        signer = self._priv_key.signer(ec.ECDSA(self._hash_alg()))
        signer.update(data)
        return der_decode(signer.finalize())


class ECDSAPublicKey(_ECKey):
    """A shim around PyCA for ECDSA public keys"""

    def verify(self, data, sig):
        """Verify the signature on a block of data"""

        verifier = self._pub_key.verifier(der_encode(sig),
                                          ec.ECDSA(self._hash_alg()))
        verifier.update(data)

        try:
            verifier.verify()
            return True
        except InvalidSignature:
            return False
