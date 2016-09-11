# Copyright (c) 2014-2015 by Ron Frederick <ronf@timeheart.net>.
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

"""A shim around PyCA for RSA public and private keys"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA1, SHA256, SHA512
from cryptography.hazmat.primitives.asymmetric import rsa

# Short variable names are used here, matching names in the spec
# pylint: disable=invalid-name


class _RSAKey:
    """Base class for shum around PyCA for RSA keys"""

    def __init__(self, pub, priv=None):
        self._pub = pub
        self._priv = priv

    @staticmethod
    def get_hash(algorithm):
        """Return hash algorithm to use for signature"""

        if algorithm == b'rsa-sha2-512':
            return SHA512()
        elif algorithm == b'rsa-sha2-256':
            return SHA256()
        else:
            return SHA1()

    @property
    def n(self):
        """Return the RSA public modulus"""

        return self._pub.n

    @property
    def e(self):
        """Return the RSA public exponent"""

        return self._pub.e

    @property
    def d(self):
        """Return the RSA private exponent"""

        return self._priv.d if self._priv else None

    @property
    def p(self):
        """Return the RSA first private prime"""

        return self._priv.p if self._priv else None

    @property
    def q(self):
        """Return the RSA second private prime"""

        return self._priv.q if self._priv else None

    @property
    def dmp1(self):
        """Return d modulo p-1"""

        return self._priv.dmp1 if self._priv else None

    @property
    def dmq1(self):
        """Return q modulo p-1"""

        return self._priv.dmq1 if self._priv else None

    @property
    def iqmp(self):
        """Return the inverse of q modulo p"""

        return self._priv.iqmp if self._priv else None


class RSAPrivateKey(_RSAKey):
    """A shim around PyCA for RSA private keys"""

    def __init__(self, pub, priv, priv_key):
        super().__init__(pub, priv)
        self._priv_key = priv_key

    @classmethod
    def construct(cls, n, e, d, p, q, dmp1, dmq1, iqmp):
        """Construct an RSA private key"""

        pub = rsa.RSAPublicNumbers(e, n)
        priv = rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, pub)
        priv_key = priv.private_key(default_backend())

        return cls(pub, priv, priv_key)

    @classmethod
    def generate(cls, key_size, exponent):
        """Generate a new RSA private key"""

        priv_key = rsa.generate_private_key(exponent, key_size,
                                            default_backend())
        priv = priv_key.private_numbers()
        pub = priv.public_numbers

        return cls(pub, priv, priv_key)

    def sign(self, data, algorithm):
        """Sign a block of data"""

        return self._priv_key.sign(data, PKCS1v15(), self.get_hash(algorithm))


class RSAPublicKey(_RSAKey):
    """A shim around PyCA for RSA public keys"""

    def __init__(self, pub, pub_key):
        super().__init__(pub)
        self._pub_key = pub_key

    @classmethod
    def construct(cls, n, e):
        """Construct an RSA public key"""

        pub = rsa.RSAPublicNumbers(e, n)
        pub_key = pub.public_key(default_backend())

        return cls(pub, pub_key)

    def verify(self, data, sig, algorithm):
        """Verify the signature on a block of data"""

        try:
            self._pub_key.verify(sig, data, PKCS1v15(),
                                 self.get_hash(algorithm))
            return True
        except InvalidSignature:
            return False
