# Copyright (c) 2014-2020 by Ron Frederick <ronf@timeheart.net> and others.
#
# This program and the accompanying materials are made available under
# the terms of the Eclipse Public License v2.0 which accompanies this
# distribution and is available at:
#
#     http://www.eclipse.org/legal/epl-2.0/
#
# This program may also be made available under the following secondary
# licenses when the conditions for such availability set forth in the
# Eclipse Public License v2.0 are satisfied:
#
#    GNU General Public License, Version 2.0, or any later versions of
#    that license
#
# SPDX-License-Identifier: EPL-2.0 OR GPL-2.0-or-later
#
# Contributors:
#     Ron Frederick - initial implementation, API, and documentation

"""A shim around PyCA for RSA public and private keys"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.padding import MGF1, OAEP
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric import rsa

from .misc import PyCAKey, hashes


# Short variable names are used here, matching names in the spec
# pylint: disable=invalid-name


class _RSAKey(PyCAKey):
    """Base class for shim around PyCA for RSA keys"""

    def __init__(self, pyca_key, pub, priv=None):
        super().__init__(pyca_key)

        self._pub = pub
        self._priv = priv

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

    @classmethod
    def construct(cls, n, e, d, p, q, dmp1, dmq1, iqmp):
        """Construct an RSA private key"""

        pub = rsa.RSAPublicNumbers(e, n)
        priv = rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, pub)
        priv_key = priv.private_key(default_backend())

        return cls(priv_key, pub, priv)

    @classmethod
    def generate(cls, key_size, exponent):
        """Generate a new RSA private key"""

        priv_key = rsa.generate_private_key(exponent, key_size,
                                            default_backend())
        priv = priv_key.private_numbers()
        pub = priv.public_numbers

        return cls(priv_key, pub, priv)

    def decrypt(self, data, hash_alg):
        """Decrypt a block of data"""

        try:
            hash_alg = hashes[hash_alg]()
            priv_key = self.pyca_key
            return priv_key.decrypt(data, OAEP(MGF1(hash_alg), hash_alg, None))
        except ValueError:
            return None

    def sign(self, data, hash_alg):
        """Sign a block of data"""

        priv_key = self.pyca_key
        return priv_key.sign(data, PKCS1v15(), hashes[hash_alg]())


class RSAPublicKey(_RSAKey):
    """A shim around PyCA for RSA public keys"""

    @classmethod
    def construct(cls, n, e):
        """Construct an RSA public key"""

        pub = rsa.RSAPublicNumbers(e, n)
        pub_key = pub.public_key(default_backend())

        return cls(pub_key, pub)

    def encrypt(self, data, hash_alg):
        """Encrypt a block of data"""

        try:
            hash_alg = hashes[hash_alg]()
            pub_key = self.pyca_key
            return pub_key.encrypt(data, OAEP(MGF1(hash_alg), hash_alg, None))
        except ValueError:
            return None

    def verify(self, data, sig, hash_alg):
        """Verify the signature on a block of data"""

        try:
            pub_key = self.pyca_key
            pub_key.verify(sig, data, PKCS1v15(), hashes[hash_alg]())
            return True
        except InvalidSignature:
            return False
