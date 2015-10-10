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
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.asymmetric import rsa

# Short variable names are used here, matching names in the spec
# pylint: disable=invalid-name


class _RSAKey:
    """Base class for shum around PyCA for RSA keys"""

    def __init__(self, n, e, d=None, p=None, q=None,
                 dmp1=None, dmq1=None, iqmp=None):
        self._pub = rsa.RSAPublicNumbers(e, n)

        if d:
            self._priv = rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1,
                                               iqmp, self._pub)
            self._priv_key = self._priv.private_key(default_backend())
        else:
            self._priv = None
            self._pub_key = self._pub.public_key(default_backend())

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

    def sign(self, data):
        """Sign a block of data"""

        signer = self._priv_key.signer(PKCS1v15(), SHA1())
        signer.update(data)
        return signer.finalize()


class RSAPublicKey(_RSAKey):
    """A shim around PyCA for RSA public keys"""

    def verify(self, data, sig):
        """Verify the signature on a block of data"""

        verifier = self._pub_key.verifier(sig, PKCS1v15(), SHA1())
        verifier.update(data)

        try:
            verifier.verify()
            return True
        except InvalidSignature:
            return False
