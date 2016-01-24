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

"""A shim around PyCA for DSA public and private keys"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.asymmetric import dsa

from ...asn1 import der_encode, der_decode

# Short variable names are used here, matching names in the spec
# pylint: disable=invalid-name


class _DSAKey:
    """Base class for shim around PyCA for DSA keys"""

    def __init__(self, p, q, g, y, x=None):
        self._params = dsa.DSAParameterNumbers(p, q, g)
        self._pub = dsa.DSAPublicNumbers(y, self._params)

        if x:
            self._priv = dsa.DSAPrivateNumbers(x, self._pub)
            self._priv_key = self._priv.private_key(default_backend())
        else:
            self._priv = None
            self._pub_key = self._pub.public_key(default_backend())

    @property
    def p(self):
        """Return the DSA public modulus"""

        return self._params.p

    @property
    def q(self):
        """Return the DSA sub-group order"""

        return self._params.q

    @property
    def g(self):
        """Return the DSA generator"""

        return self._params.g

    @property
    def y(self):
        """Return the DSA public value"""

        return self._pub.y

    @property
    def x(self):
        """Return the DSA private value"""

        return self._priv.x if self._priv else None


class DSAPrivateKey(_DSAKey):
    """A shim around PyCA for DSA private keys"""

    def sign(self, data):
        """Sign a block of data"""

        signer = self._priv_key.signer(SHA1())
        signer.update(data)
        return der_decode(signer.finalize())


class DSAPublicKey(_DSAKey):
    """A shim around PyCA for DSA public keys"""

    def verify(self, data, sig):
        """Verify the signature on a block of data"""

        verifier = self._pub_key.verifier(der_encode(sig), SHA1())
        verifier.update(data)

        try:
            verifier.verify()
            return True
        except InvalidSignature:
            return False
