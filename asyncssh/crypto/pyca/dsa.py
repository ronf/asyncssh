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

from asyncssh.asn1 import der_encode, der_decode

from cryptography.exceptions import InvalidSignature

from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.hashes import SHA1

from cryptography.hazmat.primitives.asymmetric.dsa import DSAParameterNumbers
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateNumbers

# Short variable names are used here, matching names in the spec
# pylint: disable=invalid-name


class DSAPrivateKey:
    """A shim around PyCA for DSA private keys"""

    def __init__(self, p, q, g, y, x):
        self.p = p
        self.q = q
        self.g = g
        self.y = y
        self.x = x

        params = DSAParameterNumbers(p, q, g)
        pub = DSAPublicNumbers(y, params)
        self._key = DSAPrivateNumbers(x, pub).private_key(default_backend())

    def sign(self, data):
        """Sign a block of data"""

        signer = self._key.signer(SHA1())
        signer.update(data)
        return der_decode(signer.finalize())


class DSAPublicKey:
    """A shim around PyCA for DSA public keys"""

    def __init__(self, p, q, g, y):
        self.p = p
        self.q = q
        self.g = g
        self.y = y

        params = DSAParameterNumbers(p, q, g)
        self._key = DSAPublicNumbers(y, params).public_key(default_backend())

    def verify(self, data, sig):
        """Verify the signature on a block of data"""

        verifier = self._key.verifier(der_encode(sig), SHA1())
        verifier.update(data)

        try:
            verifier.verify()
            return True
        except InvalidSignature:
            return False
