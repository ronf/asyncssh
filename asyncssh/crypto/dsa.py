# Copyright (c) 2014-2018 by Ron Frederick <ronf@timeheart.net>.
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

from .misc import PyCAKey


# Short variable names are used here, matching names in the spec
# pylint: disable=invalid-name


class _DSAKey(PyCAKey):
    """Base class for shim around PyCA for DSA keys"""

    def __init__(self, pyca_key, params, pub, priv=None):
        super().__init__(pyca_key)

        self._params = params
        self._pub = pub
        self._priv = priv

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

    @classmethod
    def construct(cls, p, q, g, y, x):
        """Construct a DSA private key"""

        params = dsa.DSAParameterNumbers(p, q, g)
        pub = dsa.DSAPublicNumbers(y, params)
        priv = dsa.DSAPrivateNumbers(x, pub)
        priv_key = priv.private_key(default_backend())

        return cls(priv_key, params, pub, priv)

    @classmethod
    def generate(cls, key_size):
        """Generate a new DSA private key"""

        priv_key = dsa.generate_private_key(key_size, default_backend())
        priv = priv_key.private_numbers()
        pub = priv.public_numbers
        params = pub.parameter_numbers

        return cls(priv_key, params, pub, priv)

    def sign(self, data):
        """Sign a block of data"""

        priv_key = self.pyca_key
        return priv_key.sign(data, SHA1())


class DSAPublicKey(_DSAKey):
    """A shim around PyCA for DSA public keys"""

    @classmethod
    def construct(cls, p, q, g, y):
        """Construct a DSA public key"""

        params = dsa.DSAParameterNumbers(p, q, g)
        pub = dsa.DSAPublicNumbers(y, params)
        pub_key = pub.public_key(default_backend())

        return cls(pub_key, params, pub)

    def verify(self, data, sig):
        """Verify the signature on a block of data"""

        try:
            pub_key = self.pyca_key
            pub_key.verify(sig, data, SHA1())
            return True
        except InvalidSignature:
            return False
