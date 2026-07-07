# Copyright (c) 2026 by Ron Frederick <ronf@timeheart.net> and others.
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

"""A shim around PyCA for ML-DSA public and private keys"""

from typing import Dict, Optional, Union, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives.asymmetric import mldsa

from .misc import CryptoKey, PyCAKey


_MLDSAPrivateKey = Union[mldsa.MLDSA44PrivateKey,
                         mldsa.MLDSA65PrivateKey,
                         mldsa.MLDSA87PrivateKey]

_MLDSAPublicKey = Union[mldsa.MLDSA44PublicKey,
                        mldsa.MLDSA65PublicKey,
                        mldsa.MLDSA87PublicKey]


mldsa_available = backend.mldsa_supported()


class _MLDSAKey(CryptoKey):
    """Base class for shim around PyCA for MLDSA keys"""

    def __init__(self, pyca_key: PyCAKey, pub: bytes,
                 priv: Optional[bytes] = None):
        super().__init__(pyca_key)

        self._pub = pub
        self._priv = priv

    @property
    def public_value(self) -> bytes:
        """Return the public value encoded as a byte string"""

        return self._pub

    @property
    def private_value(self) -> Optional[bytes]:
        """Return the private value encoded as a byte string"""

        return self._priv


class MLDSAPrivateKey(_MLDSAKey):
    """A shim around PyCA for MLDSA private keys"""

    _priv_classes: Dict[bytes, object] = {}

    if mldsa_available: # pragma: no branch
        _priv_classes = {
            b'mldsa-44': mldsa.MLDSA44PrivateKey,
            b'mldsa-65': mldsa.MLDSA65PrivateKey,
            b'mldsa-87': mldsa.MLDSA87PrivateKey
        }

    @classmethod
    def construct(cls, dimension: bytes, priv: bytes) -> 'MLDSAPrivateKey':
        """Construct an MLDSA private key"""

        priv_cls = cast('_MLDSAPrivateKey', cls._priv_classes[dimension])
        priv_key = priv_cls.from_seed_bytes(priv)
        pub_key = priv_key.public_key()
        pub = pub_key.public_bytes_raw()

        return cls(priv_key, pub, priv)

    @classmethod
    def generate(cls, dimension: bytes) -> 'MLDSAPrivateKey':
        """Generate a new MLDSA private key"""

        priv_cls = cast('_MLDSAPrivateKey', cls._priv_classes[dimension])
        priv_key = priv_cls.generate()
        priv = priv_key.private_bytes_raw()

        pub_key = priv_key.public_key()
        pub = pub_key.public_bytes_raw()

        return cls(priv_key, pub, priv)

    def sign(self, data: bytes, hash_name: str = '') -> bytes:
        """Sign a block of data"""

        # pylint: disable=unused-argument

        priv_key = cast('_MLDSAPrivateKey', self.pyca_key)
        return priv_key.sign(data)


class MLDSAPublicKey(_MLDSAKey):
    """A shim around PyCA for MLDSA public keys"""

    _pub_classes: Dict[bytes, object] = {
        b'mldsa-44': mldsa.MLDSA44PublicKey,
        b'mldsa-65': mldsa.MLDSA65PublicKey,
        b'mldsa-87': mldsa.MLDSA87PublicKey
    }

    @classmethod
    def construct(cls, dimension: bytes, pub: bytes) -> 'MLDSAPublicKey':
        """Construct an MLDSA public key"""

        pub_cls = cast('_MLDSAPublicKey', cls._pub_classes[dimension])
        pub_key = pub_cls.from_public_bytes(pub)

        return cls(pub_key, pub)

    def verify(self, data: bytes, sig: bytes, hash_name: str = '') -> bool:
        """Verify the signature on a block of data"""

        # pylint: disable=unused-argument

        try:
            pub_key = cast('_MLDSAPublicKey', self.pyca_key)
            pub_key.verify(sig, data)
            return True
        except InvalidSignature:
            return False
