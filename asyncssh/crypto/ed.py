# Copyright (c) 2019 by Ron Frederick <ronf@timeheart.net> and others.
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

"""A shim around PyCA for Edwards-curve keys and key exchange"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives.asymmetric import ed25519, ed448
from cryptography.hazmat.primitives.asymmetric import x25519, x448
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import NoEncryption

from .misc import PyCAKey


ed25519_available = backend.ed25519_supported()
ed448_available = backend.ed448_supported()
curve25519_available = backend.x25519_supported()
curve448_available = backend.x448_supported()


class _EdKey(PyCAKey):
    """Base class for shim around PyCA for Ed25519/Ed448 keys"""

    def __init__(self, pyca_key, pub, priv=None):
        super().__init__(pyca_key)

        self._pub = pub
        self._priv = priv

    @property
    def public_value(self):
        """Return the public value encoded as a byte string"""

        return self._pub

    @property
    def private_value(self):
        """Return the private value encoded as a byte string"""

        return self._priv


class EdDSAPrivateKey(_EdKey):
    """A shim around PyCA for EdDSA private keys"""

    _priv_classes = {b'ed25519': ed25519.Ed25519PrivateKey,
                     b'ed448': ed448.Ed448PrivateKey}

    @classmethod
    def construct(cls, curve_id, priv):
        """Construct an EdDSA private key"""

        priv_cls = cls._priv_classes[curve_id]
        priv_key = priv_cls.from_private_bytes(priv)
        pub_key = priv_key.public_key()
        pub = pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

        return cls(priv_key, pub, priv)

    @classmethod
    def generate(cls, curve_id):
        """Generate a new ECDSA private key"""

        priv_cls = cls._priv_classes[curve_id]
        priv_key = priv_cls.generate()
        priv = priv_key.private_bytes(Encoding.Raw, PrivateFormat.Raw,
                                      NoEncryption())

        pub_key = priv_key.public_key()
        pub = pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

        return cls(priv_key, pub, priv)

    def sign(self, data):
        """Sign a block of data"""

        return self.pyca_key.sign(data)


class EdDSAPublicKey(_EdKey):
    """A shim around PyCA for EdDSA public keys"""

    _pub_classes = {b'ed25519': ed25519.Ed25519PublicKey,
                    b'ed448': ed448.Ed448PublicKey}

    @classmethod
    def construct(cls, curve_id, pub):
        """Construct an ECDSA public key"""

        pub_cls = cls._pub_classes[curve_id]
        pub_key = pub_cls.from_public_bytes(pub)

        return cls(pub_key, pub)

    def verify(self, data, sig):
        """Verify the signature on a block of data"""

        try:
            self.pyca_key.verify(sig, data)
            return True
        except InvalidSignature:
            return False


class Curve25519DH:
    """Curve25519 Diffie Hellman implementation"""

    def __init__(self):
        self._priv_key = x25519.X25519PrivateKey.generate()

    def get_public(self):
        """Return the public key to send in the handshake"""

        return self._priv_key.public_key().public_bytes(Encoding.Raw,
                                                        PublicFormat.Raw)

    def get_shared(self, peer_public):
        """Return the shared key from the peer's public key"""

        peer_key = x25519.X25519PublicKey.from_public_bytes(peer_public)
        shared = self._priv_key.exchange(peer_key)
        return int.from_bytes(shared, 'big')


class Curve448DH:
    """Curve448 Diffie Hellman implementation"""

    def __init__(self):
        self._priv_key = x448.X448PrivateKey.generate()

    def get_public(self):
        """Return the public key to send in the handshake"""

        return self._priv_key.public_key().public_bytes(Encoding.Raw,
                                                        PublicFormat.Raw)

    def get_shared(self, peer_public):
        """Return the shared key from the peer's public key"""

        peer_key = x448.X448PublicKey.from_public_bytes(peer_public)
        shared = self._priv_key.exchange(peer_key)
        return int.from_bytes(shared, 'big')
