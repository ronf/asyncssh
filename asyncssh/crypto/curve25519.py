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

"""Curve25519 key exchange handler primitives"""

import ctypes
import os

try:
    from libnacl import nacl

    _CURVE25519_BYTES = nacl.crypto_scalarmult_curve25519_bytes()
    _CURVE25519_SCALARBYTES = nacl.crypto_scalarmult_curve25519_scalarbytes()

    _curve25519 = nacl.crypto_scalarmult_curve25519
    _curve25519_base = nacl.crypto_scalarmult_curve25519_base
except (ImportError, OSError, AttributeError): # pragma: no cover
    pass
else:
    class Curve25519DH:
        """Curve25519 Diffie Hellman implementation"""

        def __init__(self):
            self._private = os.urandom(_CURVE25519_SCALARBYTES)

        def get_public(self):
            """Return the public key to send in the handshake"""

            public = ctypes.create_string_buffer(_CURVE25519_BYTES)

            if _curve25519_base(public, self._private) != 0:
                # This error is never returned by libsodium
                raise ValueError('Curve25519 failed') # pragma: no cover

            return public.raw

        def get_shared(self, peer_public):
            """Return the shared key from the peer's public key"""

            if len(peer_public) != _CURVE25519_BYTES:
                raise AssertionError('Invalid curve25519 public key size')

            shared = ctypes.create_string_buffer(_CURVE25519_BYTES)

            if _curve25519(shared, self._private, peer_public) != 0:
                # This error is never returned by libsodium
                raise ValueError('Curve25519 failed') # pragma: no cover

            return int.from_bytes(shared.raw, 'big')
