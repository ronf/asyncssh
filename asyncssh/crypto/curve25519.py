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

from os import urandom

_found = None

try:
    from libnacl import nacl

    _CURVE25519_BYTES = nacl.crypto_scalarmult_curve25519_bytes()
    _CURVE25519_SCALARBYTES = nacl.crypto_scalarmult_curve25519_scalarbytes()

    _curve25519 = nacl.crypto_scalarmult_curve25519
    _curve25519_base = nacl.crypto_scalarmult_curve25519_base

    _found = 'libnacl'
except (ImportError, OSError, AttributeError):
    try:
        import curve25519

        _found = 'curve25519'
    except ImportError:
        pass

if _found == 'libnacl':
    class Curve25519DH:
        """Curve25519 Diffie Hellman implementation"""

        def __init__(self, secret=None):
            if secret is None:
                secret = urandom(_CURVE25519_SCALARBYTES)
            elif len(secret) != _CURVE25519_SCALARBYTES:
                raise AssertionError('Invalid curve25519 private key size')

            self._private = secret

        def get_public(self):
            """Return the public key to send in the handshake"""

            public = ctypes.create_string_buffer(_CURVE25519_BYTES)

            if _curve25519_base(public, self._private) != 0:
                raise ValueError('Curve25519 multiplication failed')

            return public.raw

        def get_shared(self, public):
            """Return the shared key from the peer's public key"""

            if len(public) != _CURVE25519_BYTES:
                raise AssertionError('Invalid curve25519 public key size')

            shared = ctypes.create_string_buffer(_CURVE25519_BYTES)

            if _curve25519(shared, self._private, public) != 0:
                raise ValueError('Curve25519 multiplication failed')

            return shared.raw
elif _found == 'curve25519':
    class Curve25519DH:
        """Curve25519 Diffie Hellman implementation"""

        def __init__(self, secret=None):
            self._private = curve25519.Private(secret)

        def get_public(self):
            """Return the public key to send in the handshake"""

            return self._private.get_public().serialize()

        def get_shared(self, public):
            """Return the shared key from the peer's public key"""

            public = curve25519.Public(public)

            return self._private.get_shared_key(public, hashfunc=lambda x: x)
