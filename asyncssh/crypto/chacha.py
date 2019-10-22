# Copyright (c) 2015-2019 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Chacha20-Poly1305 symmetric encryption handler"""

import ctypes

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from cryptography.hazmat.primitives.poly1305 import Poly1305

from .cipher import register_cipher


if backend.poly1305_supported():
    _CTR_0 = (0).to_bytes(8, 'little')
    _CTR_1 = (1).to_bytes(8, 'little')

    _POLY1305_KEYBYTES = 32

    def chacha20(key, data, nonce, ctr):
        """Encrypt/decrypt a block of data with the ChaCha20 cipher"""

        return Cipher(ChaCha20(key, (_CTR_1 if ctr else _CTR_0) + nonce),
                      mode=None, backend=backend).encryptor().update(data)

    def poly1305_key(key, nonce):
        """Derive a Poly1305 key"""

        return chacha20(key, _POLY1305_KEYBYTES * b'\0', nonce, 0)

    def poly1305(key, data, nonce):
        """Compute a Poly1305 tag for a block of data"""

        return Poly1305.generate_tag(poly1305_key(key, nonce), data)

    def poly1305_verify(key, data, nonce, tag):
        """Verify a Poly1305 tag for a block of data"""

        try:
            Poly1305.verify_tag(poly1305_key(key, nonce), data, tag)
            return True
        except InvalidSignature:
            return False

    chacha_available = True
else: # pragma: no cover
    try:
        from libnacl import nacl

        _chacha20 = nacl.crypto_stream_chacha20
        _chacha20_xor_ic = nacl.crypto_stream_chacha20_xor_ic

        _POLY1305_BYTES = nacl.crypto_onetimeauth_poly1305_bytes()
        _POLY1305_KEYBYTES = nacl.crypto_onetimeauth_poly1305_keybytes()

        _poly1305 = nacl.crypto_onetimeauth_poly1305
        _poly1305_verify = nacl.crypto_onetimeauth_poly1305_verify

        def chacha20(key, data, nonce, ctr):
            """Encrypt/decrypt a block of data with the ChaCha20 cipher"""

            datalen = len(data)
            result = ctypes.create_string_buffer(datalen)
            datalen = ctypes.c_ulonglong(datalen)
            ctr = ctypes.c_ulonglong(ctr)

            _chacha20_xor_ic(result, data, datalen, nonce, ctr, key)

            return result.raw

        def poly1305_key(key, nonce):
            """Derive a Poly1305 key"""

            polykey = ctypes.create_string_buffer(_POLY1305_KEYBYTES)
            polykeylen = ctypes.c_ulonglong(_POLY1305_KEYBYTES)

            _chacha20(polykey, polykeylen, nonce, key)

            return polykey

        def poly1305(key, data, nonce):
            """Compute a Poly1305 tag for a block of data"""

            tag = ctypes.create_string_buffer(_POLY1305_BYTES)
            datalen = ctypes.c_ulonglong(len(data))
            polykey = poly1305_key(key, nonce)

            _poly1305(tag, data, datalen, polykey)

            return tag.raw

        def poly1305_verify(key, data, nonce, tag):
            """Verify a Poly1305 tag for a block of data"""

            datalen = ctypes.c_ulonglong(len(data))
            polykey = poly1305_key(key, nonce)

            return _poly1305_verify(tag, data, datalen, polykey) == 0

        chacha_available = True
    except (ImportError, OSError, AttributeError):
        chacha_available = False


class ChachaCipher:
    """Shim for Chacha20-Poly1305 symmetric encryption"""

    def __init__(self, key):
        keylen = len(key) // 2
        self._key = key[:keylen]
        self._adkey = key[keylen:]

    def encrypt_and_sign(self, header, data, nonce):
        """Encrypt and sign a block of data"""

        header = chacha20(self._adkey, header, nonce, 0)
        data = chacha20(self._key, data, nonce, 1)
        tag = poly1305(self._key, header + data, nonce)

        return header + data, tag

    def decrypt_header(self, header, nonce):
        """Decrypt header data"""

        return chacha20(self._adkey, header, nonce, 0)

    def verify_and_decrypt(self, header, data, nonce, tag):
        """Verify the signature of and decrypt a block of data"""

        if poly1305_verify(self._key, header + data, nonce, tag):
            return chacha20(self._key, data, nonce, 1)
        else:
            return None


if chacha_available: # pragma: no branch
    register_cipher('chacha20-poly1305', 64, 0, 1)
