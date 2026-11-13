# Copyright (c) 2015-2021 by Ron Frederick <ronf@timeheart.net> and others.
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

from typing import Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives.ciphers import Cipher, CipherContext
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from cryptography.hazmat.primitives.poly1305 import Poly1305

from .cipher import register_cipher


chacha_available = backend.poly1305_supported()


_ZERO_CTR = 8 * b'\0'
_ZERO_BLOCK = 64 * b'\0'
_POLY1305_KEYBYTES = 32


class ChachaCipher:
    """Shim for Chacha20-Poly1305 symmetric encryption"""

    def __init__(self, key: bytes):
        keylen = len(key) // 2
        self._key = key[:keylen]
        self._adkey = key[keylen:]

    @staticmethod
    def _open_stream(key: bytes, nonce: bytes) -> CipherContext:
        """Open a ChaCha20 stream for a key and nonce"""

        return Cipher(ChaCha20(key, _ZERO_CTR + nonce),
                      mode=None).encryptor()

    @staticmethod
    def _poly1305_key(stream: CipherContext) -> bytes:
        """Read the Poly1305 key from block 0 of a newly opened stream"""

        return stream.update(_ZERO_BLOCK)[:_POLY1305_KEYBYTES]

    def encrypt_and_sign(self, header: bytes, data: bytes,
                         nonce: bytes) -> Tuple[bytes, bytes]:
        """Encrypt and sign a block of data"""

        header = self._open_stream(self._adkey, nonce).update(header)

        stream = self._open_stream(self._key, nonce)
        poly_key = self._poly1305_key(stream)
        data = stream.update(data)
        tag = Poly1305.generate_tag(poly_key, header + data)

        return header + data, tag

    def decrypt_header(self, header: bytes, nonce: bytes) -> bytes:
        """Decrypt header data"""

        return self._open_stream(self._adkey, nonce).update(header)

    def verify_and_decrypt(self, header: bytes, data: bytes,
                           nonce: bytes, tag: bytes) -> Optional[bytes]:
        """Verify the signature of and decrypt a block of data"""

        stream = self._open_stream(self._key, nonce)
        poly_key = self._poly1305_key(stream)

        try:
            Poly1305.verify_tag(poly_key, header + data, tag)
        except InvalidSignature:
            return None

        return stream.update(data)


if chacha_available: # pragma: no branch
    register_cipher('chacha20-poly1305', 64, 0, 1)
