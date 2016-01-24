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

"""Chacha20-Poly1305 symmetric encryption handler"""

import ctypes

from .cipher import register_cipher


class _Chacha20Poly1305Cipher:
    """Handler for Chacha20-Poly1305 symmetric encryption"""

    block_size = 1
    iv_size = 0

    def __init__(self, key):
        if len(key) != 2 * _CHACHA20_KEYBYTES:
            raise ValueError('Invalid chacha20-poly1305 key size')

        self._key = key[:_CHACHA20_KEYBYTES]
        self._adkey = key[_CHACHA20_KEYBYTES:]

    @classmethod
    def new(cls, key, iv=None, initial_bytes=0):
        """Construct a new chacha20-poly1305 cipher object"""

        # pylint: disable=unused-argument
        return cls(key)

    def _crypt(self, key, data, nonce, ctr=0):
        """Encrypt/decrypt a block of data"""

        # pylint: disable=no-self-use

        datalen = len(data)
        result = ctypes.create_string_buffer(datalen)
        datalen = ctypes.c_ulonglong(datalen)
        ctr = ctypes.c_ulonglong(ctr)

        if _chacha20_xor_ic(result, data, datalen, nonce, ctr, key) != 0:
            raise ValueError('Chacha encryption failed') # pragma: no cover

        return result.raw

    def _polykey(self, nonce):
        """Generate a poly1305 key"""

        polykey = ctypes.create_string_buffer(_POLY1305_KEYBYTES)
        polykeylen = ctypes.c_ulonglong(_POLY1305_KEYBYTES)

        if _chacha20(polykey, polykeylen, nonce, self._key) != 0:
            raise ValueError('Poly1305 key gen failed') # pragma: no cover

        return polykey

    def _compute_tag(self, data, nonce):
        """Compute a poly1305 tag for a block of data"""

        tag = ctypes.create_string_buffer(_POLY1305_BYTES)
        datalen = ctypes.c_ulonglong(len(data))
        polykey = self._polykey(nonce)

        if _poly1305(tag, data, datalen, polykey) != 0:
            raise ValueError('Poly1305 tag gen failed') # pragma: no cover

        return tag.raw

    def _verify_tag(self, data, nonce, tag):
        """Verify a poly1305 tag on a block of data"""

        datalen = ctypes.c_ulonglong(len(data))
        polykey = self._polykey(nonce)

        return _poly1305_verify(tag, data, datalen, polykey) == 0

    def crypt_len(self, data, nonce):
        """Encrypt/decrypt an SSH packet length value"""

        if len(nonce) != _CHACHA20_NONCEBYTES:
            raise ValueError('Invalid chacha20-poly1305 nonce size')

        return self._crypt(self._adkey, data, nonce)

    def encrypt_and_sign(self, header, data, nonce):
        """Encrypt and sign a block of data"""

        if len(nonce) != _CHACHA20_NONCEBYTES:
            raise ValueError('Invalid chacha20-poly1305 nonce size')

        ciphertext = self._crypt(self._key, data, nonce, 1)
        tag = self._compute_tag(header + ciphertext, nonce)

        return ciphertext, tag

    def verify_and_decrypt(self, header, data, nonce, tag):
        """Verify the signature of and decrypt a block of data"""

        if len(nonce) != _CHACHA20_NONCEBYTES:
            raise ValueError('Invalid chacha20-poly1305 nonce size')

        if self._verify_tag(header + data, nonce, tag):
            plaintext = self._crypt(self._key, data, nonce, 1)
        else:
            plaintext = None

        return plaintext

try:
    # pylint: disable=wrong-import-position,wrong-import-order
    from libnacl import nacl

    _CHACHA20_KEYBYTES = nacl.crypto_stream_chacha20_keybytes()
    _CHACHA20_NONCEBYTES = nacl.crypto_stream_chacha20_noncebytes()

    _chacha20 = nacl.crypto_stream_chacha20
    _chacha20_xor_ic = nacl.crypto_stream_chacha20_xor_ic

    _POLY1305_BYTES = nacl.crypto_onetimeauth_poly1305_bytes()
    _POLY1305_KEYBYTES = nacl.crypto_onetimeauth_poly1305_keybytes()

    _poly1305 = nacl.crypto_onetimeauth_poly1305
    _poly1305_verify = nacl.crypto_onetimeauth_poly1305_verify
except (ImportError, OSError, AttributeError): # pragma: no cover
    pass
else:
    register_cipher('chacha20-poly1305', 'chacha', _Chacha20Poly1305Cipher)
