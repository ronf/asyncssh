# Copyright (c) 2014 by Ron Frederick <ronf@timeheart.net>.
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

"""A shim around PyCA for symmetric encryption"""

from .. import register_cipher

from cryptography.exceptions import InvalidTag

from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.ciphers import Cipher

from cryptography.hazmat.primitives.ciphers.algorithms import AES, ARC4
from cryptography.hazmat.primitives.ciphers.algorithms import Blowfish, CAST5
from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

from cryptography.hazmat.primitives.ciphers.modes import CBC, CTR, GCM

_ciphers = { 'aes':      (AES,       { 'cbc': CBC, 'ctr': CTR, 'gcm': GCM }),
             'arc4':     (ARC4,      { None: None }),
             'blowfish': (Blowfish,  { 'cbc': CBC }),
             'cast':     (CAST5,     { 'cbc': CBC }),
             'des':      (TripleDES, { 'cbc': CBC }),
             'des3':     (TripleDES, { 'cbc': CBC })}


class GCMShim:
    def __init__(self, cipher, block_size, key, iv):
        self._cipher = cipher
        self._key = key
        self._iv = iv

        self.block_size = block_size

    def _update_iv(self):
        invocation = int.from_bytes(self._iv[4:], 'big')
        invocation = (invocation + 1) & 0xffffffffffffffff
        self._iv = self._iv[:4] + invocation.to_bytes(8, 'big')

    def encrypt_and_sign(self, header, data):
        encryptor = Cipher(self._cipher(self._key), GCM(self._iv),
                           default_backend()).encryptor()

        if header:
            encryptor.authenticate_additional_data(header)

        ciphertext = encryptor.update(data) + encryptor.finalize()

        self._update_iv()

        return ciphertext, encryptor.tag

    def verify_and_decrypt(self, header, data, tag):
        decryptor = Cipher(self._cipher(self._key), GCM(self._iv, tag),
                           default_backend()).decryptor()

        if header:
            decryptor.authenticate_additional_data(header)

        try:
            plaintext = decryptor.update(data) + decryptor.finalize()
        except InvalidTag:
            plaintext = None

        self._update_iv()

        return plaintext


class CipherShim:
    def __init__(self, cipher, mode, block_size, key, iv, initial_bytes):
        if mode:
            mode = mode(iv)

        self._cipher = Cipher(cipher(key), mode, default_backend())
        self._initial_bytes = initial_bytes
        self._encryptor = None
        self._decryptor = None

        self.block_size = block_size

    def encrypt(self, data):
        if not self._encryptor:
            self._encryptor = self._cipher.encryptor()

            if self._initial_bytes:
                self._encryptor.update(self._initial_bytes * b'\0')

        return self._encryptor.update(data)

    def decrypt(self, data):
        if not self._decryptor:
            self._decryptor = self._cipher.decryptor()

            if self._initial_bytes:
                self._decryptor.update(self._initial_bytes * b'\0')

        return self._decryptor.update(data)


class CipherFactory:
    def __init__(self, cipher, mode):
        self._cipher = cipher
        self._mode = mode

        self.block_size = 1 if cipher == ARC4 else cipher.block_size // 8
        self.iv_size = 12 if mode == GCM else self.block_size

    def new(self, key, iv=None, initial_bytes=0):
        if self._mode == GCM:
            return GCMShim(self._cipher, self.block_size, key, iv)
        else:
            return CipherShim(self._cipher, self._mode, self.block_size,
                              key, iv, initial_bytes)


for cipher_name, (cipher, modes) in _ciphers.items():
    for mode_name, mode in modes.items():
        register_cipher(cipher_name, mode_name, CipherFactory(cipher, mode))
