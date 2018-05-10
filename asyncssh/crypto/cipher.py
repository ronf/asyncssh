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

"""A shim around PyCA for accessing symmetric ciphers needed by AsyncSSH"""

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES, ARC4
from cryptography.hazmat.primitives.ciphers.algorithms import Blowfish, CAST5
from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

from cryptography.hazmat.primitives.ciphers.modes import CBC, CTR, GCM

_cipher_algs = {}
_cipher_params = {}


class BasicCipher:
    """Shim for basic ciphers"""

    def __init__(self, cipher_name, key, iv):
        cipher, mode, initial_bytes = _cipher_algs[cipher_name]

        self._cipher = Cipher(cipher(key), mode(iv) if mode else None,
                              default_backend())
        self._initial_bytes = initial_bytes
        self._encryptor = None
        self._decryptor = None

    def encrypt(self, data):
        """Encrypt a block of data"""

        if not self._encryptor:
            self._encryptor = self._cipher.encryptor()

            if self._initial_bytes:
                self._encryptor.update(self._initial_bytes * b'\0')

        return self._encryptor.update(data)

    def decrypt(self, data):
        """Decrypt a block of data"""

        if not self._decryptor:
            self._decryptor = self._cipher.decryptor()

            if self._initial_bytes:
                self._decryptor.update(self._initial_bytes * b'\0')

        return self._decryptor.update(data)


class GCMCipher:
    """Shim for GCM ciphers"""

    def __init__(self, cipher_name, key, iv):
        self._cipher = _cipher_algs[cipher_name][0]
        self._key = key
        self._iv = iv

    def _update_iv(self):
        """Update the IV after each encrypt/decrypt operation"""

        invocation = int.from_bytes(self._iv[4:], 'big')
        invocation = (invocation + 1) & 0xffffffffffffffff
        self._iv = self._iv[:4] + invocation.to_bytes(8, 'big')

    def encrypt_and_sign(self, header, data):
        """Encrypt and sign a block of data"""

        encryptor = Cipher(self._cipher(self._key), GCM(self._iv),
                           default_backend()).encryptor()

        if header:
            encryptor.authenticate_additional_data(header)

        data = encryptor.update(data) + encryptor.finalize()

        self._update_iv()

        return header + data, encryptor.tag

    def verify_and_decrypt(self, header, data, mac):
        """Verify the signature of and decrypt a block of data"""

        decryptor = Cipher(self._cipher(self._key), GCM(self._iv, mac),
                           default_backend()).decryptor()

        decryptor.authenticate_additional_data(header)

        try:
            data = decryptor.update(data) + decryptor.finalize()
        except InvalidTag:
            data = None

        self._update_iv()

        return data


def register_cipher(cipher_name, key_size, iv_size, block_size):
    """Register a symmetric cipher"""

    _cipher_params[cipher_name] = (key_size, iv_size, block_size)


def get_cipher_params(cipher_name):
    """Get parameters of a symmetric cipher"""

    return _cipher_params[cipher_name]


# pylint: disable=bad-whitespace

_cipher_alg_list = (
    ('aes128-cbc',   AES,       CBC,     0, 16, 16, 16),
    ('aes192-cbc',   AES,       CBC,     0, 24, 16, 16),
    ('aes256-cbc',   AES,       CBC,     0, 32, 16, 16),
    ('aes128-ctr',   AES,       CTR,     0, 16, 16, 16),
    ('aes192-ctr',   AES,       CTR,     0, 24, 16, 16),
    ('aes256-ctr',   AES,       CTR,     0, 32, 16, 16),
    ('aes128-gcm',   AES,       GCM,     0, 16, 12, 16),
    ('aes256-gcm',   AES,       GCM,     0, 32, 12, 16),
    ('arcfour',      ARC4,      None,    0, 16,  1,  1),
    ('arcfour40',    ARC4,      None,    0,  5,  1,  1),
    ('arcfour128',   ARC4,      None, 1536, 16,  1,  1),
    ('arcfour256',   ARC4,      None, 1536, 32,  1,  1),
    ('blowfish-cbc', Blowfish,  CBC,     0, 16,  8,  8),
    ('cast128-cbc',  CAST5,     CBC,     0, 16,  8,  8),
    ('des-cbc',      TripleDES, CBC,     0,  8,  8,  8),
    ('des2-cbc',     TripleDES, CBC,     0, 16,  8,  8),
    ('des3-cbc',     TripleDES, CBC,     0, 24,  8,  8)
)

# pylint: enable=bad-whitespace

for _cipher_name, _cipher, _mode, _initial_bytes, \
        _key_size, _iv_size, _block_size in _cipher_alg_list:
    _cipher_algs[_cipher_name] = (_cipher, _mode, _initial_bytes)
    register_cipher(_cipher_name, _key_size, _iv_size, _block_size)
