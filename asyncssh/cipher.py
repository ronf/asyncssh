# Copyright (c) 2013-2015 by Ron Frederick <ronf@timeheart.net>.
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

"""Symmetric key encryption handlers"""

from .crypto import lookup_cipher


_enc_algs = []
_enc_params = {}
_enc_ciphers = {}


def register_encryption_alg(alg, cipher_name, mode_name, key_size,
                            initial_bytes):
    """Register an encryption algorithm"""

    cipher = lookup_cipher(cipher_name, mode_name)
    if cipher: # pragma: no branch
        _enc_algs.append(alg)
        _enc_params[alg] = (key_size, cipher.iv_size,
                            cipher.block_size, cipher.mode_name)
        _enc_ciphers[alg] = (cipher, initial_bytes)


def get_encryption_algs():
    """Return a list of available encryption algorithms"""

    return _enc_algs


def get_encryption_params(alg):
    """Get parameters of an encryption algorithm

       This function returns the key, iv, and block sizes of an encryption
       algorithm.

    """

    return _enc_params[alg]


def get_cipher(alg, key, iv=None):
    """Return an instance of a cipher

       This function returns a cipher object initialized with the specified
       key and iv that can be used for data encryption and decryption.

    """

    cipher, initial_bytes = _enc_ciphers[alg]
    return cipher.new(key, iv, initial_bytes)


# pylint: disable=bad-whitespace

register_encryption_alg(b'chacha20-poly1305@openssh.com', 'chacha20-poly1305',
                        'chacha', 64, 0)
register_encryption_alg(b'aes256-ctr',             'aes',      'ctr', 32, 0)
register_encryption_alg(b'aes192-ctr',             'aes',      'ctr', 24, 0)
register_encryption_alg(b'aes128-ctr',             'aes',      'ctr', 16, 0)
register_encryption_alg(b'aes256-gcm@openssh.com', 'aes',      'gcm', 32, 0)
register_encryption_alg(b'aes128-gcm@openssh.com', 'aes',      'gcm', 16, 0)
register_encryption_alg(b'aes256-cbc',             'aes',      'cbc', 32, 0)
register_encryption_alg(b'aes192-cbc',             'aes',      'cbc', 24, 0)
register_encryption_alg(b'aes128-cbc',             'aes',      'cbc', 16, 0)
register_encryption_alg(b'3des-cbc',               'des3',     'cbc', 24, 0)
register_encryption_alg(b'blowfish-cbc',           'blowfish', 'cbc', 16, 0)
register_encryption_alg(b'cast128-cbc',            'cast',     'cbc', 16, 0)
register_encryption_alg(b'arcfour256',             'arc4',     None,  32, 1536)
register_encryption_alg(b'arcfour128',             'arc4',     None,  16, 1536)
register_encryption_alg(b'arcfour',                'arc4',     None,  16, 0)
