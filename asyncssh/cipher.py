# Copyright (c) 2013-2014 by Ron Frederick <ronf@timeheart.net>.
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

"""Symmetric key encryption handlers based on PyCrypto"""

from Crypto.Cipher import AES, ARC4, Blowfish, CAST, DES3
from Crypto.Util import Counter

_enc_algs = []
_enc_ciphers = {}
_enc_sizes = {}

_pem_ciphers = {}

def register_encryption_alg(alg, cipher, mode, key_size):
    """Register an encryption algorithm"""

    _enc_algs.append(alg)
    _enc_ciphers[alg] = (cipher, mode)
    _enc_sizes[alg] = (key_size, cipher.block_size)

def get_encryption_algs():
    """Return a list of available encryption algorithms"""

    return _enc_algs

def lookup_encryption_alg(alg):
    """Look up an encryption algorithm

       This function looks up an encryption algorithm and returns its key
       and block sizes.

    """

    return _enc_sizes[alg]

def get_cipher(alg, key, iv=None):
    """Return an instance of a cipher

       This function returns a cipher object initialized with the specified
       key and iv that can be used for data encryption and decryption.

    """

    cipher, mode = _enc_ciphers[alg]

    if alg.endswith(b'-ctr'):
        ctr = Counter.new(len(iv)*8, initial_value=int.from_bytes(iv, 'big'))
        return cipher.new(key, mode=mode, counter=ctr)
    elif alg.startswith(b'arcfour'):
        cipher = cipher.new(key)

        # For arcfour ciphers, we overload the mode to be the number of
        # initial key stream bytes to discard, to work around weak keys
        if mode:
            cipher.encrypt(mode * b'\0')

        return cipher
    else:
        return cipher.new(key, mode=mode, IV=iv)

register_encryption_alg(b'aes256-ctr',   AES,      AES.MODE_CTR,      32)
register_encryption_alg(b'aes192-ctr',   AES,      AES.MODE_CTR,      24)
register_encryption_alg(b'aes128-ctr',   AES,      AES.MODE_CTR,      16)
register_encryption_alg(b'aes256-cbc',   AES,      AES.MODE_CBC,      32)
register_encryption_alg(b'aes192-cbc',   AES,      AES.MODE_CBC,      24)
register_encryption_alg(b'aes128-cbc',   AES,      AES.MODE_CBC,      16)
register_encryption_alg(b'3des-cbc',     DES3,     DES3.MODE_CBC,     24)
register_encryption_alg(b'blowfish-cbc', Blowfish, Blowfish.MODE_CBC, 16)
register_encryption_alg(b'cast128-cbc',  CAST,     CAST.MODE_CBC,     16)
register_encryption_alg(b'arcfour256',   ARC4,     1536,              32)
register_encryption_alg(b'arcfour128',   ARC4,     1536,              16)
register_encryption_alg(b'arcfour',      ARC4,     0,                 16)
