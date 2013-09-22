# Copyright (c) 2013 by Ron Frederick <ronf@timeheart.net>.
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

from .constants import *
from .misc import *
from .packet import *

_enc_algs = []
_enc_ciphers = {}
_enc_sizes = {}

_pem_ciphers = {}

def register_encryption_algorithm(alg, cipher, mode, key_size):
    """Register a cipher"""

    _enc_algs.append(alg)
    _enc_ciphers[alg] = (cipher, mode)
    _enc_sizes[alg] = (key_size, cipher.block_size)

def get_encryption_algs():
    """Return a list of available ciphers"""

    return _enc_algs

def choose_encryption_algorithm(conn, peer_enc_algs):
    """Choose the cipher to use
    
       This function returns the cipher to use and the number of bytes of
       data needed for its key and iv.

    """

    if conn.is_client():
        client_algs = _enc_algs
        server_algs = peer_enc_algs
    else:
        client_algs = peer_enc_algs
        server_algs = _enc_algs

    for alg in client_algs:
        if alg in server_algs:
            key_size, block_size = _enc_sizes[alg]
            return alg, key_size, block_size

    raise SSHError(DISC_KEY_EXCHANGE_FAILED, 'No matching cipher found')

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

register_encryption_algorithm(b'aes256-ctr',   AES,      AES.MODE_CTR,      32)
register_encryption_algorithm(b'aes192-ctr',   AES,      AES.MODE_CTR,      24)
register_encryption_algorithm(b'aes128-ctr',   AES,      AES.MODE_CTR,      16)
register_encryption_algorithm(b'aes256-cbc',   AES,      AES.MODE_CBC,      32)
register_encryption_algorithm(b'aes192-cbc',   AES,      AES.MODE_CBC,      24)
register_encryption_algorithm(b'aes128-cbc',   AES,      AES.MODE_CBC,      16)
register_encryption_algorithm(b'3des-cbc',     DES3,     DES3.MODE_CBC,     24)
register_encryption_algorithm(b'blowfish-cbc', Blowfish, Blowfish.MODE_CBC, 16)
register_encryption_algorithm(b'cast128-cbc',  CAST,     CAST.MODE_CBC,     16)
register_encryption_algorithm(b'arcfour256',   ARC4,     1536,              32)
register_encryption_algorithm(b'arcfour128',   ARC4,     1536,              16)
register_encryption_algorithm(b'arcfour',      ARC4,     0,                 16)
