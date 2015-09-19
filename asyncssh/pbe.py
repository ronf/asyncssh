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

"""Asymmetric key password based encryption functions"""

import hmac
import os

from hashlib import md5, sha1, sha224, sha256, sha384, sha512

from .asn1 import ASN1DecodeError, ObjectIdentifier, der_encode, der_decode
from .crypto import lookup_cipher


# pylint: disable=bad-whitespace

_ES1_MD5_DES    = ObjectIdentifier('1.2.840.113549.1.5.3')
_ES1_SHA1_DES   = ObjectIdentifier('1.2.840.113549.1.5.10')

_ES2            = ObjectIdentifier('1.2.840.113549.1.5.13')

_P12_RC4_128    = ObjectIdentifier('1.2.840.113549.1.12.1.1')
_P12_RC4_40     = ObjectIdentifier('1.2.840.113549.1.12.1.2')
_P12_DES3       = ObjectIdentifier('1.2.840.113549.1.12.1.3')
_P12_DES2       = ObjectIdentifier('1.2.840.113549.1.12.1.4')

_ES2_CAST128    = ObjectIdentifier('1.2.840.113533.7.66.10')
_ES2_DES3       = ObjectIdentifier('1.2.840.113549.3.7')
_ES2_BF         = ObjectIdentifier('1.3.6.1.4.1.3029.1.2')
_ES2_DES        = ObjectIdentifier('1.3.14.3.2.7')
_ES2_AES128     = ObjectIdentifier('2.16.840.1.101.3.4.1.2')
_ES2_AES192     = ObjectIdentifier('2.16.840.1.101.3.4.1.22')
_ES2_AES256     = ObjectIdentifier('2.16.840.1.101.3.4.1.42')

_ES2_PBKDF2     = ObjectIdentifier('1.2.840.113549.1.5.12')

_ES2_SHA1       = ObjectIdentifier('1.2.840.113549.2.7')
_ES2_SHA224     = ObjectIdentifier('1.2.840.113549.2.8')
_ES2_SHA256     = ObjectIdentifier('1.2.840.113549.2.9')
_ES2_SHA384     = ObjectIdentifier('1.2.840.113549.2.10')
_ES2_SHA512     = ObjectIdentifier('1.2.840.113549.2.11')
_ES2_SHA512_224 = ObjectIdentifier('1.2.840.113549.2.12')
_ES2_SHA512_256 = ObjectIdentifier('1.2.840.113549.2.13')

# pylint: enable=bad-whitespace

_pkcs1_ciphers = {}
_pkcs8_ciphers = {}
_pbes2_ciphers = {}
_pbes2_kdfs = {}
_pbes2_prfs = {}

_pkcs1_cipher_names = {}
_pkcs8_cipher_suites = {}
_pbes2_cipher_names = {}
_pbes2_kdf_names = {}
_pbes2_prf_names = {}


def strxor(a, b):
    """Return the byte-wise XOR of two strings"""

    c = int.from_bytes(a, 'little') ^ int.from_bytes(b, 'little')
    return int.to_bytes(c, max(len(a), len(b)), 'little')


class KeyEncryptionError(ValueError):
    """Key encryption error

       This exception is raised by key decryption functions when the data
       provided is not a valid encrypted private key.

    """


class _RFC1423Pad:
    """RFC 1423 padding functions

       This class implements RFC 1423 padding for encryption and
       decryption of data by block ciphers. On encryption, the data is
       padded by between 1 and the cipher's block size number of bytes,
       with the padding value being equal to the length of the padding.

    """

    def __init__(self, cipher):
        self._cipher = cipher
        self._block_size = cipher.block_size

    def encrypt(self, data):
        """Pad data before encrypting it"""

        pad = self._block_size - (len(data) % self._block_size)
        data += pad * bytes((pad,))
        return self._cipher.encrypt(data)

    def decrypt(self, data):
        """Remove padding from data after decrypting it"""

        data = self._cipher.decrypt(data)

        if data:
            pad = data[-1]
            if (1 <= pad <= self._block_size and
                    data[-pad:] == pad * bytes((pad,))):
                return data[:-pad]

        raise KeyEncryptionError('Unable to decrypt key')


def _pbkdf1(hash_alg, passphrase, salt, count, key_size):
    """PKCS#5 v1.5 key derivation function for password-based encryption

       This function implements the PKCS#5 v1.5 algorithm for deriving
       an encryption key from a passphrase and salt.

       The standard PBKDF1 function cannot generate more key bytes than
       the hash digest size, but 3DES uses a modified form of it which
       calls PBKDF1 recursively on the result to generate more key data.
       Support for this is implemented here.

    """

    if isinstance(passphrase, str):
        passphrase = passphrase.encode('utf-8')

    key = passphrase + salt
    for _ in range(count):
        key = hash_alg(key).digest()

    if len(key) <= key_size:
        return key + _pbkdf1(hash_alg, key + passphrase, salt, count,
                             key_size - len(key))
    else:
        return key[:key_size]


def _pbkdf2(prf, passphrase, salt, count, key_size):
    """PKCS#5 v2.0 key derivation function for password-based encryption

       This function implements the PKCS#5 v2.0 algorithm for deriving
       an encryption key from a passphrase and salt.

    """

    # Short variable names are used here, matching names in the spec
    # pylint: disable=invalid-name

    if isinstance(passphrase, str):
        passphrase = passphrase.encode('utf-8')

    key = b''
    i = 1
    while len(key) < key_size:
        u = prf(passphrase, salt + i.to_bytes(4, 'big'))
        f = u
        for _ in range(1, count):
            u = prf(passphrase, u)
            f = strxor(f, u)

        key += f
        i += 1

    return key[:key_size]


def _pbkdf_p12(hash_alg, passphrase, salt, count, key_size, idx):
    """PKCS#12 key derivation function for password-based encryption

       This function implements the PKCS#12 algorithm for deriving an
       encryption key from a passphrase and salt.

    """

    # Short variable names are used here, matching names in the spec
    # pylint: disable=invalid-name

    def _make_block(data, v):
        """Make a block a multiple of v bytes long by repeating data"""

        l = len(data)
        size = ((l + v - 1) // v) * v
        return (((size + l - 1) // l) * data)[:size]

    v = hash_alg().block_size
    D = v * bytes((idx,))

    if isinstance(passphrase, str):
        passphrase = passphrase.encode('utf-16be')

    I = bytearray(_make_block(salt, v) + _make_block(passphrase + b'\0\0', v))

    key = b''
    while len(key) < key_size:
        A = D + I
        for i in range(count):
            A = hash_alg(A).digest()

        B = int.from_bytes(_make_block(A, v), 'big')
        for i in range(0, len(I), v):
            x = (int.from_bytes(I[i:i+v], 'big') + B + 1) % (1 << v*8)
            I[i:i+v] = x.to_bytes(v, 'big')

        key += A

    return key[:key_size]


def _pbes1(params, passphrase, hash_alg, cipher, key_size):
    """PKCS#5 v1.5 cipher selection function for password-based encryption

       This function implements the PKCS#5 v1.5 algorithm for password-based
       encryption. It returns a cipher object which can be used to encrypt
       or decrypt data based on the specified encryption parameters,
       passphrase, and salt.

    """

    if (not isinstance(params, tuple) or len(params) != 2 or
            not isinstance(params[0], bytes) or
            not isinstance(params[1], int)):
        raise KeyEncryptionError('Invalid PBES1 encryption parameters')

    salt, count = params
    key = _pbkdf1(hash_alg, passphrase, salt, count,
                  key_size + cipher.block_size)
    key, iv = key[:key_size], key[key_size:]

    return _RFC1423Pad(cipher.new(key, iv))


def _pbe_p12(params, passphrase, hash_alg, cipher, key_size):
    """PKCS#12 cipher selection function for password-based encryption

       This function implements the PKCS#12 algorithm for password-based
       encryption. It returns a cipher object which can be used to encrypt
       or decrypt data based on the specified encryption parameters,
       passphrase, and salt.

    """

    if (not isinstance(params, tuple) or len(params) != 2 or
            not isinstance(params[0], bytes) or len(params[0]) == 0 or
            not isinstance(params[1], int) or params[1] == 0):
        raise KeyEncryptionError('Invalid PBES1 PKCS#12 encryption parameters')

    salt, count = params
    key = _pbkdf_p12(hash_alg, passphrase, salt, count, key_size, 1)

    if cipher.cipher_name == 'arc4':
        cipher = cipher.new(key)
    else:
        iv = _pbkdf_p12(hash_alg, passphrase, salt, count,
                        cipher.block_size, 2)

        cipher = _RFC1423Pad(cipher.new(key, iv))

    return cipher


def _pbes2_iv(params, key, cipher):
    """PKCS#5 v2.0 handler for PBES2 ciphers with an IV as a parameter

       This function returns the appropriate cipher object to use for
       PBES2 encryption for ciphers that have only an IV as an encryption
       parameter.

    """

    if len(params) != 1 or not isinstance(params[0], bytes):
        raise KeyEncryptionError('Invalid PBES2 encryption parameters')

    if len(params[0]) != cipher.block_size:
        raise KeyEncryptionError('Invalid length IV for PBES2 encryption')

    return cipher.new(key, params[0])


def _pbes2_hmac_prf(hash_alg, digest_size=None):
    """PKCS#5 v2.0 handler for PBKDF2 psuedo-random function

       This function returns the appropriate PBKDF2 pseudo-random function
       to use for key derivation.

    """

    return lambda key, msg: hmac.new(key, msg, hash_alg).digest()[:digest_size]


def _pbes2_pbkdf2(params, passphrase, default_key_size):
    """PKCS#5 v2.0 handler for PBKDF2 key derivation

       This function parses the PBKDF2 arguments from a PKCS#8 encrypted key
       and returns the encryption key to use for encryption.

    """

    if (len(params) != 1 or not isinstance(params[0], tuple) or
            len(params[0]) < 2):
        raise KeyEncryptionError('Invalid PBES2 key derivation parameters')

    params = list(params[0])

    if not isinstance(params[0], bytes) or not isinstance(params[1], int):
        raise KeyEncryptionError('Invalid PBES2 key derivation parameters')

    salt = params.pop(0)
    count = params.pop(0)

    if params and isinstance(params[0], int):
        key_size = params.pop(0)    # pragma: no cover, used only by RC2
    else:
        key_size = default_key_size

    if params:
        if (isinstance(params[0], tuple) and len(params[0]) == 2 and
                isinstance(params[0][0], ObjectIdentifier)):
            prf_alg = params[0][0]
            if prf_alg in _pbes2_prfs:
                handler, args = _pbes2_prfs[prf_alg]
                prf = handler(*args)
            else:
                raise KeyEncryptionError('Unknown PBES2 pseudo-random '
                                         'function')
        else:
            raise KeyEncryptionError('Invalid PBES2 pseudo-random function '
                                     'parameters')
    else:
        prf = _pbes2_hmac_prf(sha1)

    return _pbkdf2(prf, passphrase, salt, count, key_size)


def _pbes2(params, passphrase):
    """PKCS#5 v2.0 cipher selection function for password-based encryption

       This function implements the PKCS#5 v2.0 algorithm for password-based
       encryption. It returns a cipher object which can be used to encrypt
       or decrypt data based on the specified encryption parameters and
       passphrase.

    """

    if (not isinstance(params, tuple) or len(params) != 2 or
            not isinstance(params[0], tuple) or len(params[0]) < 1 or
            not isinstance(params[1], tuple) or len(params[1]) < 1):
        raise KeyEncryptionError('Invalid PBES2 encryption parameters')

    kdf_params = list(params[0])

    kdf_alg = kdf_params.pop(0)
    if kdf_alg not in _pbes2_kdfs:
        raise KeyEncryptionError('Unknown PBES2 key derivation function')

    enc_params = list(params[1])

    enc_alg = enc_params.pop(0)
    if enc_alg not in _pbes2_ciphers:
        raise KeyEncryptionError('Unknown PBES2 encryption algorithm')

    kdf_handler, kdf_args = _pbes2_kdfs[kdf_alg]
    enc_handler, cipher, default_key_size = _pbes2_ciphers[enc_alg]

    key = kdf_handler(kdf_params, passphrase, default_key_size, *kdf_args)
    return _RFC1423Pad(enc_handler(enc_params, key, cipher))


def register_pkcs1_cipher(cipher_name, alg, cipher, mode, key_size):
    """Register a cipher used for PKCS#1 private key encryption"""

    cipher = lookup_cipher(cipher, mode)

    if cipher: # pragma: no branch
        _pkcs1_ciphers[alg] = (cipher, key_size)
        _pkcs1_cipher_names[cipher_name] = alg


def register_pkcs8_cipher(cipher_name, hash_name, alg, handler, hash_alg,
                          cipher, mode, key_size):
    """Register a cipher used for PKCS#8 private key encryption"""

    cipher = lookup_cipher(cipher, mode)

    if cipher: # pragma: no branch
        _pkcs8_ciphers[alg] = (handler, hash_alg, cipher, key_size)
        _pkcs8_cipher_suites[cipher_name, hash_name] = alg


def register_pbes2_cipher(cipher_name, alg, handler, cipher, mode, key_size):
    """Register a PBES2 encryption algorithm"""

    cipher = lookup_cipher(cipher, mode)

    if cipher: # pragma: no branch
        _pbes2_ciphers[alg] = (handler, cipher, key_size)
        _pbes2_cipher_names[cipher_name] = (alg, key_size)


def register_pbes2_kdf(kdf_name, alg, handler, *args):
    """Register a PBES2 key derivation function"""

    _pbes2_kdfs[alg] = (handler, args)
    _pbes2_kdf_names[kdf_name] = alg


def register_pbes2_prf(hash_name, alg, handler, *args):
    """Register a PBES2 pseudo-random function"""

    _pbes2_prfs[alg] = (handler, args)
    _pbes2_prf_names[hash_name] = alg


def pkcs1_encrypt(data, cipher, passphrase):
    """Encrypt PKCS#1 key data

       This function encrypts PKCS#1 key data using the specified cipher
       and passphrase. Available ciphers include:

           aes128-cbc, aes192-cbc, aes256-cbc, des-cbc, des3-cbc

    """

    if cipher in _pkcs1_cipher_names:
        alg = _pkcs1_cipher_names[cipher]
        cipher, key_size = _pkcs1_ciphers[alg]

        iv = os.urandom(cipher.block_size)
        key = _pbkdf1(md5, passphrase, iv[:8], 1, key_size)

        cipher = _RFC1423Pad(cipher.new(key, iv))
        return alg, iv, cipher.encrypt(data)
    else:
        raise KeyEncryptionError('Unknown PKCS#1 encryption algorithm')


def pkcs1_decrypt(data, alg, iv, passphrase):
    """Decrypt PKCS#1 key data

       This function decrypts PKCS#1 key data using the specified algorithm,
       initialization vector, and passphrase. The algorithm name and IV
       should be taken from the PEM DEK-Info header.

    """

    if alg in _pkcs1_ciphers:
        cipher, key_size = _pkcs1_ciphers[alg]
        key = _pbkdf1(md5, passphrase, iv[:8], 1, key_size)

        cipher = _RFC1423Pad(cipher.new(key, iv))
        return cipher.decrypt(data)
    else:
        raise KeyEncryptionError('Unknown PKCS#1 encryption algorithm')


def pkcs8_encrypt(data, cipher_name, hash_name, version, passphrase):
    """Encrypt PKCS#8 key data

       This function encrypts PKCS#8 key data using the specified cipher,
       hash, encryption version, and passphrase.

       Available ciphers include:

           aes128-cbc, aes192-cbc, aes256-cbc, blowfish-cbc, cast128-cbc,
           des-cbc, des2-cbc, des3-cbc, rc4-40, and rc4-128

       Available hashes include:

           md5, sha1, sha256, sha384, sha512, sha512-224, sha512-256

       Available versions include 1 for PBES1 and 2 for PBES2.

       Only some combinations of cipher, hash, and version are supported.

    """

    if version == 1 and (cipher_name, hash_name) in _pkcs8_cipher_suites:
        alg = _pkcs8_cipher_suites[cipher_name, hash_name]
        handler, hash_alg, cipher, key_size = _pkcs8_ciphers[alg]

        params = (os.urandom(8), 2048)
        cipher = handler(params, passphrase, hash_alg, cipher, key_size)
        return der_encode(((alg, params), cipher.encrypt(data)))
    elif version == 2 and cipher_name in _pbes2_cipher_names:
        enc_alg, key_size = _pbes2_cipher_names[cipher_name]
        _, cipher, _ = _pbes2_ciphers[enc_alg]

        kdf_params = [os.urandom(8), 2048]
        iv = os.urandom(cipher.block_size)
        enc_params = (enc_alg, iv)

        if hash_name != 'sha1':
            if hash_name in _pbes2_prf_names:
                kdf_params.append((_pbes2_prf_names[hash_name], None))
            else:
                raise KeyEncryptionError('Unknown PBES2 hash function')

        alg = _ES2
        params = ((_ES2_PBKDF2, tuple(kdf_params)), enc_params)
        cipher = _pbes2(params, passphrase)
    else:
        raise KeyEncryptionError('Unknown PKCS#8 encryption algorithm')

    return der_encode(((alg, params), cipher.encrypt(data)))


def pkcs8_decrypt(key_data, passphrase):
    """Decrypt PKCS#8 key data

       This function decrypts key data in PKCS#8 EncryptedPrivateKeyInfo
       format using the specified passphrase.

    """

    if not isinstance(key_data, tuple) or len(key_data) != 2:
        raise KeyEncryptionError('Invalid PKCS#8 encrypted key format')

    alg_params, data = key_data

    if (not isinstance(alg_params, tuple) or len(alg_params) != 2 or
            not isinstance(data, bytes)):
        raise KeyEncryptionError('Invalid PKCS#8 encrypted key format')

    alg, params = alg_params

    if alg == _ES2:
        cipher = _pbes2(params, passphrase)
    elif alg in _pkcs8_ciphers:
        handler, hash_alg, cipher, key_size = _pkcs8_ciphers[alg]
        cipher = handler(params, passphrase, hash_alg, cipher, key_size)
    else:
        raise KeyEncryptionError('Unknown PKCS#8 encryption algorithm')

    try:
        return der_decode(cipher.decrypt(data))
    except ASN1DecodeError:
        raise KeyEncryptionError('Invalid PKCS#8 encrypted key data')


# pylint: disable=bad-whitespace

_pkcs1_cipher_list = (
    ('aes128-cbc', b'AES-128-CBC',  'aes',  'cbc', 16),
    ('aes192-cbc', b'AES-192-CBC',  'aes',  'cbc', 24),
    ('aes256-cbc', b'AES-256-CBC',  'aes',  'cbc', 32),
    ('des-cbc',    b'DES-CBC',      'des',  'cbc', 8),
    ('des3-cbc',   b'DES-EDE3-CBC', 'des3', 'cbc', 24)
)

_pkcs8_cipher_list = (
    ('des-cbc',     'md5',  _ES1_MD5_DES,  _pbes1,   md5,  'des',  'cbc', 8),
    ('des-cbc',     'sha1', _ES1_SHA1_DES, _pbes1,   sha1, 'des',  'cbc', 8),

    ('des2-cbc',    'sha1', _P12_DES2,     _pbe_p12, sha1, 'des3', 'cbc', 16),
    ('des3-cbc',    'sha1', _P12_DES3,     _pbe_p12, sha1, 'des3', 'cbc', 24),
    ('rc4-40',      'sha1', _P12_RC4_40,   _pbe_p12, sha1, 'arc4', None,  5),
    ('rc4-128',     'sha1', _P12_RC4_128,  _pbe_p12, sha1, 'arc4', None,  16)
)

_pbes2_cipher_list = (
    ('aes128-cbc',   _ES2_AES128,  _pbes2_iv,  'aes',      'cbc', 16),
    ('aes192-cbc',   _ES2_AES192,  _pbes2_iv,  'aes',      'cbc', 24),
    ('aes256-cbc',   _ES2_AES256,  _pbes2_iv,  'aes',      'cbc', 32),
    ('blowfish-cbc', _ES2_BF,      _pbes2_iv,  'blowfish', 'cbc', 16),
    ('cast128-cbc',  _ES2_CAST128, _pbes2_iv,  'cast',     'cbc', 16),
    ('des-cbc',      _ES2_DES,     _pbes2_iv,  'des',      'cbc', 8),
    ('des3-cbc',     _ES2_DES3,    _pbes2_iv,  'des3',     'cbc', 24)
)

_pbes2_kdf_list = (
    ('pbkdf2', _ES2_PBKDF2, _pbes2_pbkdf2),
)

_pbes2_prf_list = (
    ('sha1',       _ES2_SHA1,       _pbes2_hmac_prf, sha1),
    ('sha224',     _ES2_SHA224,     _pbes2_hmac_prf, sha224),
    ('sha256',     _ES2_SHA256,     _pbes2_hmac_prf, sha256),
    ('sha384',     _ES2_SHA384,     _pbes2_hmac_prf, sha384),
    ('sha512',     _ES2_SHA512,     _pbes2_hmac_prf, sha512),
    ('sha512-224', _ES2_SHA512_224, _pbes2_hmac_prf, sha512, 28),
    ('sha512-256', _ES2_SHA512_256, _pbes2_hmac_prf, sha512, 32)
)

for _args in _pkcs1_cipher_list:
    register_pkcs1_cipher(*_args)

for _args in _pkcs8_cipher_list:
    register_pkcs8_cipher(*_args)

for _args in _pbes2_cipher_list:
    register_pbes2_cipher(*_args)

for _args in _pbes2_kdf_list:
    register_pbes2_kdf(*_args)

for _args in _pbes2_prf_list:
    register_pbes2_prf(*_args)
