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

"""Unit tests for symmetric key encryption"""

import os
import unittest

from .util import libnacl_available

from asyncssh.cipher import get_encryption_algs, get_encryption_params
from asyncssh.cipher import get_cipher


class _TestCipher(unittest.TestCase):
    """Unit tests for cipher module"""

    def test_encryption_algs(self):
        """Unit test encryption algorithms"""

        for alg in get_encryption_algs():
            with self.subTest(alg=alg):
                keysize, ivsize, blocksize, mode = get_encryption_params(alg)

                key = os.urandom(keysize)
                iv = os.urandom(ivsize)
                data = os.urandom(32*blocksize)

                enc_cipher = get_cipher(alg, key, iv)
                dec_cipher = get_cipher(alg, key, iv)

                badkey = bytearray(key)
                badkey[-1] ^= 0xff
                bad_cipher = get_cipher(alg, bytes(badkey), iv)

                hdr = os.urandom(4)

                if mode == 'chacha':
                    nonce = os.urandom(8)
                    enchdr = enc_cipher.crypt_len(hdr, nonce)
                    encdata, mac = enc_cipher.encrypt_and_sign(hdr, data,
                                                               nonce)

                    dechdr = dec_cipher.crypt_len(enchdr, nonce)
                    decdata = dec_cipher.verify_and_decrypt(dechdr, encdata,
                                                            nonce, mac)

                    badhdr = bad_cipher.crypt_len(enchdr, nonce)
                    baddata = bad_cipher.verify_and_decrypt(badhdr, encdata,
                                                            nonce, mac)
                    self.assertIsNone(baddata)
                elif mode == 'gcm':
                    dechdr = hdr
                    encdata, mac = enc_cipher.encrypt_and_sign(hdr, data)

                    decdata = dec_cipher.verify_and_decrypt(hdr, encdata, mac)

                    baddata = bad_cipher.verify_and_decrypt(hdr, encdata, mac)
                    self.assertIsNone(baddata)
                else:
                    dechdr = hdr
                    encdata1 = enc_cipher.encrypt(data[:len(data)//2])
                    encdata2 = enc_cipher.encrypt(data[len(data)//2:])

                    decdata = dec_cipher.decrypt(encdata1)
                    decdata += dec_cipher.decrypt(encdata2)

                    baddata = bad_cipher.decrypt(encdata1)
                    baddata += bad_cipher.decrypt(encdata2)
                    self.assertNotEqual(data, baddata)

                self.assertEqual(hdr, dechdr)
                self.assertEqual(data, decdata)

    if libnacl_available: # pragma: no branch
        def test_chacha_errors(self):
            """Unit test error code paths in chacha cipher"""

            alg = b'chacha20-poly1305@openssh.com'
            keysize, ivsize, _, _ = get_encryption_params(alg)
            key = os.urandom(keysize)
            iv = os.urandom(ivsize)

            with self.subTest('Chacha20Poly1305 key size error'):
                with self.assertRaises(ValueError):
                    get_cipher(alg, key[:-1], iv)

            with self.subTest('Chacha20Poly1305 nonce size error'):
                cipher = get_cipher(alg, key, iv)

                with self.assertRaises(ValueError):
                    cipher.crypt_len(b'', b'')

                with self.assertRaises(ValueError):
                    cipher.encrypt_and_sign(b'', b'', b'')

                with self.assertRaises(ValueError):
                    cipher.verify_and_decrypt(b'', b'', b'', b'')

