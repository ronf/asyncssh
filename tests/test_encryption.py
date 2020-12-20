# Copyright (c) 2015-2020 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Unit tests for symmetric key encryption"""

import os
import random
import unittest

from asyncssh.encryption import register_encryption_alg, get_encryption_algs
from asyncssh.encryption import get_encryption_params, get_encryption
from asyncssh.mac import get_mac_algs


class _TestEncryption(unittest.TestCase):
    """Unit tests for encryption module"""

    def check_encryption_alg(self, enc_alg, mac_alg):
        """Check a symmetric encryption algorithm"""

        enc_keysize, enc_ivsize, enc_blocksize, mac_keysize, _, etm = \
            get_encryption_params(enc_alg, mac_alg)

        enc_blocksize = max(8, enc_blocksize)

        enc_key = os.urandom(enc_keysize)
        enc_iv = os.urandom(enc_ivsize)
        mac_key = os.urandom(mac_keysize)

        seq = random.getrandbits(32)

        enc = get_encryption(enc_alg, enc_key, enc_iv, mac_alg, mac_key, etm)
        dec = get_encryption(enc_alg, enc_key, enc_iv, mac_alg, mac_key, etm)

        for i in range(2, 6):
            data = os.urandom(4*etm + i*enc_blocksize)
            hdr, packet = data[:4], data[4:]

            encdata, encmac = enc.encrypt_packet(seq, hdr, packet)

            first, rest = encdata[:enc_blocksize], encdata[enc_blocksize:]

            decfirst, dechdr = dec.decrypt_header(seq, first, 4)

            decdata = dec.decrypt_packet(seq, decfirst, rest, 4, encmac)

            self.assertEqual(dechdr, hdr)
            self.assertEqual(decdata, packet)

            seq = (seq + 1) & 0xffffffff

    def test_encryption_algs(self):
        """Unit test encryption algorithms"""

        for enc_alg in get_encryption_algs():
            for mac_alg in get_mac_algs():
                with self.subTest(enc_alg=enc_alg, mac_alg=mac_alg):
                    self.check_encryption_alg(enc_alg, mac_alg)

    def test_unavailable_cipher(self):
        """Test registering encryption that uses an unavailable cipher"""

        # pylint: disable=no-self-use

        register_encryption_alg('xxx', 'xxx', '', True)
