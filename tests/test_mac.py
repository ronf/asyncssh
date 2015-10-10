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

"""Unit tests for message authentication"""

import os
import unittest

from asyncssh.mac import get_mac_algs, get_mac_params, get_mac


class _TestMAC(unittest.TestCase):
    """Unit tests for mac module"""

    def test_mac_algs(self):
        """Unit test MAC algorithms"""

        for alg in get_mac_algs():
            with self.subTest(alg=alg):
                keysize, _, _ = get_mac_params(alg)

                key = os.urandom(keysize)
                data = os.urandom(256)

                enc_mac = get_mac(alg, key)
                dec_mac = get_mac(alg, key)

                baddata = bytearray(data)
                baddata[-1] ^= 0xff

                mac = enc_mac.sign(data)

                badmac = bytearray(mac)
                badmac[-1] ^= 0xff

                self.assertTrue(dec_mac.verify(data, mac))
                self.assertFalse(dec_mac.verify(bytes(baddata), mac))
                self.assertFalse(dec_mac.verify(data, bytes(badmac)))
