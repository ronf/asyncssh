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
                packet = os.urandom(256)

                enc_mac = get_mac(alg, key)
                dec_mac = get_mac(alg, key)

                badpacket = bytearray(packet)
                badpacket[-1] ^= 0xff

                mac = enc_mac.sign(0, packet)

                badmac = bytearray(mac)
                badmac[-1] ^= 0xff

                self.assertTrue(dec_mac.verify(0, packet, mac))
                self.assertFalse(dec_mac.verify(0, bytes(badpacket), mac))
                self.assertFalse(dec_mac.verify(0, packet, bytes(badmac)))

    def test_umac_wrapper(self):
        """Unit test some unused parts of the UMAC wrapper code"""

        try:
            from asyncssh.crypto import umac32
        except ImportError: # pragma: no cover
            self.skipTest('umac not available')

        key = os.urandom(16)

        mac1 = umac32(key)
        mac1.update(b'test')

        mac2 = mac1.copy()

        mac1.update(b'123')
        mac2.update(b'123')

        self.assertEqual(mac1.hexdigest(), mac2.hexdigest())
