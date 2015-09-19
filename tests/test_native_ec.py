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

"""Unit tests for native Python elliptic curve implementation"""

import unittest

from asyncssh.crypto.ec import PrimePoint, register_prime_curve
from asyncssh.crypto.ec import decode_ec_point, encode_ec_point
from asyncssh.crypto.ec import get_ec_curve_params, lookup_ec_curve_by_params
from asyncssh.crypto.ecdh import ECDH

# Short variable names are used here, matching names in the specs
# pylint: disable=invalid-name


class _TestNativeEC(unittest.TestCase):
    """Unit tests for native Python elliptic curve modules"""

    def test_register_errors(self):
        """Unit test of native Python EC registration errors"""

        G, n = get_ec_curve_params(b'nistp256')
        p, a, b, Gx, Gy = G.curve.p, G.curve.a, G.curve.b, G.x, G.y

        with self.subTest('Bad prime'):
            with self.assertRaises(ValueError):
                register_prime_curve(b'bad', p+1, a, b, Gx, Gy, n)

        with self.subTest('Bad a, b pair'):
            with self.assertRaises(ValueError):
                register_prime_curve(b'bad', p, a+1, b, Gx, Gy, n)

        with self.subTest('Bad generator point'):
            with self.assertRaises(ValueError):
                register_prime_curve(b'bad', p, a, b, Gx+1, Gy, n)

        with self.subTest('Bad order'):
            with self.assertRaises(ValueError):
                register_prime_curve(b'bad', p, a, b, Gx, Gy, n+1)

        with self.subTest('Weak prime'):
            with self.assertRaises(ValueError):
                register_prime_curve(b'bad', 263, 2, 3, 200, 39, 270)

    def test_get_params(self):
        """Test errors getting EC curve params"""

        with self.subTest('Get params'):
            with self.assertRaises(ValueError):
                get_ec_curve_params(b'xxx')

    def test_lookup_by_params(self):
        """Test errors in EC curve lookup by params"""

        G, n = get_ec_curve_params(b'nistp256')

        with self.subTest('Bad curve'):
            with self.assertRaises(ValueError):
                lookup_ec_curve_by_params(G.curve.p+1, G.curve.a, G.curve.b,
                                          G.encode(), n)

        with self.subTest('Unknown curve'):
            with self.assertRaises(ValueError):
                lookup_ec_curve_by_params(263, 2, 3,
                                          encode_ec_point(2, 200, 39), 270)

    def test_encode(self):
        """Unit test native Python EC point encoding"""

        G, _ = get_ec_curve_params(b'nistp256')

        with self.subTest('Encode infinity'):
            self.assertEqual(encode_ec_point(None, None, None), b'\x00')

        with self.subTest('Decode infinity'):
            point = PrimePoint.decode(G.curve, b'\x00')
            self.assertEqual((point.curve, point.x, point.y),
                             (None, None, None))

        with self.subTest('Encode and decode'):
            self.assertEqual(PrimePoint.decode(G.curve, G.encode()), G)

        with self.subTest('Bad point type'):
            with self.assertRaises(ValueError):
                decode_ec_point(0, b'\x05')

        with self.subTest('Bad point length'):
            with self.assertRaises(ValueError):
                decode_ec_point(G.curve.keylen, G.encode()[:-1])

    def test_math(self):
        """Unit test native Python EC point math"""

        G, n = get_ec_curve_params(b'nistp256')
        G2, _ = get_ec_curve_params(b'nistp521')
        Inf = PrimePoint.construct(G.curve, None, None)

        with self.subTest('Add to infinity'):
            self.assertEqual(G + Inf, G)

        with self.subTest('Negate'):
            negG = -G
            self.assertEqual(-negG, G)

        with self.subTest('Negate infinity'):
            self.assertEqual(-Inf, Inf)

        with self.subTest('Multiply returning infinity'):
            self.assertEqual(n * G, Inf)

        with self.subTest('Add from different curves'):
            with self.assertRaises(ValueError):
                _ = G + G2

    def test_ecdh(self):
        """Unit test native Python implementation of ECDH key exchange"""

        for curve_id in (b'nistp256', b'nistp384', b'nistp521'):
            client_priv = ECDH(curve_id)
            server_priv = ECDH(curve_id)

            client_pub = client_priv.get_public()
            server_pub = server_priv.get_public()

            client_k = client_priv.get_shared(server_pub)
            server_k = server_priv.get_shared(client_pub)

            self.assertEqual(client_k, server_k)
