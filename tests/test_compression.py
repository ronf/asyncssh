# Copyright (c) 2015-2018 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Unit tests for compression"""

import os
import unittest

from asyncssh.compression import get_compression_algs, get_compression_params
from asyncssh.compression import get_compressor, get_decompressor


class TestCompression(unittest.TestCase):
    """Unit tests for compression module"""

    def test_compression_algs(self):
        """Unit test compression algorithms"""

        for alg in get_compression_algs():
            with self.subTest(alg=alg):
                get_compression_params(alg)

                data = os.urandom(256)

                compressor = get_compressor(alg)
                decompressor = get_decompressor(alg)

                if compressor:
                    cmpdata = compressor.compress(data)
                    self.assertEqual(decompressor.decompress(cmpdata), data)
