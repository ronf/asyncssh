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

"""SSH compression handlers"""

import zlib

_cmp_algs = []
_cmp_compressors = {}
_cmp_decompressors = {}
_cmp_after_auth = {}

def _None():
    """Compressor/decompressor for no compression."""

    return None

class _ZLibCompress:
    """Wrapper class to force a sync flush when compressing"""

    def __init__(self):
        self._comp = zlib.compressobj()

    def compress(self, data):
        return self._comp.compress(data) + self._comp.flush(zlib.Z_SYNC_FLUSH)

def register_compression_alg(alg, compressor, decompressor, after_auth):
    """Register a compression algorithm"""

    _cmp_algs.append(alg)
    _cmp_compressors[alg] = compressor
    _cmp_decompressors[alg] = decompressor
    _cmp_after_auth[alg] = after_auth

def get_compression_algs():
    """Return a list of available compression algorithms"""

    return _cmp_algs

def lookup_compression_alg(alg):
    """Look up a compression algorithm

       This function looks up a compression algorithm and returns whether
       or not compression should be delayed until after authentication.

    """

    return _cmp_after_auth[alg]

def get_compressor(alg):
    """Return an instance of a compressor

       This function returns an object that can be used for data compression.

    """

    return _cmp_compressors[alg]()

def get_decompressor(alg):
    """Return an instance of a decompressor

       This function returns an object that can be used for data decompression.

    """

    return _cmp_decompressors[alg]()

register_compression_alg(b'zlib@openssh.com',
                         _ZLibCompress, zlib.decompressobj, True)
register_compression_alg(b'zlib',
                         _ZLibCompress, zlib.decompressobj, False)
register_compression_alg(b'none',
                         _None,         _None,              False)
