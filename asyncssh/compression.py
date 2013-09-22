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

"""SSH compression handlers"""

import zlib

from .constants import *
from .misc import *
from .packet import *

_cmp_algs = []
_cmp_compressors = {}
_cmp_decompressors = {}
_cmp_after_auth = {}

def _None():
    """Compressor/decompressor for no compression."""

    return None

class _ZLibCompress:
    """Wrapper class to force a sync flush when compressing."""

    def __init__(self):
        self._comp = zlib.compressobj()

    def compress(self, data):
        return self._comp.compress(data) + self._comp.flush(zlib.Z_SYNC_FLUSH)

def register_compression_algorithm(alg, compressor, decompressor, after_auth):
    """Register a compression algorithm"""

    _cmp_algs.append(alg)
    _cmp_compressors[alg] = compressor
    _cmp_decompressors[alg] = decompressor
    _cmp_after_auth[alg] = after_auth

def get_compression_algs():
    """Return a list of available compression algorithms"""

    return _cmp_algs

def choose_compression_algorithm(conn, peer_cmp_algs):
    """Choose the compression algorithm to use
    
       This function returns the compression algorithm to use.
    """

    if conn.is_client():
        client_algs = _cmp_algs
        server_algs = peer_cmp_algs
    else:
        client_algs = peer_cmp_algs
        server_algs = _cmp_algs

    for alg in client_algs:
        if alg in server_algs:
            return alg, _cmp_after_auth[alg]

    raise SSHError(DISC_KEY_EXCHANGE_FAILED,
                   b'No matching compression algorithm found')

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

register_compression_algorithm(b'zlib@openssh.com',
                               _ZLibCompress, zlib.decompressobj, True)
register_compression_algorithm(b'zlib',
                               _ZLibCompress, zlib.decompressobj, False)
register_compression_algorithm(b'none', _None,         _None,     False)
