# Copyright (c) 2016 by Ron Frederick <ronf@timeheart.net>.
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

"""UMAC cryptographic hash (RFC 4418) wrapper for Nettle library"""

import binascii
import ctypes
import ctypes.util
import sys


_UMAC_BLOCK_SIZE = 1024
_UMAC_DEFAULT_CTX_SIZE = 4096


def __build_umac(size):
    """Function to build UMAC wrapper for a specific digest size"""

    _name = 'umac%d' % size
    _prefix = 'nettle_%s_' % _name

    try:
        _context_size = getattr(_nettle, _prefix + '_ctx_size')()
    except AttributeError:
        _context_size = _UMAC_DEFAULT_CTX_SIZE

    _set_key = getattr(_nettle, _prefix + 'set_key')
    _set_nonce = getattr(_nettle, _prefix + 'set_nonce')
    _update = getattr(_nettle, _prefix + 'update')
    _digest = getattr(_nettle, _prefix + 'digest')


    class _UMAC:
        """Wrapper for UMAC cryptographic hash

           This class supports the cryptographic hash API defined in PEP 452.

        """

        name = _name
        block_size = _UMAC_BLOCK_SIZE
        digest_size = size // 8

        def __init__(self, ctx, nonce=None, msg=None):
            self._ctx = ctx

            if nonce:
                self.set_nonce(nonce)

            if msg:
                self.update(msg)

        @classmethod
        def new(cls, key, msg=None, nonce=None):
            """Construct a new UMAC hash object"""

            ctx = ctypes.create_string_buffer(_context_size)
            _set_key(ctx, key)

            return cls(ctx, nonce, msg)

        def copy(self):
            """Return a new hash object with this object's state"""

            ctx = ctypes.create_string_buffer(self._ctx.raw)
            return self.__class__(ctx)

        def set_nonce(self, nonce):
            """Reset the nonce associated with this object"""

            _set_nonce(self._ctx, ctypes.c_size_t(len(nonce)), nonce)

        def update(self, msg):
            """Add the data in msg to the hash"""

            _update(self._ctx, ctypes.c_size_t(len(msg)), msg)

        def digest(self):
            """Return the hash and increment nonce to begin a new message

               .. note:: The hash is reset and the nonce is incremented
                         when this function is called. This doesn't match
                         the behavior defined in PEP 452.

            """

            result = ctypes.create_string_buffer(self.digest_size)
            _digest(self._ctx, ctypes.c_size_t(self.digest_size), result)
            return result.raw

        def hexdigest(self):
            """Return the digest as a string of hexadecimal digits"""

            return binascii.b2a_hex(self.digest()).decode('ascii')


    globals()[_name] = _UMAC.new


digest_size = None

if sys.platform == 'win32': # pragma: no cover
    _nettle = ctypes.cdll.LoadLibrary('libnettle-6')
else:
    _nettle = ctypes.cdll.LoadLibrary(ctypes.util.find_library('nettle'))

for _size in (32, 64, 96, 128):
    __build_umac(_size)
