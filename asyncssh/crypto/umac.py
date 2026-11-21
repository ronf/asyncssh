# Copyright (c) 2016-2024 by Ron Frederick <ronf@timeheart.net> and others.
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

"""UMAC cryptographic hash (RFC 4418) wrapper for Nettle library"""

import binascii
import ctypes
import ctypes.util
import os
import sys
from typing import TYPE_CHECKING, Callable, Optional


if TYPE_CHECKING:
    _ByteArray = ctypes.Array[ctypes.c_char]
    _SetKey = Callable[[_ByteArray, bytes], None]
    _SetNonce = Callable[[_ByteArray, ctypes.c_size_t, bytes], None]
    _Update = Callable[[_ByteArray, ctypes.c_size_t, bytes], None]
    _Digest3 = Callable[[_ByteArray, ctypes.c_size_t, _ByteArray], None]
    _Digest4 = Callable[[_ByteArray, _ByteArray], None]
    _New = Callable[[bytes, Optional[bytes], Optional[bytes]], object]


_UMAC_BLOCK_SIZE = 1024
_UMAC_DEFAULT_CTX_SIZE = 4096


def _build_umac(size: int) -> '_New':
    """Function to build UMAC wrapper for a specific digest size"""

    _name = f'umac{size}'
    _prefix = f'nettle_{_name}_'

    try:
        _context_size: int = getattr(_nettle, _prefix + '_ctx_size')()
    except AttributeError:
        _context_size = _UMAC_DEFAULT_CTX_SIZE

    _set_key: _SetKey = getattr(_nettle, _prefix + 'set_key')
    _set_nonce: _SetNonce = getattr(_nettle, _prefix + 'set_nonce')
    _update: _Update = getattr(_nettle, _prefix + 'update')
    _digest = getattr(_nettle, _prefix + 'digest')


    class _UMAC:
        """Wrapper for UMAC cryptographic hash

           This class supports the cryptographic hash API defined in PEP 452.

        """

        name = _name
        block_size = _UMAC_BLOCK_SIZE
        digest_size = size // 8

        def __init__(self, ctx: '_ByteArray', nonce: Optional[bytes] = None,
                     msg: Optional[bytes] = None):
            self._ctx = ctx

            if nonce:
                self.set_nonce(nonce)

            if msg:
                self.update(msg)

        @classmethod
        def new(cls, key: bytes, msg: Optional[bytes] = None,
                nonce: Optional[bytes] = None) -> '_UMAC':
            """Construct a new UMAC hash object"""

            ctx = ctypes.create_string_buffer(_context_size)
            _set_key(ctx, key)

            return cls(ctx, nonce, msg)

        def copy(self) -> '_UMAC':
            """Return a new hash object with this object's state"""

            ctx = ctypes.create_string_buffer(self._ctx.raw)
            return self.__class__(ctx)

        def set_nonce(self, nonce: bytes) -> None:
            """Reset the nonce associated with this object"""

            _set_nonce(self._ctx, ctypes.c_size_t(len(nonce)), nonce)

        def update(self, msg: bytes) -> None:
            """Add the data in msg to the hash"""

            _update(self._ctx, ctypes.c_size_t(len(msg)), msg)

        def digest(self) -> bytes:
            """Return the hash and increment nonce to begin a new message

               .. note:: The hash is reset and the nonce is incremented
                         when this function is called. This doesn't match
                         the behavior defined in PEP 452.

            """

            result = ctypes.create_string_buffer(self.digest_size)

            if _nettle_version == 4:
                digest4: _Digest4 = _digest
                digest4(self._ctx, result)
            else:
                digest3: _Digest3 = _digest
                digest3(self._ctx, ctypes.c_size_t(self.digest_size), result)

            return result.raw

        def hexdigest(self) -> str:
            """Return the digest as a string of hexadecimal digits"""

            return binascii.b2a_hex(self.digest()).decode('ascii')


    return _UMAC.new


_NETTLE_LIBS = ('nettle-9', 'nettle-8', 'nettle',
                'libnettle-9', 'libnettle-8', 'libnettle')

_NETTLE_SONAMES = {'darwin': ('libnettle.9.dylib', 'libnettle.8.dylib'),
                   'linux': ('libnettle.so.9', 'libnettle.so.8')}

_nettle: Optional[ctypes.CDLL] = None

if sys.platform == 'win32':
    for lib in _NETTLE_LIBS: # pragma: no branch
        try:
            _nettle = ctypes.CDLL(lib)
            break
        except OSError: # pragma: no cover
            pass
elif sys.platform in _NETTLE_SONAMES: # pragma: no branch
    for prefix in dict.fromkeys((sys.prefix, sys.base_prefix)):
        for lib in _NETTLE_SONAMES[sys.platform]:
            try:
                _nettle = ctypes.CDLL(os.path.join(prefix, 'lib', lib))
                break
            except OSError:
                pass

        if _nettle:
            break

if not _nettle:
    for lib in _NETTLE_LIBS:
        _nettle_lib = ctypes.util.find_library(lib)

        if _nettle_lib: # pragma: no branch
            break
    else: # pragma: no cover
        _nettle_lib = None

    if _nettle_lib: # pragma: no branch
        _nettle = ctypes.cdll.LoadLibrary(_nettle_lib)

if _nettle: # pragma: no branch
    try:
        _nettle_version: int = _nettle.nettle_version_major()
    except AttributeError: # pragma: no cover
        _nettle_version = 3

    if _nettle_version <= 4: # pragma: no branch
        umac32, umac64, umac96, umac128 = map(_build_umac, (32, 64, 96, 128))
