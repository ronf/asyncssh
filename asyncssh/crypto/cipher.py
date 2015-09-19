# Copyright (c) 2014-2015 by Ron Frederick <ronf@timeheart.net>.
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

"""A shim for accessing symmetric ciphers needed by asyncssh"""

_ciphers = {}


def register_cipher(cipher_name, mode_name, cipher):
    """Register a symmetric cipher

       If multiple modules try to register the same cipher and mode, the
       first one to register it is used.

    """

    if (cipher_name, mode_name) not in _ciphers: # pragma: no branch
        cipher.cipher_name = cipher_name
        cipher.mode_name = mode_name
        _ciphers[cipher_name, mode_name] = cipher


def lookup_cipher(cipher_name, mode_name):
    """Look up a symmetric cipher"""

    return _ciphers.get((cipher_name, mode_name))
