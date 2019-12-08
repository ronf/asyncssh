# Copyright (c) 2019 by Ron Frederick <ronf@timeheart.net> and others.
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
#     Georg Sauthoff - fix for "setup.py test" command on non-Windows

"""Stub U2F security key module for unit tests"""

from hashlib import sha256

from unittest.mock import patch

from asyncssh.asn1 import der_decode, der_encode
from asyncssh.crypto import ECDSAPrivateKey, EdDSAPrivateKey
from asyncssh.packet import Byte, UInt32
from asyncssh.sk import SSH_SK_ECDSA


def sk_enroll_stub(alg, challenge, application, flags):
    """Enroll a new security key"""

    # pylint: disable=unused-argument

    if alg == SSH_SK_ECDSA:
        key = ECDSAPrivateKey.generate(b'nistp256')
    else:
        key = EdDSAPrivateKey.generate(b'ed25519')

    key_handle = der_encode((alg, key.public_value, key.private_value))

    return key.public_value, key_handle, b'', b''


def sk_sign_stub(alg, message_hash, application, key_handle, flags):
    """Sign a message with a security key"""

    alg, public_value, private_value = der_decode(key_handle)

    if alg == SSH_SK_ECDSA:
        key = ECDSAPrivateKey.construct(b'nistp256', public_value,
                                        int.from_bytes(private_value, 'big'))
    else:
        key = EdDSAPrivateKey.construct(b'ed25519', private_value)

    counter = 0x12345678

    sig = key.sign(sha256(application).digest() + Byte(flags) +
                   UInt32(counter) + message_hash)

    if alg == SSH_SK_ECDSA:
        r, s = der_decode(sig)
        r = r.to_bytes(32, 'big')
        s = s.to_bytes(32, 'big')
    else:
        r = sig
        s = b''

    return flags, counter, r, s


def patch_sk(cls):
    """Decorator for patching U2F security key handlers"""

    cls = patch('asyncssh.sk_ecdsa.sk_enroll', sk_enroll_stub)(cls)
    cls = patch('asyncssh.sk_ecdsa.sk_sign', sk_sign_stub)(cls)

    cls = patch('asyncssh.sk_eddsa.sk_enroll', sk_enroll_stub)(cls)
    cls = patch('asyncssh.sk_eddsa.sk_sign', sk_sign_stub)(cls)

    return cls
