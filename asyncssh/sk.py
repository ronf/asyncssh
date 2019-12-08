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

"""U2F security key handler"""

from ctypes import CDLL, POINTER, Structure, byref
from ctypes import c_char, c_size_t, c_uint8, c_uint32

import os

# Flags
SSH_SK_USER_PRESENCE_REQD = 0x01

# Algorithms
SSH_SK_ECDSA = 0
SSH_SK_ED25519 = 1


class SKEnrollResponse(Structure):
    """A security key enrollment response"""

    _fields_ = (('public_key', POINTER(c_char)),
                ('public_key_len', c_size_t),
                ('key_handle', POINTER(c_char)),
                ('key_handle_len', c_size_t),
                ('signature', POINTER(c_char)),
                ('signature_len', c_size_t),
                ('attestation_cert', POINTER(c_char)),
                ('attestation_cert_len', c_size_t))


class SKSignResponse(Structure):
    """A security key sign response"""

    _fields_ = (('flags', c_uint8),
                ('counter', c_uint32),
                ('sig_r', POINTER(c_char)),
                ('sig_r_len', c_size_t),
                ('sig_s', POINTER(c_char)),
                ('sig_s_len', c_size_t))


def sk_enroll(alg, challenge, application, flags): # pragma: no cover
    """Enroll a new security key"""

    if not sk:
        raise ValueError('Security key provider not available')

    response_ptr = POINTER(SKEnrollResponse)()

    result = sk.sk_enroll(alg, challenge, c_size_t(len(challenge)),
                          application, c_uint8(flags), byref(response_ptr))

    if result < 0:
        raise ValueError('Enrollment failed')

    response = response_ptr.contents

    public_key = response.public_key[:response.public_key_len]
    key_handle = response.key_handle[:response.key_handle_len]
    signature = response.signature[:response.signature_len]
    att_cert = response.attestation_cert[:response.attestation_cert_len]

    sk.free(response.public_key)
    sk.free(response.key_handle)
    sk.free(response.signature)
    sk.free(response.attestation_cert)
    sk.free(response_ptr)

    return public_key, key_handle, signature, att_cert


def sk_sign(alg, message_hash, application,
            key_handle, flags): # pragma: no cover
    """Sign a message with a security key"""

    if not sk:
        raise ValueError('Security key provider not available')

    response_ptr = POINTER(SKSignResponse)()

    result = sk.sk_sign(alg, message_hash, c_size_t(len(message_hash)),
                        application, key_handle, c_size_t(len(key_handle)),
                        c_uint8(flags), byref(response_ptr))

    if result < 0:
        raise ValueError('Signing failed')

    response = response_ptr.contents

    flags = response.flags
    counter = response.counter
    sig_r = response.sig_r[:response.sig_r_len]
    sig_s = response.sig_s[:response.sig_s_len]

    sk.free(response.sig_r)
    sk.free(response.sig_s)
    sk.free(response_ptr)

    return flags, counter, sig_r, sig_s


_sk_lib = os.environ.get('SSH_SK_PROVIDER') or 'libsk-libfido2.so'

try:
    sk = CDLL(_sk_lib)
except OSError: # pragma: no cover
    sk = None
