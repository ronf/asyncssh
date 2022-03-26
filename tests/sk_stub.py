# Copyright (c) 2019-2022 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Stub U2F security key module for unit tests"""

from contextlib import contextmanager
from hashlib import sha256

import asyncssh
from asyncssh.asn1 import der_encode, der_decode
from asyncssh.crypto import ECDSAPrivateKey, EdDSAPrivateKey
from asyncssh.packet import Byte, UInt32
from asyncssh.sk import sk_available

if sk_available: # pragma: no branch
    from asyncssh.sk import SSH_SK_ECDSA, SSH_SK_ED25519
    from asyncssh.sk import SSH_SK_USER_PRESENCE_REQD
    from asyncssh.sk import APDU, ApduError, CtapError


class _Registration:
    """Security key registration data"""

    def __init__(self, public_key, key_handle):
        self.public_key = public_key
        self.key_handle = key_handle


class _AuthData:
    """Security key authentication data"""

    def __init__(self, flags, counter):
        self.flags = flags
        self.counter = counter


class _Assertion:
    """Security key assertion"""

    def __init__(self, auth_data, signature):
        self.auth_data = auth_data
        self.signature = signature


class _CredentialData:
    """Security key credential data"""

    def __init__(self, alg, public_value, key_handle):
        if alg == SSH_SK_ED25519:
            self.public_key = {-2: public_value}
        else:
            self.public_key = {-2: public_value[1:33], -3: public_value[33:]}

        self.public_key[3] = alg
        self.credential_id = key_handle


class _CredentialAuthData:
    """Security key credential authentication data"""

    def __init__(self, credential_data):
        self.credential_data = credential_data


class _Credential:
    """Security key credential"""

    def __init__(self, auth_data):
        self.auth_data = auth_data


class _CtapStub:
    """Stub for unit testing U2F security key support"""

    _version = None

    def __init__(self, dev):
        if dev.version != self._version:
            raise ValueError('Wrong protocol version')

        self.dev = dev

    @staticmethod
    def _enroll(alg):
        """Enroll a new security key"""

        if alg == SSH_SK_ECDSA:
            key = ECDSAPrivateKey.generate(b'nistp256')
        else:
            key = EdDSAPrivateKey.generate(b'ed25519')

        key_handle = der_encode((alg, key.public_value, key.private_value))

        return key.public_value, key_handle

    @staticmethod
    def _sign(message_hash, app_hash, key_handle, flags):
        """Sign a message with a security key"""

        alg, public_value, private_value = der_decode(key_handle)

        if alg == SSH_SK_ECDSA:
            key = ECDSAPrivateKey.construct(
                b'nistp256', public_value, int.from_bytes(private_value, 'big'))
            hash_alg = 'sha256'
        else:
            key = EdDSAPrivateKey.construct(b'ed25519', private_value)
            hash_alg = None

        counter = 0x12345678

        sig = key.sign(app_hash + Byte(flags) + UInt32(counter) +
                       message_hash, hash_alg)

        return flags, counter, sig


class Ctap1(_CtapStub):
    """Stub for unit testing U2F security keys using CTAP version 1"""

    _version = 1

    def __init__(self, dev):
        super().__init__(dev)

        self._polled = False

    def _poll(self):
        """Simulate needing to poll the security device"""

        if not self._polled:
            self._polled = True
            raise ApduError(APDU.USE_NOT_SATISFIED, b'')

    def register(self, client_data_hash, app_hash):
        """Enroll a new security key using CTAP version 1"""

        # pylint: disable=unused-argument

        self._poll()

        if self.dev.error == 'err':
            raise ApduError(0, b'')

        public_key, key_handle = self._enroll(SSH_SK_ECDSA)

        return _Registration(public_key, key_handle)

    def authenticate(self, message_hash, app_hash, key_handle):
        """Sign a message with a security key using CTAP version 1"""

        self._poll()

        if self.dev.error == 'nocred':
            raise ApduError(APDU.WRONG_DATA, b'')
        elif self.dev.error == 'err':
            raise ApduError(0, b'')

        flags, counter, sig = self._sign(message_hash, app_hash,
                                         key_handle, SSH_SK_USER_PRESENCE_REQD)

        return Byte(flags) + UInt32(counter) + sig


class Ctap2(_CtapStub):
    """Stub for unit testing U2F security keys using CTAP version 2"""

    _version = 2

    def make_credential(self, client_data_hash, rp, user, key_params,
                        options, pin_uv_param, pin_uv_protocol):
        """Enroll a new security key using CTAP version 2"""

        # pylint: disable=unused-argument

        alg = key_params[0]['alg']

        if self.dev.error == 'err':
            raise CtapError(CtapError.ERR.INVALID_CREDENTIAL)
        elif self.dev.error == 'pinreq':
            raise CtapError(CtapError.ERR.PUAT_REQUIRED)
        elif self.dev.error == 'badpin':
            raise CtapError(CtapError.ERR.PIN_INVALID)

        public_key, key_handle = self._enroll(alg)

        cdata = _CredentialData(alg, public_key, key_handle)

        if options.get('rk'):
            cred_mgmt = CredentialManagement(self)

            cred_mgmt.add_resident_key(user['name'], cdata)

        return _Credential(_CredentialAuthData(cdata))

    def get_assertions(self, application, message_hash, allow_creds, options):
        """Sign a message with a security key using CTAP version 2"""

        app_hash = sha256(application.encode()).digest()
        key_handle = allow_creds[0]['id']
        flags = SSH_SK_USER_PRESENCE_REQD if options['up'] else 0

        if self.dev.error == 'nocred':
            raise CtapError(CtapError.ERR.NO_CREDENTIALS)
        elif self.dev.error == 'err':
            raise CtapError(CtapError.ERR.INVALID_CREDENTIAL)

        flags, counter, sig = self._sign(message_hash, app_hash,
                                         key_handle, flags)

        return [_Assertion(_AuthData(flags, counter), sig)]


class CredentialManagement:
    """Stub for unit testing U2F security device resident keys"""

    class RESULT:
        """Credential management result keys"""

        USER = 6
        CREDENTIAL_ID = 7
        PUBLIC_KEY = 8

    def __init__(self, ctap, pin_uv_protocol=None, pin_uv_token=None):
        # pylint: disable=unused-argument

        self.dev = ctap.dev

        if self.dev.error == 'err':
            raise CtapError(CtapError.ERR.INVALID_CREDENTIAL)
        elif self.dev.error == 'nocred':
            raise CtapError(CtapError.ERR.NO_CREDENTIALS)
        elif self.dev.error == 'nopin':
            raise CtapError(CtapError.ERR.PIN_NOT_SET)
        elif self.dev.error == 'badpin':
            raise CtapError(CtapError.ERR.PIN_INVALID)

    def enumerate_creds(self, app_hash):
        """Enumerate resident credentials"""

        # pylint: disable=unused-argument

        return self.dev.resident_keys

    def add_resident_key(self, user, cdata):
        """Add a resident key to a device"""

        self.dev.resident_keys.append(
            {self.RESULT.USER: {'id': b'', 'name': user, 'displayName': user},
             self.RESULT.CREDENTIAL_ID: {'id': cdata.credential_id},
             self.RESULT.PUBLIC_KEY: cdata.public_key})


class Device:
    """Stub for unit testing U2F security devices"""

    def __init__(self, version):
        self.version = version
        self.error = None
        self.resident_keys = []

    def close(self):
        """Close this security device"""


class ClientPin:
    """Stub for unit testing U2F security device PINs"""

    def __init__(self, ctap, protocol):
        # pylint: disable=unused-argument
        pass

    def get_pin_token(self, pin):
        """Return a PIN token"""

        # pylint: disable=no-self-use

        return pin


class PinProtocolV1:
    """Stub for unit testing U2F pin protocol version 1"""

    VERSION = 1


def stub_sk(devices):
    """Stub out security key module functions for unit testing"""

    devices = list(map(Device, devices))

    old_ctap1 = asyncssh.sk.Ctap1
    old_ctap2 = asyncssh.sk.Ctap2
    old_client_pin = asyncssh.sk.ClientPin
    old_cred_mgmt = asyncssh.sk.CredentialManagement
    old_pin_proto = asyncssh.sk.PinProtocolV1
    old_list_devices = asyncssh.sk.CtapHidDevice.list_devices

    asyncssh.sk.Ctap1 = Ctap1
    asyncssh.sk.Ctap2 = Ctap2
    asyncssh.sk.ClientPin = ClientPin
    asyncssh.sk.CredentialManagement = CredentialManagement
    asyncssh.sk.PinProtocolV1 = PinProtocolV1
    asyncssh.sk.CtapHidDevice.list_devices = lambda: iter(devices)

    return old_ctap1, old_ctap2, old_client_pin, \
        old_cred_mgmt, old_pin_proto, old_list_devices


def unstub_sk(old_ctap1, old_ctap2, old_client_pin, old_cred_mgmt,
              old_pin_proto, old_list_devices):
    """Restore security key module functions"""

    asyncssh.sk.Ctap1 = old_ctap1
    asyncssh.sk.Ctap2 = old_ctap2
    asyncssh.sk.ClientPin = old_client_pin
    asyncssh.sk.CredentialManagement = old_cred_mgmt
    asyncssh.sk.PinProtocolV1 = old_pin_proto
    asyncssh.sk.CtapHidDevice.list_devices = old_list_devices

@contextmanager
def patch_sk(devices):
    """Context manager to stub out security key functions"""

    old_sk_hooks = stub_sk(devices)

    try:
        yield
    finally:
        unstub_sk(*old_sk_hooks)


@contextmanager
def sk_error(err):
    """Set security key error condition"""

    try:
        for dev in asyncssh.sk.CtapHidDevice.list_devices():
            dev.error = err

        yield
    finally:
        for dev in asyncssh.sk.CtapHidDevice.list_devices():
            dev.error = None
