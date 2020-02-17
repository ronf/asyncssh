# Copyright (c) 2019-2020 by Ron Frederick <ronf@timeheart.net> and others.
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

from hashlib import sha256
import time

_CTAP1_POLL_INTERVAL = 0.1

_dummy_hash = 32 * b'\0'

# Flags
SSH_SK_USER_PRESENCE_REQD = 0x01

# Algorithms
SSH_SK_ECDSA = -7
SSH_SK_ED25519 = -8


def _ctap1_poll(poll_interval, func, *args):
    """Poll until a CTAP1 response is received"""

    while True:
        try:
            return func(*args)
        except ApduError as exc:
            if exc.code != APDU.USE_NOT_SATISFIED:
                raise

            time.sleep(poll_interval)


def _ctap1_enroll(dev, alg, application):
    """Enroll a new security key using CTAP version 1"""

    ctap1 = CTAP1(dev)

    if alg != SSH_SK_ECDSA:
        raise ValueError('Unsupported algorithm') from None

    app_hash = sha256(application).digest()
    registration = _ctap1_poll(_CTAP1_POLL_INTERVAL, ctap1.register,
                               _dummy_hash, app_hash)

    return registration.public_key, registration.key_handle


def _ctap2_enroll(dev, alg, application):
    """Enroll a new security key using CTAP version 2"""

    ctap2 = CTAP2(dev)

    application = application.decode()
    rp = {'id': application, 'name': application}
    user = {'id': b'AsyncSSH', 'name': 'AsyncSSH'}
    key_params = [{'type': 'public-key', 'alg': alg}]

    cred = ctap2.make_credential(_dummy_hash, rp, user, key_params)
    cdata = cred.auth_data.credential_data

    if alg == SSH_SK_ED25519:
        public_key = cdata.public_key[-2]
    else:
        public_key = b'\x04' + cdata.public_key[-2] + cdata.public_key[-3]

    return public_key, cdata.credential_id


def _ctap1_sign(dev, message_hash, application, key_handle):
    """Sign a message with a security key using CTAP version 1"""

    ctap1 = CTAP1(dev)

    app_hash = sha256(application).digest()

    auth_response = _ctap1_poll(_CTAP1_POLL_INTERVAL, ctap1.authenticate,
                                message_hash, app_hash, key_handle)

    flags = auth_response[0]
    counter = int.from_bytes(auth_response[1:5], 'big')
    sig = auth_response[5:]

    return flags, counter, sig


def _ctap2_sign(dev, message_hash, application, key_handle, touch_required):
    """Sign a message with a security key using CTAP version 2"""

    ctap2 = CTAP2(dev)

    application = application.decode()
    allow_creds = [{'type': 'public-key', 'id': key_handle}]
    options = {'up': touch_required}

    assertion = ctap2.get_assertions(application, message_hash,
                                     allow_creds, options=options)[0]

    auth_data = assertion.auth_data

    return auth_data.flags, auth_data.counter, assertion.signature


def sk_enroll(alg, application):
    """Enroll a new security key"""

    dev = next(CtapHidDevice.list_devices(), None)

    if not dev:
        raise ValueError('No security key found')

    try:
        return _ctap2_enroll(dev, alg, application)
    except CtapError as exc:
        raise ValueError(str(exc)) from None
    except ValueError:
        try:
            return _ctap1_enroll(dev, alg, application)
        except ApduError as exc:
            raise ValueError(str(exc)) from None
    finally:
        dev.close()


def sk_sign(message_hash, application, key_handle, flags):
    """Sign a message with a security key"""

    touch_required = bool(flags & SSH_SK_USER_PRESENCE_REQD)

    for dev in CtapHidDevice.list_devices():
        try:
            return _ctap2_sign(dev, message_hash, application,
                               key_handle, touch_required)
        except CtapError as exc:
            if exc.code != CtapError.ERR.NO_CREDENTIALS:
                raise ValueError(str(exc)) from None
        except ValueError:
            try:
                return _ctap1_sign(dev, message_hash, application, key_handle)
            except ApduError as exc:
                if exc.code != APDU.WRONG_DATA:
                    raise ValueError(str(exc)) from None
        finally:
            dev.close()

    raise ValueError('Security key credential not found')


try:
    from fido2.hid import CtapHidDevice
    from fido2.ctap import CtapError
    from fido2.ctap1 import CTAP1, APDU, ApduError
    from fido2.ctap2 import CTAP2

    sk_available = True
except (ImportError, OSError, AttributeError): # pragma: no cover
    sk_available = False
