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

"""Unit tests for AsyncSSH security key support"""

import unittest

import asyncssh

from .server import ServerTestCase
from .sk_stub import sk_available, stub_sk, unstub_sk, patch_sk, sk_error
from .util import asynctest, get_test_key


class _CheckSKAuth(ServerTestCase):
    """Common code for testing security key authentication"""

    _sk_devs = [2]
    _sk_alg = 'sk-ssh-ed25519@openssh.com'
    _sk_resident = False
    _sk_touch_required = True
    _sk_auth_touch_required = True
    _sk_cert = False
    _sk_host = False

    @classmethod
    async def start_server(cls):
        """Start an SSH server which supports security key authentication"""

        cls.addClassCleanup(unstub_sk, *stub_sk(cls._sk_devs))

        cls._privkey = get_test_key(
            cls._sk_alg, resident=cls._sk_resident,
            touch_required=cls._sk_touch_required)

        if cls._sk_host:
            if cls._sk_cert:
                cert = cls._privkey.generate_host_certificate(
                    cls._privkey, 'localhost', principals=['127.0.0.1'])

                key = (cls._privkey, cert)
            else:
                key = cls._privkey

            return await cls.create_server(server_host_keys=[key])
        else:
            options = []

            if cls._sk_cert:
                options.append('cert-authority')

            if not cls._sk_auth_touch_required:
                options.append('no-touch-required')

            auth_keys = asyncssh.import_authorized_keys(
                ','.join(options) + (' ' if options else '') +
                cls._privkey.export_public_key().decode('utf-8'))

            return await cls.create_server(authorized_client_keys=auth_keys)


@unittest.skipUnless(sk_available, 'security key support not available')
class _TestSKAuthKeyNotFound(ServerTestCase):
    """Unit tests for security key authentication with no key found"""

    @patch_sk([])
    @asynctest
    async def test_enroll_key_not_found(self):
        """Test generating key with no security key found"""

        with self.assertRaises(ValueError):
            asyncssh.generate_private_key('sk-ssh-ed25519@openssh.com')


@unittest.skipUnless(sk_available, 'security key support not available')
class _TestSKAuthCTAP1(_CheckSKAuth):
    """Unit tests for security key authentication with CTAP version 1"""

    _sk_devs = [1]
    _sk_alg = 'sk-ecdsa-sha2-nistp256@openssh.com'

    @asynctest
    async def test_auth(self):
        """Test authenticating with a CTAP 1 security key"""

        async with self.connect(username='ckey', client_keys=[self._privkey]):
            pass

    @asynctest
    async def test_sk_unsupported_alg(self):
        """Test unsupported security key algorithm"""

        with self.assertRaises(ValueError):
            asyncssh.generate_private_key('sk-ssh-ed25519@openssh.com')

    @asynctest
    async def test_enroll_ctap1_error(self):
        """Test generating key returning a CTAP 1 error"""

        with sk_error('err'):
            with self.assertRaises(ValueError):
                asyncssh.generate_private_key(self._sk_alg)

    @asynctest
    async def test_auth_ctap1_error(self):
        """Test security key returning a CTAP 1 error"""

        with sk_error('err'):
            with self.assertRaises(ValueError):
                await self.connect(username='ckey', client_keys=[self._privkey])


@unittest.skipUnless(sk_available, 'security key support not available')
class _TestSKAuthCTAP2(_CheckSKAuth):
    """Unit tests for security key authentication with CTAP version 2"""

    _sk_devs = [2]

    @asynctest
    async def test_auth(self):
        """Test authenticating with a CTAP 2 security key"""

        async with self.connect(username='ckey', client_keys=[self._privkey]):
            pass

    @asynctest
    async def test_enroll_without_pin(self):
        """Test generating key without a PIN"""

        key = get_test_key('sk-ssh-ed25519@openssh.com')

        self.assertIsNotNone(key)

    @asynctest
    async def test_enroll_with_pin(self):
        """Test generating key with a PIN"""

        key = get_test_key('sk-ssh-ed25519@openssh.com', pin=b'123456')

        self.assertIsNotNone(key)

    @asynctest
    async def test_enroll_ctap2_error(self):
        """Test generating key returning a CTAP 2 error"""

        with sk_error('err'):
            with self.assertRaises(ValueError):
                asyncssh.generate_private_key('sk-ssh-ed25519@openssh.com')

    @asynctest
    async def test_auth_ctap2_error(self):
        """Test security key returning a CTAP 2 error"""

        with sk_error('err'):
            with self.assertRaises(ValueError):
                await self.connect(username='ckey', client_keys=[self._privkey])

    @asynctest
    async def test_enroll_pin_invalid(self):
        """Test generating key while providing invalid PIN"""

        with sk_error('badpin'):
            with self.assertRaises(ValueError):
                asyncssh.generate_private_key('sk-ssh-ed25519@openssh.com',
                                              pin=b'123456')

    @asynctest
    async def test_enroll_pin_required(self):
        """Test generating key without providing a required PIN"""

        with sk_error('pinreq'):
            with self.assertRaises(ValueError):
                asyncssh.generate_private_key('sk-ssh-ed25519@openssh.com')


@unittest.skipUnless(sk_available, 'security key support not available')
class _TestSKAuthMultipleKeys(_CheckSKAuth):
    """Unit tests for security key authentication with multiple keys"""

    _sk_devs = [2, 1]

    @asynctest
    async def test_auth_cred_not_found(self):
        """Test authenticating with security credential not found"""

        with sk_error('nocred'):
            with self.assertRaises(ValueError):
                await self.connect(username='ckey', client_keys=[self._privkey])


@unittest.skipUnless(sk_available, 'security key support not available')
class _TestSKAuthResidentKeys(_CheckSKAuth):
    """Unit tests for loading resident keys"""

    _sk_resident = True

    @asynctest
    async def test_load_resident(self):
        """Test loading resident keys"""

        keys = asyncssh.load_resident_keys(b'123456')

        async with self.connect(username='ckey', client_keys=[keys[0]]):
            pass

    @asynctest
    async def test_load_resident_user_match(self):
        """Test loading resident keys matching a specific user"""

        keys = asyncssh.load_resident_keys(b'123456', user='AsyncSSH')

        async with self.connect(username='ckey', client_keys=[keys[0]]):
            pass

    @asynctest
    async def test_koad_resident_user_match(self):
        """Test loading resident keys matching a specific user"""

        self.assertIsNotNone(asyncssh.load_resident_keys(b'123456',
                                                         user='AsyncSSH'))

    @asynctest
    async def test_load_resident_no_match(self):
        """Test loading resident keys with no user match"""

        self.assertEqual(asyncssh.load_resident_keys(b'123456',
                                                     user='xxx'), [])

    @asynctest
    async def test_no_resident_keys(self):
        """Test retrieving empty list of resident keys"""

        with sk_error('nocred'):
            self.assertEqual(asyncssh.load_resident_keys(b'123456'), [])

    @asynctest
    async def test_load_resident_ctap2_error(self):
        """Test getting resident keys returning a CTAP 2 error"""

        with sk_error('err'):
            with self.assertRaises(ValueError):
                asyncssh.load_resident_keys(b'123456')

    @asynctest
    async def test_load_resident_pin_invalid(self):
        """Test getting resident keys while providing invalid PIN"""

        with sk_error('badpin'):
            with self.assertRaises(ValueError):
                asyncssh.load_resident_keys(b'123456')

    @asynctest
    async def test_pin_not_set(self):
        """Test getting resident keys from a key with no configured PIN"""

        with sk_error('nopin'):
            with self.assertRaises(ValueError):
                asyncssh.load_resident_keys(b'123456')


@unittest.skipUnless(sk_available, 'security key support not available')
class _TestSKAuthTouchNotRequired(_CheckSKAuth):
    """Unit tests for security key authentication without touch"""

    _sk_touch_required = False
    _sk_auth_touch_required = False

    @asynctest
    async def test_auth_without_touch(self):
        """Test authenticating with a security key without touch"""

        async with self.connect(username='ckey', client_keys=[self._privkey]):
            pass


@unittest.skipUnless(sk_available, 'security key support not available')
class _TestSKAuthTouchRequiredECDSA(_CheckSKAuth):
    """Unit tests for security key authentication failing without touch"""

    _sk_alg = 'sk-ecdsa-sha2-nistp256@openssh.com'
    _sk_touch_required = False
    _sk_auth_touch_required = True

    @asynctest
    async def test_auth_touch_required(self):
        """Test auth failing with a security key not providing touch"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='ckey', client_keys=[self._privkey])


@unittest.skipUnless(sk_available, 'security key support not available')
class _TestSKCertAuthTouchNotRequired(_CheckSKAuth):
    """Unit tests for security key cert authentication without touch"""

    _sk_touch_required = False
    _sk_auth_touch_required = False
    _sk_cert = True

    @asynctest
    async def test_cert_auth_cert_touch_not_required(self):
        """Test authenticating with a security key cert not requiring touch"""

        cert = self._privkey.generate_user_certificate(self._privkey, 'name',
                                                       touch_required=False)

        async with self.connect(username='ckey',
                                client_keys=[(self._privkey, cert)]):
            pass

    @asynctest
    async def test_cert_auth_cert_touch_required(self):
        """Test cert auth failing with a security key cert requiring touch"""

        cert = self._privkey.generate_user_certificate(self._privkey, 'name',
                                                       touch_required=True)

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='ckey',
                               client_keys=[(self._privkey, cert)])


@unittest.skipUnless(sk_available, 'security key support not available')
class _TestSKCertAuthTouchRequired(_CheckSKAuth):
    """Unit tests for security key cert authentication failing without touch"""

    _sk_touch_required = False
    _sk_auth_touch_required = True
    _sk_cert = True

    @asynctest
    async def test_cert_auth_touch_required(self):
        """Test cert auth failing with a security key requiring touch"""

        cert = self._privkey.generate_user_certificate(self._privkey, 'name',
                                                       touch_required=False)

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='ckey',
                               client_keys=[(self._privkey, cert)])

    @asynctest
    async def test_cert_auth_cert_touch_required(self):
        """Test cert auth failing with a security key cert requiring touch"""

        cert = self._privkey.generate_user_certificate(self._privkey, 'name',
                                                       touch_required=True)

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='ckey',
                               client_keys=[(self._privkey, cert)])


@unittest.skipUnless(sk_available, 'security key support not available')
class _TestSKHostAuth(_CheckSKAuth):
    """Unit tests for security key host authentication"""

    _sk_host = True

    @asynctest
    async def test_sk_host_auth(self):
        """Test a server using a security key as a host key"""

        pubkey = self._privkey.convert_to_public()

        async with self.connect(known_hosts=([pubkey], [], [])):
            pass


@unittest.skipUnless(sk_available, 'security key support not available')
class _TestSKHostCertAuth(_CheckSKAuth):
    """Unit tests for security key host cert authentication"""

    _sk_cert = True
    _sk_host = True

    @asynctest
    async def test_sk_host_auth(self):
        """Test a server host using a security key host certificate"""

        pubkey = self._privkey.convert_to_public()

        async with self.connect(known_hosts=([pubkey], [pubkey], [])):
            pass
