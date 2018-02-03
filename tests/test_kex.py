# Copyright (c) 2015-2018 by Ron Frederick <ronf@timeheart.net>.
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

"""Unit tests for key exchange"""

import asyncio
import unittest

from hashlib import sha1

import asyncssh

from asyncssh.dh import MSG_KEXDH_INIT, MSG_KEXDH_REPLY
from asyncssh.dh import _KexDHGex, MSG_KEX_DH_GEX_REQUEST, MSG_KEX_DH_GEX_GROUP
from asyncssh.dh import MSG_KEX_DH_GEX_INIT, MSG_KEX_DH_GEX_REPLY
from asyncssh.dh import MSG_KEXGSS_INIT, MSG_KEXGSS_COMPLETE, MSG_KEXGSS_ERROR
from asyncssh.ecdh import MSG_KEX_ECDH_INIT, MSG_KEX_ECDH_REPLY
from asyncssh.gss import GSSClient, GSSServer
from asyncssh.kex import register_kex_alg, get_kex_algs, get_kex
from asyncssh.misc import DisconnectError
from asyncssh.packet import SSHPacket, Boolean, Byte, MPInt, String
from asyncssh.public_key import SSHLocalKeyPair, decode_ssh_public_key

from .util import asynctest, gss_available, patch_gss
from .util import AsyncTestCase, ConnectionStub

# Short variable names are used here, matching names in the specs
# pylint: disable=invalid-name


class _KexConnectionStub(ConnectionStub):
    """Connection stub class to test key exchange"""

    def __init__(self, alg, gss, peer, server=False):
        super().__init__(peer, server)

        self._gss = gss
        self._key_waiter = asyncio.Future()

        self._kex = get_kex(self, alg)

        if self.is_client():
            self._kex.start()

    def connection_lost(self, exc):
        """Handle the closing of a connection"""

        raise NotImplementedError

    def enable_gss_kex_auth(self):
        """Ignore request to enable GSS key exchange authentication"""

        pass

    def process_packet(self, data):
        """Process an incoming packet"""

        packet = SSHPacket(data)
        pkttype = packet.get_byte()
        self._kex.process_packet(pkttype, None, packet)

    def get_hash_prefix(self):
        """Return the bytes used in calculating unique connection hashes"""

        # pylint: disable=no-self-use

        return b'prefix'

    def send_newkeys(self, k, h):
        """Handle a request to send a new keys message"""

        self._key_waiter.set_result(self._kex.compute_key(k, h, b'A', h, 128))

    def get_key(self):
        """Return generated key data"""

        return (yield from self._key_waiter)

    def get_gss_context(self):
        """Return the GSS context associated with this connection"""

        return self._gss

    def simulate_dh_init(self, e):
        """Simulate receiving a DH init packet"""

        self.process_packet(Byte(MSG_KEXDH_INIT) + MPInt(e))

    def simulate_dh_reply(self, host_key_data, f, sig):
        """Simulate receiving a DH reply packet"""

        self.process_packet(b''.join((Byte(MSG_KEXDH_REPLY),
                                      String(host_key_data),
                                      MPInt(f), String(sig))))

    def simulate_dh_gex_group(self, p, g):
        """Simulate receiving a DH GEX group packet"""

        self.process_packet(Byte(MSG_KEX_DH_GEX_GROUP) + MPInt(p) + MPInt(g))

    def simulate_dh_gex_init(self, e):
        """Simulate receiving a DH GEX init packet"""

        self.process_packet(Byte(MSG_KEX_DH_GEX_INIT) + MPInt(e))

    def simulate_dh_gex_reply(self, host_key_data, f, sig):
        """Simulate receiving a DH GEX reply packet"""

        self.process_packet(b''.join((Byte(MSG_KEX_DH_GEX_REPLY),
                                      String(host_key_data),
                                      MPInt(f), String(sig))))

    def simulate_gss_complete(self, f, sig):
        """Simulate receiving a GSS complete packet"""

        self.process_packet(b''.join((Byte(MSG_KEXGSS_COMPLETE), MPInt(f),
                                      String(sig), Boolean(False))))

    def simulate_ecdh_init(self, client_pub):
        """Simulate receiving an ECDH init packet"""

        self.process_packet(Byte(MSG_KEX_ECDH_INIT) + String(client_pub))

    def simulate_ecdh_reply(self, host_key_data, server_pub, sig):
        """Simulate receiving ab ECDH reply packet"""

        self.process_packet(b''.join((Byte(MSG_KEX_ECDH_REPLY),
                                      String(host_key_data),
                                      String(server_pub), String(sig))))


class _KexClientStub(_KexConnectionStub):
    """Stub class for client connection"""

    @classmethod
    def make_pair(cls, alg, gss_host=None):
        """Make a client and server connection pair to test key exchange"""

        client_conn = cls(alg, gss_host)
        return client_conn, client_conn.get_peer()

    def __init__(self, alg, gss_host):
        server_conn = _KexServerStub(alg, gss_host, self)

        try:
            if gss_host:
                gss = GSSClient(gss_host, 'delegate' in gss_host)
            else:
                gss = None

            super().__init__(alg, gss, server_conn)
        except DisconnectError:
            server_conn.close()
            raise

    def connection_lost(self, exc):
        """Handle the closing of a connection"""

        if exc and not self._key_waiter.done():
            self._key_waiter.set_exception(exc)

        self.close()

    def validate_server_host_key(self, host_key_data):
        """Validate and return the server's host key"""

        # pylint: disable=no-self-use

        return decode_ssh_public_key(host_key_data)


class _KexServerStub(_KexConnectionStub):
    """Stub class for server connection"""

    def __init__(self, alg, gss_host, peer):
        gss = GSSServer(gss_host) if gss_host else None
        super().__init__(alg, gss, peer, True)

        if gss_host and 'no_host_key' in gss_host:
            self._server_host_key = None
        else:
            priv_key = asyncssh.generate_private_key('ssh-rsa')
            self._server_host_key = SSHLocalKeyPair(priv_key)

    def connection_lost(self, exc):
        """Handle the closing of a connection"""

        if self._peer:
            self._peer.connection_lost(exc)

        self.close()

    def get_server_host_key(self):
        """Return the server host key"""

        return self._server_host_key


@patch_gss
class _TestKex(AsyncTestCase):
    """Unit tests for kex module"""

    @asyncio.coroutine
    def _check_kex(self, alg, gss_host=None):
        """Unit test key exchange"""

        client_conn, server_conn = _KexClientStub.make_pair(alg, gss_host)

        try:
            self.assertEqual((yield from client_conn.get_key()),
                             (yield from server_conn.get_key()))
        finally:
            client_conn.close()
            server_conn.close()

    @asynctest
    def test_key_exchange_algs(self):
        """Unit test key exchange algorithms"""

        for alg in get_kex_algs():
            with self.subTest(alg=alg):
                if alg.startswith(b'gss-'):
                    if gss_available: # pragma: no branch
                        yield from self._check_kex(alg + b'-mech', '1')
                else:
                    yield from self._check_kex(alg)

        if gss_available: # pragma: no branch
            for steps in range(4):
                with self.subTest('GSS key exchange', steps=steps):
                    yield from self._check_kex(b'gss-group1-sha1-mech',
                                               str(steps))

            with self.subTest('GSS with credential delegation'):
                yield from self._check_kex(b'gss-group1-sha1-mech',
                                           '1,delegate')

            with self.subTest('GSS with no host key'):
                yield from self._check_kex(b'gss-group1-sha1-mech',
                                           '1,no_host_key')

            with self.subTest('GSS with full host principal'):
                yield from self._check_kex(b'gss-group1-sha1-mech',
                                           'host/1@TEST')

    @asynctest
    def test_dh_gex_old(self):
        """Unit test old DH group exchange request"""

        register_kex_alg(b'dh-gex-sha1-1024', _KexDHGex, sha1, 1024)
        register_kex_alg(b'dh-gex-sha1-2048', _KexDHGex, sha1, 2048)

        for size in (b'1024', b'2048'):
            with self.subTest('Old DH group exchange', size=size):
                yield from self._check_kex(b'dh-gex-sha1-' + size)

    @asynctest
    def test_dh_gex(self):
        """Unit test old DH group exchange request"""

        register_kex_alg(b'dh-gex-sha1-1024-1536', _KexDHGex, sha1, 1024, 1536)
        register_kex_alg(b'dh-gex-sha1-1536-3072', _KexDHGex, sha1, 1536, 3072)
        register_kex_alg(b'dh-gex-sha1-2560-2560', _KexDHGex, sha1, 2560, 2560)
        register_kex_alg(b'dh-gex-sha1-2560-4096', _KexDHGex, sha1, 2560, 4096)
        register_kex_alg(b'dh-gex-sha1-9216-9216', _KexDHGex, sha1, 9216, 9216)

        for size in (b'1024-1536', b'1536-3072', b'2560-2560',
                     b'2560-4096', b'9216-9216'):
            with self.subTest('Old DH group exchange', size=size):
                yield from self._check_kex(b'dh-gex-sha1-' + size)

    @asynctest
    def test_dh_errors(self):
        """Unit test error conditions in DH key exchange"""

        client_conn, server_conn = \
            _KexClientStub.make_pair(b'diffie-hellman-group14-sha1')

        host_key = server_conn.get_server_host_key()

        with self.subTest('Init sent to client'):
            with self.assertRaises(DisconnectError):
                client_conn.process_packet(Byte(MSG_KEXDH_INIT))

        with self.subTest('Reply sent to server'):
            with self.assertRaises(DisconnectError):
                server_conn.process_packet(Byte(MSG_KEXDH_REPLY))

        with self.subTest('Invalid e value'):
            with self.assertRaises(DisconnectError):
                server_conn.simulate_dh_init(0)

        with self.subTest('Invalid f value'):
            with self.assertRaises(DisconnectError):
                client_conn.simulate_dh_reply(host_key.public_data, 0, b'')

        with self.subTest('Invalid signature'):
            with self.assertRaises(DisconnectError):
                client_conn.simulate_dh_reply(host_key.public_data, 1, b'')

        client_conn.close()
        server_conn.close()

    @asynctest
    def test_dh_gex_errors(self):
        """Unit test error conditions in DH group exchange"""

        client_conn, server_conn = \
            _KexClientStub.make_pair(b'diffie-hellman-group-exchange-sha1')

        with self.subTest('Request sent to client'):
            with self.assertRaises(DisconnectError):
                client_conn.process_packet(Byte(MSG_KEX_DH_GEX_REQUEST))

        with self.subTest('Group sent to server'):
            with self.assertRaises(DisconnectError):
                server_conn.simulate_dh_gex_group(1, 2)

        with self.subTest('Init sent to client'):
            with self.assertRaises(DisconnectError):
                client_conn.simulate_dh_gex_init(1)

        with self.subTest('Init sent before group'):
            with self.assertRaises(DisconnectError):
                server_conn.simulate_dh_gex_init(1)

        with self.subTest('Reply sent to server'):
            with self.assertRaises(DisconnectError):
                server_conn.simulate_dh_gex_reply(b'', 1, b'')

        with self.subTest('Reply sent before group'):
            with self.assertRaises(DisconnectError):
                client_conn.simulate_dh_gex_reply(b'', 1, b'')

        client_conn.close()
        server_conn.close()

    @unittest.skipUnless(gss_available, 'GSS not available')
    @asynctest
    def test_gss_errors(self):
        """Unit test error conditions in GSS key exchange"""

        client_conn, server_conn = \
            _KexClientStub.make_pair(b'gss-group1-sha1-mech', '3')

        with self.subTest('Init sent to client'):
            with self.assertRaises(DisconnectError):
                client_conn.process_packet(Byte(MSG_KEXGSS_INIT))

        with self.subTest('Complete sent to server'):
            with self.assertRaises(DisconnectError):
                server_conn.process_packet(Byte(MSG_KEXGSS_COMPLETE))

        with self.subTest('Exchange failed to complete'):
            with self.assertRaises(DisconnectError):
                client_conn.simulate_gss_complete(1, b'succeed')

        with self.subTest('Error sent to server'):
            with self.assertRaises(DisconnectError):
                server_conn.process_packet(Byte(MSG_KEXGSS_ERROR))

        client_conn.close()
        server_conn.close()

        with self.subTest('Signature verification failure'):
            with self.assertRaises(DisconnectError):
                yield from self._check_kex(b'gss-group1-sha1-mech', '0,fail')

        with self.subTest('Empty token in init'):
            with self.assertRaises(DisconnectError):
                yield from self._check_kex(b'gss-group1-sha1-mech',
                                           '0,empty_init')

        with self.subTest('Empty token in continue'):
            with self.assertRaises(DisconnectError):
                yield from self._check_kex(b'gss-group1-sha1-mech',
                                           '1,empty_continue')

        with self.subTest('Token after complete'):
            with self.assertRaises(DisconnectError):
                yield from self._check_kex(b'gss-group1-sha1-mech',
                                           '0,continue_token')

        for steps in range(2):
            with self.subTest('Token after complete', steps=steps):
                with self.assertRaises(DisconnectError):
                    yield from self._check_kex(b'gss-group1-sha1-mech',
                                               str(steps) + ',extra_token')

        with self.subTest('Context not secure'):
            with self.assertRaises(DisconnectError):
                yield from self._check_kex(b'gss-group1-sha1-mech',
                                           '1,no_server_integrity')

        with self.subTest('GSS error'):
            with self.assertRaises(DisconnectError):
                yield from self._check_kex(b'gss-group1-sha1-mech',
                                           '1,step_error')

        with self.subTest('GSS error with error token'):
            with self.assertRaises(DisconnectError):
                yield from self._check_kex(b'gss-group1-sha1-mech',
                                           '1,step_error,errtok')

    @asynctest
    def test_ecdh_errors(self):
        """Unit test error conditions in ECDH key exchange"""

        try:
            from asyncssh.crypto import ECDH
        except ImportError: # pragma: no cover
            return

        client_conn, server_conn = \
            _KexClientStub.make_pair(b'ecdh-sha2-nistp256')

        with self.subTest('Init sent to client'):
            with self.assertRaises(DisconnectError):
                client_conn.simulate_ecdh_init(b'')

        with self.subTest('Invalid client public key'):
            with self.assertRaises(DisconnectError):
                server_conn.simulate_ecdh_init(b'')

        with self.subTest('Reply sent to server'):
            with self.assertRaises(DisconnectError):
                server_conn.simulate_ecdh_reply(b'', b'', b'')

        with self.subTest('Invalid server host key'):
            with self.assertRaises(DisconnectError):
                client_conn.simulate_ecdh_reply(b'', b'', b'')

        with self.subTest('Invalid server public key'):
            with self.assertRaises(DisconnectError):
                host_key = server_conn.get_server_host_key()
                client_conn.simulate_ecdh_reply(host_key.public_data, b'', b'')

        with self.subTest('Invalid signature'):
            with self.assertRaises(DisconnectError):
                host_key = server_conn.get_server_host_key()
                server_pub = ECDH(b'nistp256').get_public()
                client_conn.simulate_ecdh_reply(host_key.public_data,
                                                server_pub, b'')

        client_conn.close()
        server_conn.close()

    @asynctest
    def test_curve25519dh_errors(self):
        """Unit test error conditions in Curve25519DH key exchange"""

        try:
            from asyncssh.crypto import Curve25519DH
        except ImportError: # pragma: no cover
            return

        client_conn, server_conn = \
            _KexClientStub.make_pair(b'curve25519-sha256@libssh.org')

        with self.subTest('Invalid client public key'):
            with self.assertRaises(DisconnectError):
                server_conn.simulate_ecdh_init(b'')

        with self.subTest('Invalid server public key'):
            with self.assertRaises(DisconnectError):
                host_key = server_conn.get_server_host_key()
                client_conn.simulate_ecdh_reply(host_key.public_data, b'', b'')

        with self.subTest('Invalid signature'):
            with self.assertRaises(DisconnectError):
                host_key = server_conn.get_server_host_key()
                server_pub = Curve25519DH().get_public()
                client_conn.simulate_ecdh_reply(host_key.public_data,
                                                server_pub, b'')

        client_conn.close()
        server_conn.close()
