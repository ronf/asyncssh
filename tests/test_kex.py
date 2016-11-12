# Copyright (c) 2015-2016 by Ron Frederick <ronf@timeheart.net>.
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

from hashlib import sha1

import asyncssh

from asyncssh.dh import MSG_KEXDH_INIT, MSG_KEXDH_REPLY
from asyncssh.dh import _KexDHGex, MSG_KEX_DH_GEX_GROUP
from asyncssh.dh import MSG_KEX_DH_GEX_INIT, MSG_KEX_DH_GEX_REPLY
from asyncssh.ecdh import MSG_KEX_ECDH_INIT, MSG_KEX_ECDH_REPLY
from asyncssh.kex import register_kex_alg, get_kex_algs, get_kex
from asyncssh.misc import DisconnectError
from asyncssh.packet import SSHPacket, Byte, MPInt, String
from asyncssh.public_key import SSHLocalKeyPair, decode_ssh_public_key

from .util import asynctest, ConnectionStub, AsyncTestCase

# Short variable names are used here, matching names in the specs
# pylint: disable=invalid-name


class _KexConnectionStub(ConnectionStub):
    """Connection stub class to test key exchange"""

    def __init__(self, alg, peer, server):
        super().__init__(peer, server)

        self._key_future = asyncio.Future()

        self._kex = get_kex(self, alg)

    def process_packet(self, data):
        """Process an incoming packet"""

        packet = SSHPacket(data)
        pkttype = packet.get_byte()
        self._kex.process_packet(pkttype, packet)

    def get_hash_prefix(self):
        """Return the bytes used in calculating unique connection hashes"""

        # pylint: disable=no-self-use

        return b'prefix'

    def send_newkeys(self, k, h):
        """Handle a request to send a new keys message"""

        self._key_future.set_result(self._kex.compute_key(k, h, b'A', h, 128))

    def get_key(self):
        """Return generated key data"""

        return (yield from self._key_future)

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
    def make_pair(cls, alg):
        """Make a client and server connection pair to test key exchange"""

        client_conn = cls(alg)

        return client_conn, client_conn.get_peer()

    def __init__(self, alg):
        super().__init__(alg, _KexServerStub(alg, self), False)

    def validate_server_host_key(self, host_key_data):
        """Validate and return the server's host key"""

        # pylint: disable=no-self-use

        return decode_ssh_public_key(host_key_data)


class _KexServerStub(_KexConnectionStub):
    """Stub class for server connection"""

    def __init__(self, alg, peer):
        super().__init__(alg, peer, True)

        priv_key = asyncssh.generate_private_key('ssh-rsa')
        self._server_host_key = SSHLocalKeyPair(priv_key)

    def get_server_host_key(self):
        """Return the server host key"""

        return self._server_host_key


class _TestKex(AsyncTestCase):
    """Unit tests for kex module"""

    @asynctest
    def test_key_exchange_algs(self):
        """Unit test kex exchange algorithms"""

        for alg in get_kex_algs():
            with self.subTest(alg=alg):
                client_conn, server_conn = _KexClientStub.make_pair(alg)

                with self.subTest('Check matching keys'):
                    self.assertEqual((yield from client_conn.get_key()),
                                     (yield from server_conn.get_key()))

                with self.subTest('Check bad init msg'):
                    with self.assertRaises(DisconnectError):
                        client_conn.process_packet(Byte(MSG_KEXDH_INIT))

                with self.subTest('Check bad reply msg'):
                    with self.assertRaises(DisconnectError):
                        server_conn.process_packet(Byte(MSG_KEXDH_REPLY))

                client_conn.close()
                server_conn.close()

    @asynctest
    def test_dh_gex_old(self):
        """Unit test old DH group exchange request"""

        register_kex_alg(b'diffie-hellman-group-exchange-sha1-1024',
                         _KexDHGex, sha1, True, 1024)
        register_kex_alg(b'diffie-hellman-group-exchange-sha1-2048',
                         _KexDHGex, sha1, True, 2048)

        for size in (b'1024', b'2048'):
            with self.subTest('Old DH group exchange', size=size):
                alg = b'diffie-hellman-group-exchange-sha1-' + size

                client_conn, server_conn = _KexClientStub.make_pair(alg)

                self.assertEqual((yield from client_conn.get_key()),
                                 (yield from server_conn.get_key()))

                client_conn.close()
                server_conn.close()

    @asynctest
    def test_dh_errors(self):
        """Unit test error conditions in DH key exchange"""

        client_conn, server_conn = \
            _KexClientStub.make_pair(b'diffie-hellman-group14-sha1')

        with self.subTest('Invalid e value'):
            with self.assertRaises(DisconnectError):
                server_conn.simulate_dh_init(0)

        with self.subTest('Invalid f value'):
            with self.assertRaises(DisconnectError):
                client_conn.simulate_dh_reply(b'', 0, b'')

        with self.subTest('Invalid signature'):
            with self.assertRaises(DisconnectError):
                host_key = server_conn.get_server_host_key()
                client_conn.simulate_dh_reply(host_key.public_data, 1, b'')

        client_conn.close()
        server_conn.close()

    @asynctest
    def test_dh_gex_errors(self):
        """Unit test error conditions in DH group and key exchange"""

        client_conn, server_conn = \
            _KexClientStub.make_pair(b'diffie-hellman-group-exchange-sha1')

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
