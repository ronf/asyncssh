# Copyright (c) 2015 by Ron Frederick <ronf@timeheart.net>.
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

from hashlib import sha1

from .util import TempDirTestCase, run

from asyncssh.dh import MSG_KEXDH_INIT, MSG_KEXDH_REPLY
from asyncssh.dh import _KexDHGex, MSG_KEX_DH_GEX_GROUP
from asyncssh.dh import MSG_KEX_DH_GEX_INIT, MSG_KEX_DH_GEX_REPLY
from asyncssh.ecdh import MSG_KEX_ECDH_INIT, MSG_KEX_ECDH_REPLY
from asyncssh.kex import register_kex_alg, get_kex_algs, get_kex
from asyncssh.misc import DisconnectError
from asyncssh.packet import SSHPacket, Byte, MPInt, String
from asyncssh.public_key import decode_ssh_public_key, read_private_key

# Short variable names are used here, matching names in the specs
# pylint: disable=invalid-name


class _Conn:
    """Stub class for connection object"""

    _packets = []

    @classmethod
    def process_packets(cls):
        """Process queued packets"""

        while cls._packets:
            peer, data = cls._packets.pop(0)
            peer.process_packet(data)

    def __init__(self, alg, peer, server):
        self._peer = peer
        self._server = server
        self._key = None

        self._kex = get_kex(self, alg)

    def is_client(self):
        """Return if this is a client connection"""

        return not self._server

    def is_server(self):
        """Return if this is a server connection"""

        return self._server

    def get_hash_prefix(self):
        """Return the bytes used in calculating unique connection hashes"""

        # pylint: disable=no-self-use

        return b'prefix'

    def process_packet(self, data):
        """Handle an incoming SSH packet"""

        packet = SSHPacket(data)
        pkttype = packet.get_byte()

        self._kex.process_packet(pkttype, packet)

    def send_packet(self, *args):
        """Handle a request to send an SSH packet"""

        self._packets.append((self._peer, b''.join(args)))

    def send_newkeys(self, k, h):
        """Handle a request to send a new keys message"""

        # TODO
        self._key = self._kex.compute_key(k, h, b'A', h, 128)

    def get_key(self):
        """Return generated key data"""

        return self._key

    def get_peer(self):
        """Return peer"""

        return self._peer

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


class _ClientConn(_Conn):
    """Stub class for client connection"""

    def __init__(self, alg):
        super().__init__(alg, _ServerConn(alg, self), False)

    def validate_server_host_key(self, host_key_data):
        """Validate and return the server's host key"""

        # pylint: disable=no-self-use

        return decode_ssh_public_key(host_key_data)


class _ServerConn(_Conn):
    """Stub class for server connection"""

    def __init__(self, alg, client_conn):
        super().__init__(alg, client_conn, True)

        run('openssl genrsa -out priv 2048')
        priv_key = read_private_key('priv')
        self._server_host_key = (priv_key, String(priv_key.algorithm) +
                                 priv_key.encode_ssh_public())

    def get_server_host_key(self):
        """Return the server host key"""

        return self._server_host_key


class _TestKex(TempDirTestCase):
    """Unit tests for kex module"""

    def test_key_exchange_algs(self):
        """Unit test kex exchange algorithms"""

        for alg in get_kex_algs():
            with self.subTest(alg=alg):
                client_conn = _ClientConn(alg)
                server_conn = client_conn.get_peer()

                with self.subTest('Check matching keys'):
                    _Conn.process_packets()
                    self.assertEqual(client_conn.get_key(),
                                     server_conn.get_key())

                with self.subTest('Check bad init msg'):
                    with self.assertRaises(DisconnectError):
                        client_conn.process_packet(Byte(MSG_KEXDH_INIT))

                with self.subTest('Check bad reply msg'):
                    with self.assertRaises(DisconnectError):
                        server_conn.process_packet(Byte(MSG_KEXDH_REPLY))

    def test_dh_gex_old(self):
        """Unit test old DH group exchange request"""

        register_kex_alg(b'diffie-hellman-group-exchange-sha1-1024',
                         _KexDHGex, sha1, True, 1024)
        register_kex_alg(b'diffie-hellman-group-exchange-sha1-2048',
                         _KexDHGex, sha1, True, 1024)

        for size in (b'1024', b'2048'):
            with self.subTest('Old DH group exchange', size=size):
                alg = b'diffie-hellman-group-exchange-sha1-' + size
                client_conn = _ClientConn(alg)
                server_conn = client_conn.get_peer()
                _Conn.process_packets()
                self.assertEqual(client_conn.get_key(), server_conn.get_key())

    def test_dh_errors(self):
        """Unit test error conditions in DH key exchange"""

        client_conn = _ClientConn(b'diffie-hellman-group14-sha1')
        server_conn = client_conn.get_peer()

        with self.subTest('Invalid e value'):
            with self.assertRaises(DisconnectError):
                server_conn.simulate_dh_init(0)

        with self.subTest('Invalid f value'):
            with self.assertRaises(DisconnectError):
                client_conn.simulate_dh_reply(b'', 0, b'')

        with self.subTest('Invalid signature'):
            with self.assertRaises(DisconnectError):
                _, host_key_data = server_conn.get_server_host_key()
                client_conn.simulate_dh_reply(host_key_data, 1, b'')

    def test_dh_gex_errors(self):
        """Unit test error conditions in DH group and key exchange"""

        client_conn = _ClientConn(b'diffie-hellman-group-exchange-sha1')
        server_conn = client_conn.get_peer()

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

    def test_ecdh_errors(self):
        """Unit test error conditions in ECDH key exchange"""

        try:
            from asyncssh.crypto import ECDH
        except ImportError: # pragma: no cover
            return

        client_conn = _ClientConn(b'ecdh-sha2-nistp256')
        server_conn = client_conn.get_peer()

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
                _, host_key_data = server_conn.get_server_host_key()
                client_conn.simulate_ecdh_reply(host_key_data, b'', b'')

        with self.subTest('Invalid signature'):
            with self.assertRaises(DisconnectError):
                _, host_key_data = server_conn.get_server_host_key()
                server_pub = ECDH(b'nistp256').get_public()
                client_conn.simulate_ecdh_reply(host_key_data, server_pub, b'')

    def test_curve25519dh_errors(self):
        """Unit test error conditions in Curve25519DH key exchange"""

        try:
            from asyncssh.crypto import Curve25519DH
        except ImportError: # pragma: no cover
            return

        client_conn = _ClientConn(b'curve25519-sha256@libssh.org')
        server_conn = client_conn.get_peer()

        with self.subTest('Invalid client public key'):
            with self.assertRaises(DisconnectError):
                server_conn.simulate_ecdh_init(b'')

        with self.subTest('Invalid server public key'):
            with self.assertRaises(DisconnectError):
                _, host_key_data = server_conn.get_server_host_key()
                client_conn.simulate_ecdh_reply(host_key_data, b'', b'')

        with self.subTest('Invalid signature'):
            with self.assertRaises(DisconnectError):
                _, host_key_data = server_conn.get_server_host_key()
                server_pub = Curve25519DH().get_public()
                client_conn.simulate_ecdh_reply(host_key_data, server_pub, b'')
