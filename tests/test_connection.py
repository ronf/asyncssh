# Copyright (c) 2016-2019 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Unit tests for AsyncSSH connection API"""

import asyncio
from copy import copy
import os
import sys
import unittest
from unittest.mock import patch

import asyncssh
from asyncssh.constants import MSG_UNIMPLEMENTED, MSG_DEBUG
from asyncssh.constants import MSG_SERVICE_REQUEST, MSG_SERVICE_ACCEPT
from asyncssh.constants import MSG_KEXINIT, MSG_NEWKEYS
from asyncssh.constants import MSG_USERAUTH_REQUEST, MSG_USERAUTH_SUCCESS
from asyncssh.constants import MSG_USERAUTH_FAILURE, MSG_USERAUTH_BANNER
from asyncssh.constants import MSG_GLOBAL_REQUEST
from asyncssh.constants import MSG_CHANNEL_OPEN, MSG_CHANNEL_OPEN_CONFIRMATION
from asyncssh.constants import MSG_CHANNEL_OPEN_FAILURE, MSG_CHANNEL_DATA
from asyncssh.compression import get_compression_algs
from asyncssh.crypto.cipher import GCMCipher
from asyncssh.encryption import get_encryption_algs
from asyncssh.kex import get_kex_algs
from asyncssh.mac import _HMAC, _mac_handler, get_mac_algs
from asyncssh.packet import Boolean, NameList, String, UInt32

from .server import Server, ServerTestCase
from .util import asynctest, gss_available, patch_gss, x509_available


class _SplitClientConnection(asyncssh.SSHClientConnection):
    """Test SSH messages being split into multiple packets"""

    def data_received(self, data, datatype=None):
        """Handle incoming data on the connection"""

        super().data_received(data[:3], datatype)
        super().data_received(data[3:6], datatype)
        super().data_received(data[6:9], datatype)
        super().data_received(data[9:], datatype)


class _ReplayKexClientConnection(asyncssh.SSHClientConnection):
    """Test starting SSH key exchange while it is in progress"""

    def replay_kex(self):
        """Replay last kexinit packet"""

        self.send_packet(MSG_KEXINIT, self._client_kexinit[1:])


class _KeepaliveClientConnection(asyncssh.SSHClientConnection):
    """Test handling of keepalive requests on client"""

    def _process_keepalive_at_openssh_dot_com_global_request(self, packet):
        """Process an incoming OpenSSH keepalive request"""

        super()._process_keepalive_at_openssh_dot_com_global_request(packet)
        self.disconnect(asyncssh.DISC_BY_APPLICATION, 'Keepalive')


class _KeepaliveClientConnectionFailure(asyncssh.SSHClientConnection):
    """Test handling of keepalive failures on client"""

    def _process_keepalive_at_openssh_dot_com_global_request(self, packet):
        """Ignore an incoming OpenSSH keepalive request"""


class _KeepaliveServerConnection(asyncssh.SSHServerConnection):
    """Test handling of keepalive requests on server"""

    def _process_keepalive_at_openssh_dot_com_global_request(self, packet):
        """Process an incoming OpenSSH keepalive request"""

        super()._process_keepalive_at_openssh_dot_com_global_request(packet)
        self.disconnect(asyncssh.DISC_BY_APPLICATION, 'Keepalive')


class _KeepaliveServerConnectionFailure(asyncssh.SSHServerConnection):
    """Test handling of keepalive failures on server"""

    def _process_keepalive_at_openssh_dot_com_global_request(self, packet):
        """Ignore an incoming OpenSSH keepalive request"""


class _VersionedServerConnection(asyncssh.SSHServerConnection):
    """Test alternate SSH server version lines"""

    def __init__(self, version, leading_text, newline, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._version = version
        self._leading_text = leading_text
        self._newline = newline

    @classmethod
    def create(cls, version=b'SSH-2.0-AsyncSSH_Test',
               leading_text=b'', newline=b'\r\n'):
        """Return a connection factory which sends modified version lines"""

        return (lambda *args, **kwargs: cls(version, leading_text,
                                            newline, *args, **kwargs))

    def _send_version(self):
        """Start the SSH handshake"""

        self._server_version = self._version
        self._extra.update(server_version=self._version.decode('ascii'))
        self._send(self._leading_text + self._version + self._newline)


class _BadHostKeyServerConnection(asyncssh.SSHServerConnection):
    """Test returning invalid server host key"""

    def get_server_host_key(self):
        """Return the chosen server host key"""

        result = copy(super().get_server_host_key())
        result.public_data = b'xxx'
        return result


class _ExtInfoServerConnection(asyncssh.SSHServerConnection):
    """Test adding an unrecognized extension in extension info"""

    def _send_ext_info(self):
        """Send extension information"""

        self._extensions_sent['xxx'] = b''
        super()._send_ext_info()


def _failing_get_mac(alg, key):
    """Replace HMAC class with FailingMAC"""

    class _FailingMAC(_HMAC):
        """Test error in MAC validation"""

        def verify(self, seq, packet, sig):
            """Verify the signature of a message"""

            return super().verify(seq, packet + b'\xff', sig)

    _, hash_size, args = _mac_handler[alg]
    return _FailingMAC(key, hash_size, *args)


class _FailingGCMCipher(GCMCipher):
    """Test error in GCM tag verification"""

    def verify_and_decrypt(self, header, data, mac):
        """Verify the signature of and decrypt a block of data"""

        return super().verify_and_decrypt(header, data + b'\xff', mac)


class _ValidateHostKeyClient(asyncssh.SSHClient):
    """Test server host key/CA validation callbacks"""

    def __init__(self, host_key=None, ca_key=None):
        self._host_key = \
            asyncssh.read_public_key(host_key) if host_key else None
        self._ca_key = \
            asyncssh.read_public_key(ca_key) if ca_key else None

    def validate_host_public_key(self, host, addr, port, key):
        """Return whether key is an authorized key for this host"""

        # pylint: disable=unused-argument

        return key == self._host_key

    def validate_host_ca_key(self, host, addr, port, key):
        """Return whether key is an authorized CA key for this host"""

        # pylint: disable=unused-argument

        return key == self._ca_key


class _PreAuthRequestClient(asyncssh.SSHClient):
    """Test sending a request prior to auth complete"""

    def __init__(self):
        self._conn = None

    def connection_made(self, conn):
        """Save connection for use later"""

        self._conn = conn

    def password_auth_requested(self):
        """Attempt to execute a command before authentication is complete"""

        # pylint: disable=protected-access
        self._conn._auth_complete = True

        self._conn.send_packet(MSG_GLOBAL_REQUEST, String(b'\xff'),
                               Boolean(True))
        return 'pw'


class _InternalErrorClient(asyncssh.SSHClient):
    """Test of internal error exception handler"""

    def connection_made(self, conn):
        """Raise an error when a new connection is opened"""

        # pylint: disable=unused-argument

        raise RuntimeError('Exception handler test')


class _TunnelServer(Server):
    """Allow forwarding to test server host key request tunneling"""

    def connection_requested(self, dest_host, dest_port, orig_host, orig_port):
        """Handle a request to create a new connection"""

        return True


class _AbortServer(Server):
    """Server for testing connection abort during auth"""

    def begin_auth(self, username):
        """Abort the connection during auth"""

        self._conn.abort()
        return False


class _CloseDuringAuthServer(Server):
    """Server for testing connection close during long auth callback"""

    def password_auth_supported(self):
        """Return that password auth is supported"""

        return True

    async def validate_password(self, username, password):
        """Delay validating password"""

        # pylint: disable=unused-argument

        await asyncio.sleep(1)
        return False


class _InternalErrorServer(Server):
    """Server for testing internal error during auth"""

    def begin_auth(self, username):
        """Raise an internal error during auth"""

        raise RuntimeError('Exception handler test')


class _InvalidAuthBannerServer(Server):
    """Server for testing invalid auth banner"""

    def begin_auth(self, username):
        """Send an invalid auth banner"""

        self._conn.send_auth_banner(b'\xff')
        return False


class _VersionRecordingClient(asyncssh.SSHClient):
    """Client for testing custom client version"""

    def __init__(self):
        self.reported_version = None

    def auth_banner_received(self, msg, lang):
        """Record the client version reported in the auth banner"""

        self.reported_version = msg


class _VersionReportingServer(Server):
    """Server for testing custom client version"""

    def begin_auth(self, username):
        """Report the client's version in the auth banner"""

        version = self._conn.get_extra_info('client_version')
        self._conn.send_auth_banner(version)
        return False


def disconnect_on_unimplemented(self, pkttype, pktid, packet):
    """Process an unimplemented message response"""

    # pylint: disable=unused-argument

    self.disconnect(asyncssh.DISC_BY_APPLICATION, 'Unexpected response')


@patch_gss
class _TestConnection(ServerTestCase):
    """Unit tests for AsyncSSH connection API"""

    # pylint: disable=too-many-public-methods

    @classmethod
    async def start_server(cls):
        """Start an SSH server to connect to"""

        def acceptor(conn):
            """Acceptor for SSH connections"""

            conn.logger.info('Acceptor called')

        return (await cls.create_server(_TunnelServer, gss_host=(),
                                        acceptor=acceptor))

    async def get_server_host_key(self, **kwargs):
        """Create a connection to the test server"""

        return (await asyncssh.get_server_host_key(self._server_addr,
                                                   self._server_port,
                                                   **kwargs))

    async def _check_version(self, *args, **kwargs):
        """Check alternate SSH server version lines"""

        with patch('asyncssh.connection.SSHServerConnection',
                   _VersionedServerConnection.create(*args, **kwargs)):
            async with self.connect():
                pass

    @asynctest
    async def test_connect(self):
        """Test connecting with async context manager"""

        async with self.connect():
            pass

    @asynctest
    async def test_connect_invalid_options_type(self):
        """Test connecting using options using incorrect type of options"""

        options = asyncssh.SSHServerConnectionOptions()

        with self.assertRaises(TypeError):
            await self.connect(options=options)

    @asynctest
    async def test_connect_invalid_option_name(self):
        """Test connecting using incorrect option name"""

        with self.assertRaises(TypeError):
            await self.connect(xxx=1)

    @asynctest
    async def test_connect_failure(self):
        """Test failure connecting"""

        with self.assertRaises(OSError):
            await asyncssh.connect('0.0.0.1')

    @asynctest
    async def test_connect_failure_without_agent(self):
        """Test failure connecting with SSH agent disabled"""

        with self.assertRaises(OSError):
            await asyncssh.connect('0.0.0.1', agent_path=None)

    @asynctest
    async def test_split_version(self):
        """Test version split across two packets"""

        with patch('asyncssh.connection.SSHClientConnection',
                   _SplitClientConnection):
            async with self.connect():
                pass

    @asynctest
    async def test_version_1_99(self):
        """Test SSH server version 1.99"""

        await self._check_version(b'SSH-1.99-Test')

    @asynctest
    async def test_text_before_version(self):
        """Test additional text before SSH server version"""

        await self._check_version(leading_text=b'Test\r\n')

    @asynctest
    async def test_version_without_cr(self):
        """Test SSH server version with LF instead of CRLF"""

        await self._check_version(newline=b'\n')

    @asynctest
    async def test_unknown_version(self):
        """Test unknown SSH server version"""

        with self.assertRaises(asyncssh.ProtocolNotSupported):
            await self._check_version(b'SSH-1.0-Test')

    @asynctest
    async def test_no_server_host_keys(self):
        """Test starting a server with no host keys"""

        with self.assertRaises(ValueError):
            await asyncssh.create_server(Server, server_host_keys=[],
                                         gss_host=None)

    @asynctest
    async def test_duplicate_type_server_host_keys(self):
        """Test starting a server with duplicate host key types"""

        with self.assertRaises(ValueError):
            await asyncssh.listen(server_host_keys=['skey', 'skey'])

    @asynctest
    async def test_get_server_host_key(self):
        """Test retrieving a server host key"""

        keylist = asyncssh.load_public_keys('skey.pub')
        key = await self.get_server_host_key()
        self.assertEqual(key, keylist[0])

    @asynctest
    async def test_get_server_host_key_tunnel(self):
        """Test retrieving a server host key while tunneling over SSH"""

        keylist = asyncssh.load_public_keys('skey.pub')

        async with self.connect() as conn:
            key = await self.get_server_host_key(tunnel=conn)

        self.assertEqual(key, keylist[0])

    @asynctest
    async def test_get_server_host_key_connect_failure(self):
        """Test failure connecting when retrieving a server host key"""

        with self.assertRaises(OSError):
            await asyncssh.get_server_host_key('0.0.0.1')

    @asynctest
    async def test_known_hosts_not_present(self):
        """Test connecting with default known hosts file not present"""

        try:
            os.rename(os.path.join('.ssh', 'known_hosts'),
                      os.path.join('.ssh', 'known_hosts.save'))

            with self.assertRaises(asyncssh.HostKeyNotVerifiable):
                await self.connect()
        finally:
            os.rename(os.path.join('.ssh', 'known_hosts.save'),
                      os.path.join('.ssh', 'known_hosts'))

    @unittest.skipIf(sys.platform == 'win32', 'skip chmod tests on Windows')
    @asynctest
    async def test_known_hosts_not_readable(self):
        """Test connecting with default known hosts file not readable"""

        try:
            os.chmod(os.path.join('.ssh', 'known_hosts'), 0)

            with self.assertRaises(asyncssh.HostKeyNotVerifiable):
                await self.connect()
        finally:
            os.chmod(os.path.join('.ssh', 'known_hosts'), 0o644)

    @asynctest
    async def test_known_hosts_none(self):
        """Test connecting with known hosts checking disabled"""

        async with self.connect(known_hosts=None):
            pass

    @asynctest
    async def test_known_hosts_none_without_x509(self):
        """Test connecting with known hosts checking and X.509 disabled"""

        async with self.connect(known_hosts=None,
                                x509_trusted_certs=None):
            pass

    @asynctest
    async def test_known_hosts_multiple_keys(self):
        """Test connecting with multiple trusted known hosts keys"""

        async with self.connect(known_hosts=(['skey.pub', 'skey.pub'],
                                             [], [])):
            pass

    @asynctest
    async def test_known_hosts_ca(self):
        """Test connecting with a known hosts CA"""

        async with self.connect(known_hosts=([], ['skey.pub'], [])):
            pass

    @asynctest
    async def test_known_hosts_bytes(self):
        """Test connecting with known hosts passed in as bytes"""

        with open('skey.pub', 'rb') as f:
            skey = f.read()

        async with self.connect(known_hosts=([skey], [], [])):
            pass

    @asynctest
    async def test_known_hosts_keylist_file(self):
        """Test connecting with known hosts passed as a keylist file"""

        async with self.connect(known_hosts=('skey.pub', [], [])):
            pass

    @asynctest
    async def test_known_hosts_sshkeys(self):
        """Test connecting with known hosts passed in as SSHKeys"""

        keylist = asyncssh.load_public_keys('skey.pub')

        async with self.connect(known_hosts=(keylist, [], [])) as conn:
            self.assertEqual(conn.get_server_host_key(), keylist[0])

    @asynctest
    async def test_read_known_hosts(self):
        """Test connecting with known hosts object from read_known_hosts"""

        known_hosts_path = os.path.join('.ssh', 'known_hosts')
        known_hosts = asyncssh.read_known_hosts(known_hosts_path)

        async with self.connect(known_hosts=known_hosts):
            pass

    @asynctest
    async def test_import_known_hosts(self):
        """Test connecting with known hosts object from import_known_hosts"""

        known_hosts_path = os.path.join('.ssh', 'known_hosts')

        with open(known_hosts_path, 'r') as f:
            known_hosts = asyncssh.import_known_hosts(f.read())

        async with self.connect(known_hosts=known_hosts):
            pass

    @asynctest
    async def test_validate_host_ca_callback(self):
        """Test callback to validate server CA key"""

        def client_factory():
            """Return an SSHClient which can validate the sevrer CA key"""

            return _ValidateHostKeyClient(ca_key='skey.pub')

        conn, _ = await self.create_connection(client_factory,
                                               known_hosts=([], [], []))

        async with conn:
            pass

    @asynctest
    async def test_untrusted_known_hosts_ca(self):
        """Test untrusted server CA key"""

        with self.assertRaises(asyncssh.HostKeyNotVerifiable):
            await self.connect(known_hosts=([], ['ckey.pub'], []))

    @asynctest
    async def test_untrusted_host_key_callback(self):
        """Test callback to validate server host key returning failure"""

        def client_factory():
            """Return an SSHClient which can validate the sevrer host key"""

            return _ValidateHostKeyClient(host_key='ckey.pub')

        with self.assertRaises(asyncssh.HostKeyNotVerifiable):
            await self.create_connection(client_factory,
                                         known_hosts=([], [], []))

    @asynctest
    async def test_untrusted_host_ca_callback(self):
        """Test callback to validate server CA key returning failure"""

        def client_factory():
            """Return an SSHClient which can validate the sevrer CA key"""

            return _ValidateHostKeyClient(ca_key='ckey.pub')

        with self.assertRaises(asyncssh.HostKeyNotVerifiable):
            await self.create_connection(client_factory,
                                         known_hosts=([], [], []))

    @asynctest
    async def test_revoked_known_hosts_key(self):
        """Test revoked server host key"""

        with self.assertRaises(asyncssh.HostKeyNotVerifiable):
            await self.connect(known_hosts=(['ckey.pub'], [], ['skey.pub']))

    @asynctest
    async def test_revoked_known_hosts_ca(self):
        """Test revoked server CA key"""

        with self.assertRaises(asyncssh.HostKeyNotVerifiable):
            await self.connect(known_hosts=([], ['ckey.pub'], ['skey.pub']))

    @asynctest
    async def test_empty_known_hosts(self):
        """Test empty known hosts list"""

        with self.assertRaises(asyncssh.HostKeyNotVerifiable):
            await self.connect(known_hosts=([], [], []))

    @asynctest
    async def test_invalid_server_host_key(self):
        """Test invalid server host key"""

        with patch('asyncssh.connection.SSHServerConnection',
                   _BadHostKeyServerConnection):
            with self.assertRaises(asyncssh.HostKeyNotVerifiable):
                await self.connect()

    @asynctest
    async def test_kex_algs(self):
        """Test connecting with different key exchange algorithms"""

        for kex in get_kex_algs():
            kex = kex.decode('ascii')

            if kex.startswith('gss-') and not gss_available: # pragma: no cover
                continue

            with self.subTest(kex_alg=kex):
                async with self.connect(kex_algs=[kex], gss_host='1'):
                    pass

    @asynctest
    async def test_empty_kex_algs(self):
        """Test connecting with an empty list of key exchange algorithms"""

        with self.assertRaises(ValueError):
            await self.connect(kex_algs=[])

    @asynctest
    async def test_invalid_kex_alg(self):
        """Test connecting with invalid key exchange algorithm"""

        with self.assertRaises(ValueError):
            await self.connect(kex_algs=['xxx'])

    @asynctest
    async def test_unsupported_kex_alg(self):
        """Test connecting with unsupported key exchange algorithm"""

        def unsupported_kex_alg():
            """Patched version of get_kex_algs to test unsupported algorithm"""

            return [b'fail'] + get_kex_algs()

        with patch('asyncssh.connection.get_kex_algs', unsupported_kex_alg):
            with self.assertRaises(asyncssh.KeyExchangeFailed):
                await self.connect(kex_algs=['fail'])

    @asynctest
    async def test_skip_ext_info(self):
        """Test not requesting extension info from the server"""

        def skip_ext_info(self):
            """Don't request extension information"""

            # pylint: disable=unused-argument

            return []

        with patch('asyncssh.connection.SSHConnection._get_ext_info_kex_alg',
                   skip_ext_info):
            async with self.connect():
                pass

    @asynctest
    async def test_unknown_ext_info(self):
        """Test receiving unknown extension information"""

        with patch('asyncssh.connection.SSHServerConnection',
                   _ExtInfoServerConnection):
            async with self.connect():
                pass

    @asynctest
    async def test_server_ext_info(self):
        """Test receiving unsolicited extension information on server"""

        def send_newkeys(self, k, h):
            """Finish a key exchange and send a new keys message"""

            asyncssh.connection.SSHConnection.send_newkeys(self, k, h)
            self._send_ext_info()

        with patch('asyncssh.connection.SSHClientConnection.send_newkeys',
                   send_newkeys):
            async with self.connect():
                pass

    @asynctest
    async def test_encryption_algs(self):
        """Test connecting with different encryption algorithms"""

        for enc in get_encryption_algs():
            enc = enc.decode('ascii')
            with self.subTest(encryption_alg=enc):
                async with self.connect(encryption_algs=[enc]):
                    pass

    @asynctest
    async def test_empty_encryption_algs(self):
        """Test connecting with an empty list of encryption algorithms"""

        with self.assertRaises(ValueError):
            await self.connect(encryption_algs=[])

    @asynctest
    async def test_invalid_encryption_alg(self):
        """Test connecting with invalid encryption algorithm"""

        with self.assertRaises(ValueError):
            await self.connect(encryption_algs=['xxx'])

    @asynctest
    async def test_mac_algs(self):
        """Test connecting with different MAC algorithms"""

        for mac in get_mac_algs():
            mac = mac.decode('ascii')
            with self.subTest(mac_alg=mac):
                async with self.connect(encryption_algs=['aes128-ctr'],
                                        mac_algs=[mac]):
                    pass

    @asynctest
    async def test_mac_verify_error(self):
        """Test MAC validation failure"""

        with patch('asyncssh.encryption.get_mac', _failing_get_mac):
            for mac in ('hmac-sha2-256-etm@openssh.com', 'hmac-sha2-256'):
                with self.subTest(mac_alg=mac):
                    with self.assertRaises(asyncssh.MACError):
                        await self.connect(encryption_algs=['aes128-ctr'],
                                           mac_algs=[mac])

    @asynctest
    async def test_gcm_verify_error(self):
        """Test GCM tag validation failure"""

        with patch('asyncssh.encryption.GCMCipher', _FailingGCMCipher):
            with self.assertRaises(asyncssh.MACError):
                await self.connect(encryption_algs=['aes128-gcm@openssh.com'])

    @asynctest
    async def test_empty_mac_algs(self):
        """Test connecting with an empty list of MAC algorithms"""

        with self.assertRaises(ValueError):
            await self.connect(mac_algs=[])

    @asynctest
    async def test_invalid_mac_alg(self):
        """Test connecting with invalid MAC algorithm"""

        with self.assertRaises(ValueError):
            await self.connect(mac_algs=['xxx'])

    @asynctest
    async def test_compression_algs(self):
        """Test connecting with different compression algorithms"""

        for cmp in get_compression_algs():
            cmp = cmp.decode('ascii')
            with self.subTest(cmp_alg=cmp):
                async with self.connect(compression_algs=[cmp]):
                    pass

    @asynctest
    async def test_no_compression(self):
        """Test connecting with compression disabled"""

        async with self.connect(compression_algs=None):
            pass

    @asynctest
    async def test_invalid_cmp_alg(self):
        """Test connecting with invalid compression algorithm"""

        with self.assertRaises(ValueError):
            await self.connect(compression_algs=['xxx'])

    @asynctest
    async def test_disconnect(self):
        """Test sending disconnect message"""

        conn = await self.connect()
        conn.disconnect(asyncssh.DISC_BY_APPLICATION, 'Closing')
        await conn.wait_closed()

    @asynctest
    async def test_invalid_disconnect(self):
        """Test sending disconnect message with invalid Unicode in it"""

        conn = await self.connect()
        conn.disconnect(asyncssh.DISC_BY_APPLICATION, b'\xff')
        await conn.wait_closed()

    @asynctest
    async def test_debug(self):
        """Test sending debug message"""

        async with self.connect() as conn:
            conn.send_debug('debug')

    @asynctest
    async def test_invalid_debug(self):
        """Test sending debug message with invalid Unicode in it"""

        conn = await self.connect()
        conn.send_debug(b'\xff')
        await conn.wait_closed()

    @asynctest
    async def test_invalid_service_request(self):
        """Test invalid service request"""

        conn = await self.connect()
        conn.send_packet(MSG_SERVICE_REQUEST, String('xxx'))
        await conn.wait_closed()

    @asynctest
    async def test_invalid_service_accept(self):
        """Test invalid service accept"""

        conn = await self.connect()
        conn.send_packet(MSG_SERVICE_ACCEPT, String('xxx'))
        await conn.wait_closed()

    @asynctest
    async def test_packet_decode_error(self):
        """Test SSH packet decode error"""

        conn = await self.connect()
        conn.send_packet(MSG_DEBUG)
        await conn.wait_closed()

    @asynctest
    async def test_unknown_packet(self):
        """Test unknown SSH packet"""

        async with self.connect() as conn:
            conn.send_packet(0xff)
            await asyncio.sleep(0.1)

    @asynctest
    async def test_client_keepalive(self):
        """Test sending keepalive from client"""

        with patch('asyncssh.connection.SSHServerConnection',
                   _KeepaliveServerConnection):
            conn = await self.connect(keepalive_interval=0.1)
            await conn.wait_closed()

    @asynctest
    async def test_client_set_keepalive_interval(self):
        """Test sending keepalive interval with set_keepalive"""

        with patch('asyncssh.connection.SSHServerConnection',
                   _KeepaliveServerConnection):
            conn = await self.connect()
            conn.set_keepalive(0.1)
            await conn.wait_closed()

    @asynctest
    async def test_client_set_keepalive_count_max(self):
        """Test sending keepalive count max with set_keepalive"""

        with patch('asyncssh.connection.SSHServerConnection',
                   _KeepaliveServerConnection):
            conn = await self.connect(keepalive_interval=0.1)
            conn.set_keepalive(count_max=10)
            await conn.wait_closed()

    @asynctest
    async def test_client_keepalive_failure(self):
        """Test client keepalive failure"""

        with patch('asyncssh.connection.SSHServerConnection',
                   _KeepaliveServerConnectionFailure):
            conn = await self.connect(keepalive_interval=0.1)
            await conn.wait_closed()

    @asynctest
    async def test_rekey(self):
        """Test SSH re-keying"""

        async with self.connect(rekey_bytes=1) as conn:
            await asyncio.sleep(0.1)
            conn.send_debug('test')
            await asyncio.sleep(0.1)

    @asynctest
    async def test_kex_in_progress(self):
        """Test starting SSH key exchange while it is in progress"""

        with patch('asyncssh.connection.SSHClientConnection',
                   _ReplayKexClientConnection):
            conn = await self.connect()
            conn.replay_kex()
            conn.replay_kex()
            await conn.wait_closed()

    @asynctest
    async def test_no_matching_kex_algs(self):
        """Test no matching key exchange algorithms"""

        conn = await self.connect()

        conn.send_packet(MSG_KEXINIT, os.urandom(16), NameList([b'xxx']),
                         NameList([]), NameList([]), NameList([]),
                         NameList([]), NameList([]), NameList([]),
                         NameList([]), NameList([]), NameList([]),
                         Boolean(False), UInt32(0))

        await conn.wait_closed()

    @asynctest
    async def test_no_matching_host_key_algs(self):
        """Test no matching server host key algorithms"""

        conn = await self.connect()

        conn.send_packet(MSG_KEXINIT, os.urandom(16),
                         NameList([b'ecdh-sha2-nistp521']),
                         NameList([b'xxx']), NameList([]), NameList([]),
                         NameList([]), NameList([]), NameList([]),
                         NameList([]), NameList([]), NameList([]),
                         Boolean(False), UInt32(0))

        await conn.wait_closed()

    @asynctest
    async def test_invalid_newkeys(self):
        """Test invalid new keys request"""

        conn = await self.connect()
        conn.send_packet(MSG_NEWKEYS)
        await conn.wait_closed()

    @asynctest
    async def test_invalid_userauth_service(self):
        """Test invalid service in userauth request"""

        conn = await self.connect()

        conn.send_packet(MSG_USERAUTH_REQUEST, String('guest'),
                         String('xxx'), String('none'))

        await conn.wait_closed()

    @asynctest
    async def test_invalid_username(self):
        """Test invalid username in userauth request"""

        conn = await self.connect()

        conn.send_packet(MSG_USERAUTH_REQUEST, String(b'\xff'),
                         String('ssh-connection'), String('none'))

        await conn.wait_closed()

    @asynctest
    async def test_extra_userauth_request(self):
        """Test userauth request after auth is complete"""

        async with self.connect() as conn:
            conn.send_packet(MSG_USERAUTH_REQUEST, String('guest'),
                             String('ssh-connection'), String('none'))
            await asyncio.sleep(0.1)

    @asynctest
    async def test_unexpected_userauth_success(self):
        """Test unexpected userauth success response"""

        with patch.dict('asyncssh.connection.SSHConnection._packet_handlers',
                        {MSG_UNIMPLEMENTED: disconnect_on_unimplemented}):
            conn = await self.connect()
            conn.send_packet(MSG_USERAUTH_SUCCESS)
            await conn.wait_closed()

    @asynctest
    async def test_unexpected_userauth_failure(self):
        """Test unexpected userauth failure response"""

        with patch.dict('asyncssh.connection.SSHConnection._packet_handlers',
                        {MSG_UNIMPLEMENTED: disconnect_on_unimplemented}):
            conn = await self.connect()
            conn.send_packet(MSG_USERAUTH_FAILURE, NameList([]), Boolean(False))
            await conn.wait_closed()

    @asynctest
    async def test_unexpected_userauth_banner(self):
        """Test unexpected userauth banner"""

        conn = await self.connect()
        conn.send_packet(MSG_USERAUTH_BANNER, String(''), String(''))
        await conn.wait_closed()

    @asynctest
    async def test_invalid_global_request(self):
        """Test invalid global request"""

        conn = await self.connect()
        conn.send_packet(MSG_GLOBAL_REQUEST, String(b'\xff'), Boolean(True))
        await conn.wait_closed()

    @asynctest
    async def test_unexpected_global_response(self):
        """Test unexpected global response"""

        conn = await self.connect()
        conn.send_packet(MSG_GLOBAL_REQUEST, String('xxx'), Boolean(True))
        await conn.wait_closed()

    @asynctest
    async def test_invalid_channel_open(self):
        """Test invalid channel open request"""

        conn = await self.connect()

        conn.send_packet(MSG_CHANNEL_OPEN, String(b'\xff'),
                         UInt32(0), UInt32(0), UInt32(0))

        await conn.wait_closed()

    @asynctest
    async def test_unknown_channel_type(self):
        """Test unknown channel open type"""

        conn = await self.connect()

        conn.send_packet(MSG_CHANNEL_OPEN, String('xxx'),
                         UInt32(0), UInt32(0), UInt32(0))

        await conn.wait_closed()

    @asynctest
    async def test_invalid_channel_open_confirmation_number(self):
        """Test invalid channel number in open confirmation"""

        conn = await self.connect()

        conn.send_packet(MSG_CHANNEL_OPEN_CONFIRMATION, UInt32(0xff),
                         UInt32(0), UInt32(0), UInt32(0))

        await conn.wait_closed()

    @asynctest
    async def test_invalid_channel_open_failure_number(self):
        """Test invalid channel number in open failure"""

        conn = await self.connect()

        conn.send_packet(MSG_CHANNEL_OPEN_FAILURE, UInt32(0xff),
                         UInt32(0), String(''), String(''))

        await conn.wait_closed()

    @asynctest
    async def test_invalid_channel_open_failure_reason(self):
        """Test invalid reason in channel open failure"""

        conn = await self.connect()

        conn.send_packet(MSG_CHANNEL_OPEN_FAILURE, UInt32(0),
                         UInt32(0), String(b'\xff'), String(''))

        await conn.wait_closed()

    @asynctest
    async def test_invalid_channel_open_failure_language(self):
        """Test invalid language in channel open failure"""

        conn = await self.connect()

        conn.send_packet(MSG_CHANNEL_OPEN_FAILURE, UInt32(0),
                         UInt32(0), String(''), String(b'\xff'))

        await conn.wait_closed()

    @asynctest
    async def test_missing_data_channel_number(self):
        """Test missing channel number in channel data message"""

        conn = await self.connect()
        conn.send_packet(MSG_CHANNEL_DATA)
        await conn.wait_closed()

    @asynctest
    async def test_invalid_data_channel_number(self):
        """Test invalid channel number in channel data message"""

        conn = await self.connect()
        conn.send_packet(MSG_CHANNEL_DATA, UInt32(99), String(''))
        await conn.wait_closed()

    @asynctest
    async def test_internal_error(self):
        """Test internal error in client callback"""

        with self.assertRaises(RuntimeError):
            await self.create_connection(_InternalErrorClient)


class _TestConnectionAsyncAcceptor(ServerTestCase):
    """Unit test for async acceptor"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server to connect to"""

        async def acceptor(conn):
            """Async cceptor for SSH connections"""

            conn.logger.info('Acceptor called')

        return (await cls.create_server(_TunnelServer, gss_host=(),
                                        acceptor=acceptor))

    @asynctest
    async def test_connect(self):
        """Test acceptor"""

        with self.assertLogs(level='INFO'):
            async with self.connect():
                pass


class _TestConnectionReverse(ServerTestCase):
    """Unit test for reverse direction connections"""

    @classmethod
    async def start_server(cls):
        """Start an SSH listener which opens SSH client connections"""

        def acceptor(conn):
            """Acceptor for reverse-direction SSH connections"""

            conn.logger.info('Reverse acceptor called')

        return await cls.listen_reverse(acceptor=acceptor)

    @asynctest
    async def test_connect_reverse(self):
        """Test reverse direction SSH connection"""

        with self.assertLogs(level='INFO'):
            async with self.connect_reverse():
                pass

    @asynctest
    async def test_connect_reverse_options(self):
        """Test reverse direction SSH connection with options"""

        async with self.connect_reverse(passphrase=None):
            pass

    @asynctest
    async def test_connect_reverse_no_server_host_keys(self):
        """Test starting a reverse direction connection with no host keys"""

        with self.assertRaises(ValueError):
            await self.connect_reverse(server_host_keys=[])


class _TestConnectionReverseAsyncAcceptor(ServerTestCase):
    """Unit test for reverse direction connections with async acceptor"""

    @classmethod
    async def start_server(cls):
        """Start an SSH listener which opens SSH client connections"""

        async def acceptor(conn):
            """Acceptor for reverse-direction SSH connections"""

            conn.logger.info('async acceptor called')

        return await cls.listen_reverse(acceptor=acceptor)

    @asynctest
    async def test_connect_reverse_async_acceptor(self):
        """Test reverse direction SSH connection with async acceptor"""

        with self.assertLogs(level='INFO'):
            async with self.connect_reverse():
                pass


class _TestConnectionReverseFailed(ServerTestCase):
    """Unit test for reverse direction connection failure"""

    @classmethod
    async def start_server(cls):
        """Start an SSH listener which opens SSH client connections"""

        def err_handler(conn, _exc):
            """Error handler for failed SSH handshake"""

            conn.logger.info('Error handler called')

        return (await cls.listen_reverse(username='user',
                                         error_handler=err_handler))

    @asynctest
    async def test_connect_failed(self):
        """Test starting a reverse direction connection which fails"""

        with self.assertLogs(level='INFO'):
            with self.assertRaises(asyncssh.ConnectionLost):
                await self.connect_reverse(authorized_client_keys=[])


class _TestConnectionKeepalive(ServerTestCase):
    """Unit test for keepalive"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which sends keepalive messages"""

        return await cls.create_server(keepalive_interval=0.1)

    @asynctest
    async def test_server_keepalive(self):
        """Test sending keepalive"""

        with patch('asyncssh.connection.SSHClientConnection',
                   _KeepaliveClientConnection):
            conn = await self.connect()
            await conn.wait_closed()


    @asynctest
    async def test_server_keepalive_failure(self):
        """Test server keepalive failure"""

        with patch('asyncssh.connection.SSHClientConnection',
                   _KeepaliveClientConnectionFailure):
            conn = await self.connect()
            await conn.wait_closed()


class _TestConnectionAbort(ServerTestCase):
    """Unit test for connection abort"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which aborts connections during auth"""

        return await cls.create_server(_AbortServer)

    @asynctest
    async def test_abort(self):
        """Test connection abort"""

        with self.assertRaises(asyncssh.ConnectionLost):
            await self.connect()


class _TestDuringAuth(ServerTestCase):
    """Unit test for operations during auth"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which aborts connections during auth"""

        return await cls.create_server(_CloseDuringAuthServer)

    @asynctest
    async def test_close_during_auth(self):
        """Test connection close during long auth callback"""

        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(self.connect(username='user',
                                                password=''), 0.5)

    @asynctest
    async def test_request_during_auth(self):
        """Test sending a request prior to auth complete"""

        with self.assertRaises(asyncssh.ProtocolError):
            await self.create_connection(_PreAuthRequestClient, username='user',
                                         compression_algs=['none'])


@unittest.skipUnless(x509_available, 'X.509 not available')
class _TestServerX509Self(ServerTestCase):
    """Unit test for server with self-signed X.509 host certificate"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server with a self-signed X.509 host certificate"""

        return await cls.create_server(server_host_keys=['skey_x509_self'])

    @asynctest
    async def test_connect_x509_self(self):
        """Test connecting with X.509 self-signed certificate"""

        async with self.connect():
            pass

    @asynctest
    async def test_connect_x509_untrusted_self(self):
        """Test connecting with untrusted X.509 self-signed certficate"""

        with self.assertRaises(asyncssh.HostKeyNotVerifiable):
            await self.connect(x509_trusted_certs='root_ca_cert.pem')

    @asynctest
    async def test_connect_x509_revoked_self(self):
        """Test connecting with revoked X.509 self-signed certficate"""

        with self.assertRaises(asyncssh.HostKeyNotVerifiable):
            await self.connect(known_hosts=([], [], [], ['root_ca_cert.pem'],
                                            ['skey_x509_self.pem'], [], []))

    @asynctest
    async def test_connect_x509_trusted_subject(self):
        """Test connecting to server with trusted X.509 subject name"""

        async with self.connect(known_hosts=([], [], [], [], [],
                                             ['OU=name'], ['OU=name1']),
                                x509_trusted_certs=['skey_x509_self.pem']):
            pass

    @asynctest
    async def test_connect_x509_untrusted_subject(self):
        """Test connecting to server with untrusted X.509 subject name"""

        with self.assertRaises(asyncssh.HostKeyNotVerifiable):
            await self.connect(known_hosts=([], [], [], [], [],
                                            ['OU=name1'], []),
                               x509_trusted_certs=['skey_x509_self.pem'])

    @asynctest
    async def test_connect_x509_revoked_subject(self):
        """Test connecting to server with revoked X.509 subject name"""

        with self.assertRaises(asyncssh.HostKeyNotVerifiable):
            await self.connect(known_hosts=([], [], [], [], [],
                                            [], ['OU=name']),
                               x509_trusted_certs=['skey_x509_self.pem'])

    @asynctest
    async def test_connect_x509_disabled(self):
        """Test connecting to X.509 server with X.509 disabled"""

        with self.assertRaises(asyncssh.HostKeyNotVerifiable):
            await self.connect(known_hosts=([], [], [], [], [],
                                            ['OU=name'], []),
                               x509_trusted_certs=None)

    @unittest.skipIf(sys.platform == 'win32', 'skip chmod tests on Windows')
    @asynctest
    async def test_trusted_x509_certs_not_readable(self):
        """Test connecting with default trusted X509 cert file not readable"""

        try:
            os.chmod(os.path.join('.ssh', 'ca-bundle.crt'), 0)

            with self.assertRaises(asyncssh.HostKeyNotVerifiable):
                await self.connect()
        finally:
            os.chmod(os.path.join('.ssh', 'ca-bundle.crt'), 0o644)


@unittest.skipUnless(x509_available, 'X.509 not available')
class _TestServerX509Chain(ServerTestCase):
    """Unit test for server with X.509 host certificate chain"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server with an X.509 host certificate chain"""

        return await cls.create_server(server_host_keys=['skey_x509_chain'])

    @asynctest
    async def test_connect_x509_chain(self):
        """Test connecting with X.509 certificate chain"""

        async with self.connect(x509_trusted_certs='root_ca_cert.pem'):
            pass

    @asynctest
    async def test_connect_x509_chain_cert_path(self):
        """Test connecting with X.509 certificate and certificate path"""

        async with self.connect(x509_trusted_cert_paths=['cert_path'],
                                known_hosts=b'\n'):
            pass

    @asynctest
    async def test_connect_x509_untrusted_root(self):
        """Test connecting to server with untrusted X.509 root CA"""

        with self.assertRaises(asyncssh.HostKeyNotVerifiable):
            await self.connect()

    @asynctest
    async def test_connect_x509_untrusted_root_cert_path(self):
        """Test connecting to server with untrusted X.509 root CA"""

        with self.assertRaises(asyncssh.HostKeyNotVerifiable):
            await self.connect(known_hosts=b'\n')

    @asynctest
    async def test_connect_x509_revoked_intermediate(self):
        """Test connecting to server with revoked X.509 intermediate CA"""

        with self.assertRaises(asyncssh.HostKeyNotVerifiable):
            await self.connect(known_hosts=([], [], [], ['root_ca_cert.pem'],
                                            ['int_ca_cert.pem'], [], []))

    @asynctest
    async def test_invalid_x509_path(self):
        """Test passing in invalid trusted X.509 certificate path"""

        with self.assertRaises(ValueError):
            await self.connect(x509_trusted_cert_paths='xxx')


@unittest.skipUnless(gss_available, 'GSS not available')
@patch_gss
class _TestServerNoHostKey(ServerTestCase):
    """Unit test for server with no server host key"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which sets no server host keys"""

        return await cls.create_server(server_host_keys=None, gss_host='1')

    @asynctest
    async def test_gss_with_no_host_key(self):
        """Test GSS key exchange with no server host key specified"""

        async with self.connect(known_hosts=b'\n', gss_host='1',
                                x509_trusted_certs=None,
                                x509_trusted_cert_paths=None):
            pass

    @asynctest
    async def test_dh_with_no_host_key(self):
        """Test failure of DH key exchange with no server host key specified"""

        with self.assertRaises(asyncssh.KeyExchangeFailed):
            await self.connect()


class _TestServerWithoutCert(ServerTestCase):
    """Unit tests with a server that advertises a host key instead of a cert"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server to connect to"""

        return await cls.create_server(server_host_keys=[('skey', None)])

    @asynctest
    async def test_validate_host_key_callback(self):
        """Test callback to validate server host key"""

        def client_factory():
            """Return an SSHClient which can validate the sevrer host key"""

            return _ValidateHostKeyClient(host_key='skey.pub')

        conn, _ = await self.create_connection(client_factory,
                                               known_hosts=([], [], []))

        async with conn:
            pass

    @asynctest
    async def test_validate_host_key_callback_with_algs(self):
        """Test callback to validate server host key with alg list"""

        def client_factory():
            """Return an SSHClient which can validate the sevrer host key"""

            return _ValidateHostKeyClient(host_key='skey.pub')

        algs = [asyncssh.read_public_key('skey.pub').get_algorithm()]

        conn, _ = await self.create_connection(client_factory,
                                               known_hosts=([], [], []),
                                               server_host_key_algs=algs)

        async with conn:
            pass

    @asynctest
    async def test_untrusted_known_hosts_key(self):
        """Test untrusted server host key"""

        with self.assertRaises(asyncssh.HostKeyNotVerifiable):
            await self.connect(known_hosts=(['ckey.pub'], [], []))

    @asynctest
    async def test_known_hosts_none_with_key(self):
        """Test disabled known hosts checking with server host key"""

        async with self.connect(known_hosts=None):
            pass


class _TestServerInternalError(ServerTestCase):
    """Unit test for server internal error during auth"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which raises an error during auth"""

        return await cls.create_server(_InternalErrorServer)

    @asynctest
    async def test_server_internal_error(self):
        """Test server internal error during auth"""

        with self.assertRaises(asyncssh.ConnectionLost):
            await self.connect()


class _TestInvalidAuthBanner(ServerTestCase):
    """Unit test for invalid auth banner"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which sends invalid auth banner"""

        return await cls.create_server(_InvalidAuthBannerServer)

    @asynctest
    async def test_invalid_auth_banner(self):
        """Test server sending invalid auth banner"""

        with self.assertRaises(asyncssh.ProtocolError):
            await self.connect()


class _TestExpiredServerHostCertificate(ServerTestCase):
    """Unit tests for expired server host certificate"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server with an expired host certificate"""

        return await cls.create_server(server_host_keys=['exp_skey'])

    @asynctest
    async def test_expired_server_host_cert(self):
        """Test expired server host certificate"""

        with self.assertRaises(asyncssh.HostKeyNotVerifiable):
            await self.connect(known_hosts=([], ['skey.pub'], []))

    @asynctest
    async def test_known_hosts_none_with_expired_cert(self):
        """Test disabled known hosts checking with expired host certificate"""

        async with self.connect(known_hosts=None):
            pass


class _TestCustomClientVersion(ServerTestCase):
    """Unit test for custom SSH client version"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which sends client version in auth banner"""

        return await cls.create_server(_VersionReportingServer)

    async def _check_client_version(self, version):
        """Check custom client version"""

        conn, client = \
            await self.create_connection(_VersionRecordingClient,
                                         client_version=version)

        async with conn:
            self.assertEqual(client.reported_version, 'SSH-2.0-custom')

    @asynctest
    async def test_custom_client_version(self):
        """Test custom client version"""

        await self._check_client_version('custom')

    @asynctest
    async def test_custom_client_version_bytes(self):
        """Test custom client version set as bytes"""

        await self._check_client_version(b'custom')

    @asynctest
    async def test_long_client_version(self):
        """Test client version which is too long"""

        with self.assertRaises(ValueError):
            await self.connect(client_version=246*'a')

    @asynctest
    async def test_nonprintable_client_version(self):
        """Test client version with non-printable character"""

        with self.assertRaises(ValueError):
            await self.connect(client_version='xxx\0')


class _TestCustomServerVersion(ServerTestCase):
    """Unit test for custom SSH server version"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which sends a custom version"""

        return await cls.create_server(server_version='custom')

    @asynctest
    async def test_custom_server_version(self):
        """Test custom server version"""

        async with self.connect() as conn:
            version = conn.get_extra_info('server_version')
            self.assertEqual(version, 'SSH-2.0-custom')

    @asynctest
    async def test_long_server_version(self):
        """Test server version which is too long"""

        with self.assertRaises(ValueError):
            await self.create_server(server_version=246*'a')

    @asynctest
    async def test_nonprintable_server_version(self):
        """Test server version with non-printable character"""

        with self.assertRaises(ValueError):
            await self.create_server(server_version='xxx\0')
