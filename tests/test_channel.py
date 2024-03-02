# Copyright (c) 2016-2024 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Unit tests for AsyncSSH channel API"""

import asyncio
import os
import tempfile
from signal import SIGINT

from unittest.mock import patch

import asyncssh

from asyncssh.constants import DEFAULT_LANG, MSG_USERAUTH_REQUEST
from asyncssh.constants import MSG_CHANNEL_OPEN_CONFIRMATION
from asyncssh.constants import MSG_CHANNEL_OPEN_FAILURE
from asyncssh.constants import MSG_CHANNEL_WINDOW_ADJUST
from asyncssh.constants import MSG_CHANNEL_DATA
from asyncssh.constants import MSG_CHANNEL_EXTENDED_DATA
from asyncssh.constants import MSG_CHANNEL_EOF, MSG_CHANNEL_CLOSE
from asyncssh.constants import MSG_CHANNEL_SUCCESS
from asyncssh.packet import Byte, String, UInt32
from asyncssh.public_key import CERT_TYPE_USER
from asyncssh.stream import SSHTCPStreamSession, SSHUNIXStreamSession
from asyncssh.stream import SSHTunTapStreamSession
from asyncssh.tuntap import SSH_TUN_MODE_POINTTOPOINT, SSH_TUN_MODE_ETHERNET

from .server import Server, ServerTestCase
from .util import asynctest, echo, make_certificate

PTY_OP_PARTIAL = 158
PTY_OP_NO_END = 159

class _ClientChannel(asyncssh.SSHClientChannel):
    """Patched SSH client channel for unit testing"""

    def _send_request(self, request, *args, want_reply=False):
        """Send a channel request"""

        if request == b'env' and args[1] == String('invalid'):
            args = args[:1] + (String(b'\xff'),)
        elif request == b'pty-req':
            if args[5][-6:-5] == Byte(PTY_OP_PARTIAL):
                args = args[:5] + (String(args[5][4:-5]),)
            elif args[5][-6:-5] == Byte(PTY_OP_NO_END):
                args = args[:5] + (String(args[5][4:-6]),)

        super()._send_request(request, *args, want_reply=want_reply)

    def get_send_pktsize(self):
        """Return the sender's max packet size """

        return self._send_pktsize

    def send_request(self, request, *args):
        """Send a custom request (for unit testing)"""

        self._send_request(request, *args)

    async def make_request(self, request, *args):
        """Make a custom request (for unit testing)"""

        return await self._make_request(request, *args)


class _ClientSession(asyncssh.SSHClientSession):
    """Unit test SSH client session"""

    def __init__(self):
        self._chan = None

        self.recv_buf = {None: [], asyncssh.EXTENDED_DATA_STDERR: []}
        self.xon_xoff = None
        self.exit_status = None
        self.exit_signal_msg = None
        self.exc = None

    def connection_made(self, chan):
        """Handle connection open"""

        self._chan = chan

    def connection_lost(self, exc):
        """Handle connection close"""

        self.exc = exc
        self._chan = None

    def data_received(self, data, datatype):
        """Handle data from the channel"""

        self.recv_buf[datatype].append(data)

    def xon_xoff_requested(self, client_can_do):
        """Handle request to enable/disable XON/XOFF flow control"""

        self.xon_xoff = client_can_do

    def exit_status_received(self, status):
        """Handle remote exit status"""

        # pylint: disable=unused-argument

        self.exit_status = status

    def exit_signal_received(self, signal, core_dumped, msg, lang):
        """Handle remote exit signal"""

        # pylint: disable=unused-argument

        self.exit_signal_msg = msg


async def _create_session(conn, command=None, *, subsystem=None, **kwargs):
    """Create a client session"""

    return await conn.create_session(_ClientSession, command,
                                     subsystem=subsystem, **kwargs)


class _ServerChannel(asyncssh.SSHServerChannel):
    """Patched SSH server channel class for unit testing"""

    def _send_request(self, request, *args, want_reply=False):
        """Send a channel request"""

        if request == b'exit-signal':
            if args[0] == String('invalid'):
                args = (String(b'\xff'),) + args[1:]

            if args[3] == String('invalid'):
                args = args[:3] + (String(b'\xff'),)

        super()._send_request(request, *args, want_reply=want_reply)

    def _process_delayed_request(self, packet):
        """Process a request that delays before responding"""

        packet.check_end()

        asyncio.get_event_loop().call_later(0.1, self._report_response, True)

    def get_send_pktsize(self):
        """Return the sender's max packet size """

        return self._send_pktsize

    async def open_session(self):
        """Attempt to open a session on the client"""

        return await self._open(b'session')


class _EchoServerSession(asyncssh.SSHServerSession):
    """A shell session which echoes data from stdin to stdout/stderr"""

    def __init__(self):
        self._chan = None

    def connection_made(self, chan):
        """Handle session open"""

        self._chan = chan

        username = self._chan.get_extra_info('username')

        if username == 'close':
            self._chan.close()
        elif username == 'task_error':
            raise RuntimeError('Exception handler test')

    def shell_requested(self):
        """Handle shell request"""

        return True

    def data_received(self, data, datatype):
        """Handle data from the channel"""

        self._chan.write(data[:1])
        self._chan.writelines([data[1:]])
        self._chan.write_stderr(data[:1])
        self._chan.writelines_stderr([data[1:]])

    def eof_received(self):
        """Handle EOF on the channel"""

        self._chan.write_eof()
        self._chan.close()


class _PTYServerSession(asyncssh.SSHServerSession):
    """Server for testing PTY requests"""

    def __init__(self):
        self._chan = None
        self._pty_ok = True

    def connection_made(self, chan):
        """Handle session open"""

        self._chan = chan

        username = self._chan.get_extra_info('username')

        if username == 'no_pty':
            self._pty_ok = False

    def pty_requested(self, term_type, term_size, term_modes):
        """Handle pseudo-terminal request"""

        self._chan.set_extra_info(
            pty_args=(term_type, term_size,
                      term_modes.get(asyncssh.PTY_OP_OSPEED)))

        return self._pty_ok

    def shell_requested(self):
        """Handle shell request"""

        return True

    def session_started(self):
        """Handle session start"""

        chan = self._chan


        chan.write(f'Req: {chan.get_extra_info("pty_args")}\n')
        chan.close()


class _ChannelServer(Server):
    """Server for testing the AsyncSSH channel API"""

    async def _begin_session(self, stdin, stdout, stderr):
        """Begin processing a new session"""

        # pylint: disable=too-many-statements

        action = stdin.channel.get_command() or stdin.channel.get_subsystem()
        if not action:
            action = 'echo'

        if action == 'echo':
            await echo(stdin, stdout, stderr)
        elif action == 'conn_close':
            await stdin.read(1)
            stdout.write('\n')
            self._conn.close()
        elif action == 'close':
            await stdin.read(1)
            stdout.write('\n')
        elif action == 'agent':
            try:
                async with asyncssh.connect_agent(self._conn) as agent:
                    stdout.write(str(len((await agent.get_keys()))) + '\n')
            except (OSError, asyncssh.ChannelOpenError):
                stdout.channel.exit(1)
        elif action == 'agent_sock':
            agent_path = stdin.channel.get_agent_path()

            if agent_path:
                async with asyncssh.connect_agent(agent_path) as agent:
                    await asyncio.sleep(0.1)
                    stdout.write(str(len((await agent.get_keys()))) + '\n')
            else:
                stdout.channel.exit(1)
        elif action == 'rejected_agent':
            agent_path = stdin.channel.get_agent_path()
            stdout.write(str(bool(agent_path)) + '\n')

            chan = self._conn.create_agent_channel()

            try:
                await chan.open(SSHUNIXStreamSession)
            except asyncssh.ChannelOpenError:
                stdout.channel.exit(1)
        elif action == 'rejected_session':
            chan = _ServerChannel(self._conn, asyncio.get_event_loop(),
                                  False, False, False, 0, 1024, None,
                                  'strict', 1, 32768)

            try:
                await chan.open_session()
            except asyncssh.ChannelOpenError:
                stdout.channel.exit(1)
        elif action == 'rejected_tcpip_direct':
            chan = self._conn.create_tcp_channel()

            try:
                await chan.connect(SSHTCPStreamSession, '', 0, '', 0)
            except asyncssh.ChannelOpenError:
                stdout.channel.exit(1)
        elif action == 'unknown_tcpip_listener':
            chan = self._conn.create_tcp_channel()

            try:
                await chan.accept(SSHTCPStreamSession, 'xxx', 0, '', 0)
            except asyncssh.ChannelOpenError:
                stdout.channel.exit(1)
        elif action == 'invalid_tcpip_listener':
            chan = self._conn.create_tcp_channel()

            try:
                await chan.accept(SSHTCPStreamSession, b'\xff', 0, '', 0)
            except asyncssh.ChannelOpenError:
                stdout.channel.exit(1)
        elif action == 'rejected_unix_direct':
            chan = self._conn.create_unix_channel()

            try:
                await chan.connect(SSHUNIXStreamSession, '')
            except asyncssh.ChannelOpenError:
                stdout.channel.exit(1)
        elif action == 'unknown_unix_listener':
            chan = self._conn.create_unix_channel()

            try:
                await chan.accept(SSHUNIXStreamSession, 'xxx')
            except asyncssh.ChannelOpenError:
                stdout.channel.exit(1)
        elif action == 'invalid_unix_listener':
            chan = self._conn.create_unix_channel()

            try:
                await chan.accept(SSHUNIXStreamSession, b'\xff')
            except asyncssh.ChannelOpenError:
                stdout.channel.exit(1)
        elif action == 'rejected_tun_request':
            chan = self._conn.create_tuntap_channel()

            try:
                await chan.open(SSHTunTapStreamSession,
                                SSH_TUN_MODE_POINTTOPOINT, 0)
            except asyncssh.ChannelOpenError:
                stdout.channel.exit(1)
        elif action == 'rejected_tap_request':
            chan = self._conn.create_tuntap_channel()

            try:
                await chan.open(SSHTunTapStreamSession,
                                SSH_TUN_MODE_ETHERNET, 0)
            except asyncssh.ChannelOpenError:
                stdout.channel.exit(1)
        elif action == 'late_auth_banner':
            try:
                self._conn.send_auth_banner('auth banner')
            except OSError:
                stdin.channel.exit(1)
        elif action == 'invalid_open_confirm':
            stdin.channel.send_packet(MSG_CHANNEL_OPEN_CONFIRMATION,
                                      UInt32(0), UInt32(0), UInt32(0))
        elif action == 'invalid_open_failure':
            stdin.channel.send_packet(MSG_CHANNEL_OPEN_FAILURE,
                                      UInt32(0), String(''), String(''))
        elif action == 'env':
            value = stdin.channel.get_environment().get('TEST', '')
            stdout.write(value + '\n')
        elif action == 'term':
            chan = stdin.channel
            info = str((chan.get_terminal_type(), chan.get_terminal_size(),
                        chan.get_terminal_mode(asyncssh.PTY_OP_OSPEED)))
            stdout.write(info + '\n')
        elif action == 'xon_xoff':
            stdin.channel.set_xon_xoff(True)
        elif action == 'no_xon_xoff':
            stdin.channel.set_xon_xoff(False)
        elif action == 'signals':
            try:
                await stdin.readline()
            except asyncssh.BreakReceived as exc:
                stdin.channel.exit_with_signal('ABRT', False, str(exc.msec))
            except asyncssh.SignalReceived as exc:
                stdin.channel.exit_with_signal('ABRT', False, exc.signal)
            except asyncssh.TerminalSizeChanged as exc:
                size = (exc.width, exc.height, exc.pixwidth, exc.pixheight)
                stdin.channel.exit_with_signal('ABRT', False, str(size))
        elif action == 'exit_status':
            stdin.channel.exit(1)
        elif action == 'closed_status':
            stdin.channel.close()
            stdin.channel.exit(1)
        elif action == 'exit_signal':
            stdin.channel.exit_with_signal('INT', False, 'exit_signal')
        elif action == 'unknown_signal':
            stdin.channel.exit_with_signal('unknown', False, 'unknown_signal')
        elif action == 'closed_signal':
            stdin.channel.close()
            stdin.channel.exit_with_signal('INT', False, 'closed_signal')
        elif action == 'invalid_exit_signal':
            stdin.channel.exit_with_signal('invalid')
        elif action == 'invalid_exit_lang':
            stdin.channel.exit_with_signal('INT', False, '', 'invalid')
        elif action == 'window_after_close':
            stdin.channel.send_packet(MSG_CHANNEL_CLOSE)
            stdin.channel.send_packet(MSG_CHANNEL_WINDOW_ADJUST, UInt32(0))
        elif action == 'empty_data':
            stdin.channel.send_packet(MSG_CHANNEL_DATA, String(''))
        elif action == 'partial_unicode':
            data = '\xff\xff'.encode('utf-8')
            stdin.channel.send_packet(MSG_CHANNEL_DATA, String(data[:3]))
            stdin.channel.send_packet(MSG_CHANNEL_DATA, String(data[3:]))
        elif action == 'partial_unicode_at_eof':
            data = '\xff\xff'.encode('utf-8')
            stdin.channel.send_packet(MSG_CHANNEL_DATA, String(data[:3]))
        elif action == 'unicode_error':
            stdin.channel.send_packet(MSG_CHANNEL_DATA, String(b'\xff'))
        elif action == 'data_past_window':
            stdin.channel.send_packet(MSG_CHANNEL_DATA,
                                      String(2*1025*1024*'\0'))
        elif action == 'ext_data_past_window':
            stdin.channel.send_packet(MSG_CHANNEL_EXTENDED_DATA,
                                      UInt32(asyncssh.EXTENDED_DATA_STDERR),
                                      String(2*1025*1024*'\0'))
        elif action == 'data_after_eof':
            stdin.channel.send_packet(MSG_CHANNEL_EOF)
            stdout.write('xxx')
        elif action == 'data_after_close':
            await asyncio.sleep(0.1)
            stdout.write('xxx')
        elif action == 'ext_data_after_eof':
            stdin.channel.send_packet(MSG_CHANNEL_EOF)
            stdin.channel.write_stderr('xxx')
        elif action == 'invalid_datatype':
            stdin.channel.send_packet(MSG_CHANNEL_EXTENDED_DATA,
                                      UInt32(255), String(''))
        elif action == 'double_eof':
            await asyncio.sleep(0.1)
            stdin.channel.send_packet(MSG_CHANNEL_EOF)
            stdin.channel.write_eof()
        elif action == 'double_close':
            await asyncio.sleep(0.1)
            stdout.write('xxx')
            stdin.channel.send_packet(MSG_CHANNEL_CLOSE)
        elif action == 'request_after_close':
            stdin.channel.send_packet(MSG_CHANNEL_CLOSE)
            stdin.channel.exit(1)
        elif action == 'unexpected_auth':
            self._conn.send_packet(MSG_USERAUTH_REQUEST, String('guest'),
                                   String('ssh-connection'), String('none'))
        elif action == 'invalid_response':
            stdin.channel.send_packet(MSG_CHANNEL_SUCCESS)
        elif action == 'send_pktsize':
            stdout.write(str(stdout.channel.get_send_pktsize()))
            stdout.close()
        else:
            stdin.channel.exit(255)

        stdin.channel.close()
        await stdin.channel.wait_closed()

    async def _conn_close(self):
        """Close the connection during a channel open"""

        self._conn.close()
        await asyncio.sleep(0.1)
        return _EchoServerSession()

    def begin_auth(self, username):
        """Handle client authentication request"""

        return username not in {'guest', 'conn_close_startup',
                                'conn_close_open', 'close', 'echo',
                                'no_channels', 'no_pty', 'request_pty',
                                'task_error'}

    def session_requested(self):
        """Handle a request to create a new session"""

        username = self._conn.get_extra_info('username')

        with patch('asyncssh.connection.SSHServerChannel', _ServerChannel):
            channel = self._conn.create_server_channel()

            if username == 'conn_close_startup':
                self._conn.close()
                return False
            elif username == 'conn_close_open':
                return (channel, self._conn_close())
            elif username in {'close', 'echo', 'task_error'}:
                return (channel, _EchoServerSession())
            elif username in {'request_pty', 'no_pty'}:
                return (channel, _PTYServerSession())
            elif username != 'no_channels':
                return (channel, self._begin_session)
            else:
                return False


class _TestChannel(ServerTestCase):
    """Unit tests for AsyncSSH channel API"""

    # pylint: disable=too-many-public-methods

    @classmethod
    async def start_server(cls):
        """Start an SSH server for the tests to use"""

        return (await cls.create_server(
            _ChannelServer, authorized_client_keys='authorized_keys'))

    async def _check_action(self, command, expected_result):
        """Run a command on a remote session and check for a specific result"""

        async with self.connect() as conn:
            chan, session = await _create_session(conn, command)

            await chan.wait_closed()

            self.assertEqual(session.exit_status, expected_result)

    async def _check_session(self, conn, command=(), *,
                             large_block=False, **kwargs):
        """Open a session and test if an input line is echoed back"""

        chan, session = await _create_session(conn, command, **kwargs)

        if large_block:
            data = 4 * [1025*1024*'\0']
        else:
            data = [str(id(self))]

        chan.writelines(data)

        self.assertTrue(chan.can_write_eof())
        self.assertFalse(chan.is_closing())
        chan.write_eof()
        self.assertTrue(chan.is_closing())

        await chan.wait_closed()

        data = ''.join(data)

        for buf in session.recv_buf.values():
            self.assertEqual(data, ''.join(buf))

        chan.close()

    @asynctest
    async def test_shell(self):
        """Test starting a shell"""

        async with self.connect(username='echo') as conn:
            await self._check_session(conn)

    @asynctest
    async def test_shell_failure(self):
        """Test failure to start a shell"""

        async with self.connect(username='no_channels') as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                await _create_session(conn)

    @asynctest
    async def test_shell_internal_error(self):
        """Test internal error in callback to start a shell"""

        async with self.connect(username='task_error') as conn:
            with self.assertRaises((OSError, asyncssh.ConnectionLost)):
                await _create_session(conn)

    @asynctest
    async def test_shell_large_block(self):
        """Test starting a shell and sending a large block of data"""

        async with self.connect(username='echo') as conn:
            await self._check_session(conn, large_block=True)

    @asynctest
    async def test_exec(self):
        """Test execution of a remote command"""

        async with self.connect() as conn:
            await self._check_session(conn, 'echo', window=1024*1024,
                                      max_pktsize=16384)

    @asynctest
    async def test_exec_from_connect(self):
        """Test execution of a remote command set on connection"""

        async with self.connect(command='echo') as conn:
            await self._check_session(conn)

    @asynctest
    async def test_forced_exec(self):
        """Test execution of a forced remote command"""

        ckey = asyncssh.read_private_key('ckey')
        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_USER, ckey, ckey, ['ckey'],
                                options={'force-command': String('echo')})

        async with self.connect(username='ckey', client_keys=[(ckey, cert)],
                                agent_path=None) as conn:
            await self._check_session(conn)

    @asynctest
    async def test_invalid_exec(self):
        """Test execution of an invalid remote command"""

        async with self.connect() as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                await _create_session(conn, b'\xff')

    @asynctest
    async def test_exec_failure(self):
        """Test failure to execute a remote command"""

        async with self.connect(username='no_channels') as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                await _create_session(conn, 'echo')

    @asynctest
    async def test_subsystem(self):
        """Test starting a subsystem"""

        async with self.connect() as conn:
            await self._check_session(conn, subsystem='echo')

    @asynctest
    async def test_invalid_subsystem(self):
        """Test starting an invalid subsystem"""

        async with self.connect() as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                await _create_session(conn, subsystem=b'\xff')

    @asynctest
    async def test_subsystem_failure(self):
        """Test failure to start a subsystem"""

        async with self.connect(username='no_channels') as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                await _create_session(conn, subsystem='echo')

    @asynctest
    async def test_conn_close_during_startup(self):
        """Test connection close during channel startup"""

        async with self.connect(username='conn_close_startup') as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                await _create_session(conn)

    @asynctest
    async def test_conn_close_during_open(self):
        """Test connection close during channel open"""

        async with self.connect(username='conn_close_open') as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                await _create_session(conn)

    @asynctest
    async def test_close_during_startup(self):
        """Test channel close during startup"""

        async with self.connect(username='close') as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                await _create_session(conn)

    @asynctest
    async def test_inbound_conn_close_while_read_paused(self):
        """Test inbound connection close while reading is paused"""

        async with self.connect() as conn:
            chan, _ = await _create_session(conn, 'conn_close')

            chan.pause_reading()
            chan.write('\n')
            await asyncio.sleep(0.1)
            conn.close()

            await chan.wait_closed()

    @asynctest
    async def test_outbound_conn_close_while_read_paused(self):
        """Test outbound connection close while reading is paused"""

        async with self.connect() as conn:
            chan, _ = await _create_session(conn, 'close')

            chan.pause_reading()
            chan.write('\n')
            await asyncio.sleep(0.1)
            conn.close()

            await chan.wait_closed()

    @asynctest
    async def test_close_while_read_paused(self):
        """Test closing a remotely closed channel while reading is paused"""

        async with self.connect() as conn:
            chan, _ = await _create_session(conn, 'close')

            chan.pause_reading()
            chan.write('\n')
            await asyncio.sleep(0.1)
            chan.close()

            await chan.wait_closed()

    @asynctest
    async def test_keepalive(self):
        """Test keepalive channel requests"""

        with patch('asyncssh.connection.SSHClientChannel', _ClientChannel):
            async with self.connect() as conn:
                chan, _ = await _create_session(conn)

                result = await chan.make_request(b'keepalive@openssh.com')
                self.assertFalse(result)

    @asynctest
    async def test_invalid_open_confirmation(self):
        """Test receiving an open confirmation on already open channel"""

        async with self.connect() as conn:
            chan, _ = await _create_session(conn, 'invalid_open_confirm')

            await chan.wait_closed()

    @asynctest
    async def test_invalid_open_failure(self):
        """Test receiving an open failure on already open channel"""

        async with self.connect() as conn:
            chan, _ = await _create_session(conn, 'invalid_open_failure')

            await chan.wait_closed()

    @asynctest
    async def test_unknown_channel_request(self):
        """Test sending unknown channel request"""

        with patch('asyncssh.connection.SSHClientChannel', _ClientChannel):
            async with self.connect() as conn:
                chan, _ = await _create_session(conn)

                self.assertFalse((await chan.make_request('unknown')))

    @asynctest
    async def test_invalid_channel_request(self):
        """Test sending non-ASCII channel request"""

        with patch('asyncssh.connection.SSHClientChannel', _ClientChannel):
            async with self.connect() as conn:
                chan, _ = await _create_session(conn)

                with self.assertRaises(asyncssh.ProtocolError):
                    await chan.make_request('\xff')

    @asynctest
    async def test_delayed_channel_request(self):
        """Test queuing channel requests with delayed response"""

        with patch('asyncssh.connection.SSHClientChannel', _ClientChannel):
            async with self.connect() as conn:
                chan, _ = await _create_session(conn)

                chan.send_request(b'delayed')
                chan.send_request(b'delayed')

    @asynctest
    async def test_invalid_channel_response(self):
        """Test receiving response for non-existent channel request"""

        async with self.connect() as conn:
            chan, _ = await _create_session(conn, 'invalid_response')

            chan.close()

    @asynctest
    async def test_already_open(self):
        """Test connect on an already open channel"""

        async with self.connect() as conn:
            chan, _ = await _create_session(conn)

            with self.assertRaises(OSError):
                await chan.create(None, None, None, {}, False, None, None,
                                  None, False, None, None, False, False)

            chan.close()

    @asynctest
    async def test_write_buffer(self):
        """Test setting write buffer limits"""

        async with self.connect() as conn:
            chan, _ = await _create_session(conn)

            chan.set_write_buffer_limits()
            chan.set_write_buffer_limits(low=8192)
            chan.set_write_buffer_limits(high=32768)
            chan.set_write_buffer_limits(32768, 8192)

            with self.assertRaises(ValueError):
                chan.set_write_buffer_limits(8192, 32768)

            self.assertEqual(chan.get_write_buffer_size(), 0)

            chan.close()

    @asynctest
    async def test_empty_write(self):
        """Test writing an empty block of data"""

        async with self.connect() as conn:
            chan, _ = await _create_session(conn)
            chan.write('')
            chan.close()

    @asynctest
    async def test_invalid_write_extended(self):
        """Test writing using an invalid extended data type"""

        async with self.connect() as conn:
            chan, _ = await _create_session(conn)

            with self.assertRaises(OSError):
                chan.write('test', -1)

    @asynctest
    async def test_unneeded_resume_reading(self):
        """Test resume reading when not paused"""

        async with self.connect() as conn:
            chan, _ = await _create_session(conn)
            await asyncio.sleep(0.1)
            chan.resume_reading()
            chan.close()

    @asynctest
    async def test_agent_forwarding(self):
        """Test SSH agent forwarding"""

        if not self.agent_available(): # pragma: no cover
            self.skipTest('ssh-agent not available')

        async with self.connect(username='ckey',
                                agent_forwarding=True) as conn:
            chan, session = await _create_session(conn, 'agent')

            await chan.wait_closed()

            result = ''.join(session.recv_buf[None])
            self.assertEqual(result, '3\n')

            chan, session = await _create_session(conn, 'agent')

            await chan.wait_closed()

            result = ''.join(session.recv_buf[None])
            self.assertEqual(result, '3\n')

    @asynctest
    async def test_agent_forwarding_sock(self):
        """Test SSH agent forwarding via UNIX domain socket"""

        if not self.agent_available(): # pragma: no cover
            self.skipTest('ssh-agent not available')

        async with self.connect(username='ckey',
                                agent_forwarding=True) as conn:
            chan, session = await _create_session(conn, 'agent_sock')

            await chan.wait_closed()

            result = ''.join(session.recv_buf[None])
            self.assertEqual(result, '3\n')

    @asynctest
    async def test_rejected_session(self):
        """Test receiving inbound session request"""

        await self._check_action('rejected_session', 1)

    @asynctest
    async def test_rejected_tcpip_direct(self):
        """Test receiving inbound direct TCP/IP connection"""

        await self._check_action('rejected_tcpip_direct', 1)

    @asynctest
    async def test_unknown_tcpip_listener(self):
        """Test receiving connection on unknown TCP/IP listener"""

        await self._check_action('unknown_tcpip_listener', 1)

    @asynctest
    async def test_invalid_tcpip_listener(self):
        """Test receiving connection on invalid TCP/IP listener path"""

        await self._check_action('invalid_tcpip_listener', None)

    @asynctest
    async def test_rejected_unix_direct(self):
        """Test receiving inbound direct UNIX connection"""

        await self._check_action('rejected_unix_direct', 1)

    @asynctest
    async def test_unknown_unix_listener(self):
        """Test receiving connection on unknown UNIX listener"""

        await self._check_action('unknown_unix_listener', 1)

    @asynctest
    async def test_invalid_unix_listener(self):
        """Test receiving connection on invalid UNIX listener path"""

        await self._check_action('invalid_unix_listener', None)

    @asynctest
    async def test_rejected_tun_request(self):
        """Test receiving inbound TUN request"""

        await self._check_action('rejected_tun_request', 1)

    @asynctest
    async def test_rejected_tap_request(self):
        """Test receiving inbound TAP request"""

        await self._check_action('rejected_tap_request', 1)

    @asynctest
    async def test_agent_forwarding_failure(self):
        """Test failure of SSH agent forwarding"""

        ckey = asyncssh.read_private_key('ckey')
        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_USER, ckey, ckey, ['ckey'],
                                extensions={'no-agent-forwarding': ''})

        async with self.connect(username='ckey', client_keys=[(ckey, cert)],
                                agent_path=None, agent_forwarding=True) as conn:
            chan, session = await _create_session(conn, 'agent')

            await chan.wait_closed()

            self.assertEqual(session.exit_status, 1)

    @asynctest
    async def test_agent_forwarding_sock_failure(self):
        """Test failure to create SSH agent forwarding socket"""

        old_tempdir = tempfile.tempdir

        try:
            tempfile.tempdir = 'xxx'

            async with self.connect(username='ckey',
                                    agent_forwarding=True) as conn:
                chan, session = await _create_session(conn, 'agent_sock')

                await chan.wait_closed()

                self.assertEqual(session.exit_status, 1)
        finally:
            tempfile.tempdir = old_tempdir

    @asynctest
    async def test_agent_forwarding_not_offered(self):
        """Test SSH agent forwarding not offered by client"""

        async with self.connect() as conn:
            chan, session = await _create_session(conn, 'agent')

            await chan.wait_closed()

            self.assertEqual(session.exit_status, 1)

    @asynctest
    async def test_agent_forwarding_rejected(self):
        """Test rejection of SSH agent forwarding by client"""

        async with self.connect() as conn:
            chan, session = await _create_session(conn, 'rejected_agent')

            await chan.wait_closed()

            result = ''.join(session.recv_buf[None])
            self.assertEqual(result, 'False\n')

            self.assertEqual(session.exit_status, 1)

    @asynctest
    async def test_request_pty(self):
        """Test reuquesting a PTY with terminal information"""

        modes = {asyncssh.PTY_OP_OSPEED: 9600}

        async with self.connect(username='request_pty') as conn:
            chan, session = await _create_session(conn, term_type='ansi',
                                                  term_size=(80, 24),
                                                  term_modes=modes)

            await chan.wait_closed()

            result = ''.join(session.recv_buf[None])
            self.assertEqual(result, "Req: ('ansi', (80, 24, 0, 0), 9600)\r\n")

    @asynctest
    async def test_terminal_full_size(self):
        """Test sending terminal information with full size"""

        modes = {asyncssh.PTY_OP_OSPEED: 9600}

        async with self.connect() as conn:
            chan, session = await _create_session(conn, 'term',
                                                  term_type='ansi',
                                                  term_size=(80, 24, 480, 240),
                                                  term_modes=modes)

            await chan.wait_closed()

            result = ''.join(session.recv_buf[None])
            self.assertEqual(result, "('ansi', (80, 24, 480, 240), 9600)\r\n")

    @asynctest
    async def test_pty_without_term_type(self):
        """Test requesting a PTY without setting the terminal type"""

        async with self.connect() as conn:
            chan, session = await _create_session(conn, 'term',
                                                  request_pty='force')

            await chan.wait_closed()

            result = ''.join(session.recv_buf[None])
            self.assertEqual(result, "('', (0, 0, 0, 0), None)\n")

    @asynctest
    async def test_invalid_terminal_size(self):
        """Test sending invalid terminal size"""

        async with self.connect() as conn:
            with self.assertRaises(ValueError):
                await _create_session(conn, 'term', term_type='ansi',
                                      term_size=(0, 0, 0))

    @asynctest
    async def test_invalid_terminal_modes(self):
        """Test sending invalid terminal modes"""

        modes = {asyncssh.PTY_OP_RESERVED: 0}

        async with self.connect() as conn:
            with self.assertRaises(ValueError):
                await _create_session(conn, 'term', term_type='ansi',
                                      term_modes=modes)

    @asynctest
    async def test_pty_disallowed_by_cert(self):
        """Test rejection of pty request by certificate"""

        ckey = asyncssh.read_private_key('ckey')
        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_USER, ckey, ckey, ['ckey'],
                                extensions={'no-pty': ''})

        async with self.connect(username='ckey', client_keys=[(ckey, cert)],
                                agent_path=None) as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                await _create_session(conn, 'term', term_type='ansi')

    @asynctest
    async def test_pty_disallowed_by_session(self):
        """Test rejection of pty request by session"""

        async with self.connect(username='no_pty') as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                await _create_session(conn, term_type='ansi')

    @asynctest
    async def test_invalid_term_type(self):
        """Test requesting an invalid terminal type"""

        with patch('asyncssh.connection.SSHClientChannel', _ClientChannel):
            async with self.connect() as conn:
                with self.assertRaises(asyncssh.ProtocolError):
                    await _create_session(conn, term_type=b'\xff')

    @asynctest
    async def test_term_modes_missing_end(self):
        """Test sending terminal modes without PTY_OP_END"""

        modes = {asyncssh.PTY_OP_OSPEED: 9600, PTY_OP_NO_END: 0}

        with patch('asyncssh.connection.SSHClientChannel', _ClientChannel):
            async with self.connect() as conn:
                chan, session = await _create_session(conn, 'term',
                                                      term_type='ansi',
                                                      term_modes=modes)

                await chan.wait_closed()

                result = ''.join(session.recv_buf[None])
                self.assertEqual(result, "('ansi', (0, 0, 0, 0), 9600)\r\n")

    @asynctest
    async def test_term_modes_incomplete(self):
        """Test sending terminal modes with incomplete value"""

        modes = {asyncssh.PTY_OP_OSPEED: 9600, PTY_OP_PARTIAL: 0}

        with patch('asyncssh.connection.SSHClientChannel', _ClientChannel):
            async with self.connect() as conn:
                with self.assertRaises(asyncssh.ProtocolError):
                    await _create_session(conn, 'term', term_type='ansi',
                                          term_modes=modes)

    @asynctest
    async def test_env(self):
        """Test setting environment"""

        async with self.connect() as conn:
            chan, session = await _create_session(conn, 'env',
                                                  env={'TEST': 'test'})

            await chan.wait_closed()

            result = ''.join(session.recv_buf[None])
            self.assertEqual(result, 'test\n')

    @asynctest
    async def test_env_from_connect(self):
        """Test setting environment on connection"""

        async with self.connect(env={'TEST': 'test'}) as conn:
            chan, session = await _create_session(conn, 'env')

            await chan.wait_closed()

            result = ''.join(session.recv_buf[None])
            self.assertEqual(result, 'test\n')

    @asynctest
    async def test_env_list(self):
        """Test setting environment using a list of name=value strings"""

        async with self.connect() as conn:
            chan, session = await _create_session(conn, 'env',
                                                  env=['TEST=test'])

            await chan.wait_closed()

            result = ''.join(session.recv_buf[None])
            self.assertEqual(result, 'test\n')

    @asynctest
    async def test_invalid_env_list(self):
        """Test setting environment using an invalid string"""

        with self.assertRaises(ValueError):
            async with self.connect() as conn:
                await _create_session(conn, 'env', env=['XXX'])

    @asynctest
    async def test_send_env(self):
        """Test sending local environment"""

        async with self.connect() as conn:
            try:
                os.environ['TEST'] = 'test'
                chan, session = await _create_session(conn, 'env',
                                                      send_env=['TEST'])
            finally:
                del os.environ['TEST']

            await chan.wait_closed()

            result = ''.join(session.recv_buf[None])
            self.assertEqual(result, 'test\n')

    @asynctest
    async def test_send_env_from_connect(self):
        """Test sending local environment on connection"""

        try:
            os.environ['TEST'] = 'test'

            async with self.connect(send_env=['TEST']) as conn:
                chan, session = await _create_session(conn, 'env')

                await chan.wait_closed()

                result = ''.join(session.recv_buf[None])
                self.assertEqual(result, 'test\n')
        finally:
            del os.environ['TEST']

    @asynctest
    async def test_mixed_env(self):
        """Test sending a mix of local environment and new values"""

        async with self.connect() as conn:
            try:
                os.environ['TEST'] = '1'
                chan, session = await _create_session(conn, 'env',
                                                      env={'TEST': 2},
                                                      send_env='TEST')
            finally:
                del os.environ['TEST']

            await chan.wait_closed()

            result = ''.join(session.recv_buf[None])
            self.assertEqual(result, '2\n')

    @asynctest
    async def test_invalid_env(self):
        """Test sending invalid environment"""

        with patch('asyncssh.connection.SSHClientChannel', _ClientChannel):
            async with self.connect() as conn:
                chan, session = await _create_session(
                    conn, 'env', env={'TEST': 'invalid'})

                await chan.wait_closed()

                result = ''.join(session.recv_buf[None])
                self.assertEqual(result, '\n')

    @asynctest
    async def test_xon_xoff_enable(self):
        """Test enabling XON/XOFF flow control"""

        async with self.connect() as conn:
            chan, session = await _create_session(conn, 'xon_xoff')

            await chan.wait_closed()
            self.assertEqual(session.xon_xoff, True)

    @asynctest
    async def test_xon_xoff_disable(self):
        """Test disabling XON/XOFF flow control"""

        async with self.connect() as conn:
            chan, session = await _create_session(conn, 'no_xon_xoff')

            await chan.wait_closed()
            self.assertEqual(session.xon_xoff, False)

    @asynctest
    async def test_break(self):
        """Test sending a break"""

        async with self.connect() as conn:
            chan, session = await _create_session(conn, 'signals')

            chan.send_break(1000)
            await chan.wait_closed()
            self.assertEqual(session.exit_signal_msg, '1000')

    @asynctest
    async def test_signal(self):
        """Test sending a signal"""

        async with self.connect() as conn:
            chan, session = await _create_session(conn, 'signals')

            chan.send_signal('INT')
            await chan.wait_closed()
            self.assertEqual(session.exit_signal_msg, 'INT')

    @asynctest
    async def test_numeric_signal(self):
        """Test sending a signal using a numeric value"""

        async with self.connect() as conn:
            chan, session = await _create_session(conn, 'signals')

            chan.send_signal(SIGINT)
            await chan.wait_closed()
            self.assertEqual(session.exit_signal_msg, 'INT')

    @asynctest
    async def test_unknown_signal(self):
        """Test sending a signal with an unknown numeric value"""

        async with self.connect() as conn:
            chan, _ = await _create_session(conn, 'signals')

            with self.assertRaises(ValueError):
                chan.send_signal(123)

            chan.close()

    @asynctest
    async def test_terminate(self):
        """Test sending a terminate signal"""

        async with self.connect() as conn:
            chan, session = await _create_session(conn, 'signals')

            chan.terminate()
            await chan.wait_closed()
            self.assertEqual(session.exit_signal_msg, 'TERM')

    @asynctest
    async def test_kill(self):
        """Test sending a kill signal"""

        async with self.connect() as conn:
            chan, session = await _create_session(conn, 'signals')

            chan.kill()
            await chan.wait_closed()
            self.assertEqual(session.exit_signal_msg, 'KILL')

    @asynctest
    async def test_invalid_signal(self):
        """Test sending an invalid signal"""

        with patch('asyncssh.connection.SSHClientChannel', _ClientChannel):
            async with self.connect() as conn:
                chan, session = await _create_session(conn, 'signals')

                chan.send_signal(b'\xff')
                chan.write('\n')
                await chan.wait_closed()
                self.assertEqual(session.exit_status, None)

    @asynctest
    async def test_terminal_size_change(self):
        """Test sending terminal size change"""

        async with self.connect() as conn:
            chan, session = await _create_session(conn, 'signals',
                                                  term_type='ansi')

            chan.change_terminal_size(80, 24)
            await chan.wait_closed()
            self.assertEqual(session.exit_signal_msg, '(80, 24, 0, 0)')

    @asynctest
    async def test_full_terminal_size_change(self):
        """Test sending full terminal size change"""

        async with self.connect() as conn:
            chan, session = await _create_session(conn, 'signals',
                                                  term_type='ansi')

            chan.change_terminal_size(80, 24, 480, 240)
            await chan.wait_closed()
            self.assertEqual(session.exit_signal_msg, '(80, 24, 480, 240)')

    @asynctest
    async def test_exit_status(self):
        """Test receiving exit status"""

        async with self.connect() as conn:
            chan, session = await _create_session(conn, 'exit_status')

            await chan.wait_closed()
            self.assertEqual(session.exit_status, 1)
            self.assertEqual(chan.get_exit_status(), 1)
            self.assertIsNone(chan.get_exit_signal())
            self.assertEqual(chan.get_returncode(), 1)

    @asynctest
    async def test_exit_status_after_close(self):
        """Test delivery of exit status after remote close"""

        async with self.connect() as conn:
            chan, session = await _create_session(conn, 'closed_status')

            await chan.wait_closed()
            self.assertIsNone(session.exit_status)
            self.assertIsNone(chan.get_exit_status())
            self.assertIsNone(chan.get_exit_signal())
            self.assertIsNone(chan.get_returncode())

    @asynctest
    async def test_exit_signal(self):
        """Test receiving exit signal"""

        async with self.connect() as conn:
            chan, session = await _create_session(conn, 'exit_signal')

            await chan.wait_closed()
            self.assertEqual(session.exit_signal_msg, 'exit_signal')
            self.assertEqual(chan.get_exit_status(), -1)
            self.assertEqual(chan.get_exit_signal(), ('INT', False,
                                                      'exit_signal',
                                                      DEFAULT_LANG))
            self.assertEqual(chan.get_returncode(), -SIGINT)

    @asynctest
    async def test_exit_signal_after_close(self):
        """Test delivery of exit signal after remote close"""

        async with self.connect() as conn:
            chan, session = await _create_session(conn, 'closed_signal')

            await chan.wait_closed()
            self.assertIsNone(session.exit_signal_msg)
            self.assertIsNone(chan.get_exit_status())
            self.assertIsNone(chan.get_exit_signal())
            self.assertIsNone(chan.get_returncode())

    @asynctest
    async def test_unknown_exit_signal(self):
        """Test receiving unknown exit signal"""

        async with self.connect() as conn:
            chan, session = await _create_session(conn, 'unknown_signal')

            await chan.wait_closed()
            self.assertEqual(session.exit_signal_msg, 'unknown_signal')
            self.assertEqual(chan.get_exit_status(), -1)
            self.assertEqual(chan.get_exit_signal(), ('unknown', False,
                                                      'unknown_signal',
                                                      DEFAULT_LANG))
            self.assertEqual(chan.get_returncode(), -99)

    @asynctest
    async def test_invalid_exit_signal(self):
        """Test delivery of invalid exit signal"""

        async with self.connect() as conn:
            chan, _ = await _create_session(conn, 'invalid_exit_signal')

            await chan.wait_closed()

    @asynctest
    async def test_invalid_exit_lang(self):
        """Test delivery of invalid exit signal language"""

        async with self.connect() as conn:
            chan, _ = await _create_session(conn, 'invalid_exit_lang')

            await chan.wait_closed()

    @asynctest
    async def test_window_adjust_after_eof(self):
        """Test receiving window adjust after EOF"""

        async with self.connect() as conn:
            chan, _ = await _create_session(conn, 'window_after_close')

            await chan.wait_closed()

    @asynctest
    async def test_empty_data(self):
        """Test receiving empty data packet"""

        async with self.connect() as conn:
            chan, _ = await _create_session(conn, 'empty_data')

            chan.close()

    @asynctest
    async def test_partial_unicode(self):
        """Test receiving Unicode data spread across two packets"""

        async with self.connect() as conn:
            chan, session = await _create_session(conn, 'partial_unicode')

            await chan.wait_closed()

            result = ''.join(session.recv_buf[None])
            self.assertEqual(result, '\xff\xff')

    @asynctest
    async def test_partial_unicode_at_eof(self):
        """Test receiving partial Unicode data and then EOF"""

        async with self.connect() as conn:
            chan, session = await _create_session(
                conn, 'partial_unicode_at_eof')

            await chan.wait_closed()
            self.assertIsInstance(session.exc, asyncssh.ProtocolError)

    @asynctest
    async def test_unicode_error(self):
        """Test receiving bad Unicode data"""

        async with self.connect() as conn:
            chan, session = await _create_session(conn, 'unicode_error')

            await chan.wait_closed()
            self.assertIsInstance(session.exc, asyncssh.ProtocolError)

    @asynctest
    async def test_data_past_window(self):
        """Test receiving a data packet past the advertised window"""

        async with self.connect() as conn:
            chan, _ = await _create_session(conn, 'data_past_window')

            await chan.wait_closed()

    @asynctest
    async def test_ext_data_past_window(self):
        """Test receiving an extended data packet past the advertised window"""

        async with self.connect() as conn:
            chan, _ = await _create_session(conn, 'ext_data_past_window')

            await chan.wait_closed()

    @asynctest
    async def test_data_after_eof(self):
        """Test receiving data after EOF"""

        async with self.connect() as conn:
            chan, _ = await _create_session(conn, 'data_after_eof')

            await chan.wait_closed()

    @asynctest
    async def test_data_after_close(self):
        """Test receiving data after close"""

        async with self.connect() as conn:
            chan, _ = await _create_session(conn, 'data_after_close')

            chan.write(4*1025*1024*'\0')
            chan.close()
            await asyncio.sleep(0.2)
            await chan.wait_closed()

    @asynctest
    async def test_extended_data_after_eof(self):
        """Test receiving extended data after EOF"""

        async with self.connect() as conn:
            chan, _ = await _create_session(conn, 'ext_data_after_eof')

            await chan.wait_closed()

    @asynctest
    async def test_invalid_datatype(self):
        """Test receiving data with invalid data type"""

        async with self.connect() as conn:
            chan, _ = await _create_session(conn, 'invalid_datatype')

            await chan.wait_closed()

    @asynctest
    async def test_double_eof(self):
        """Test receiving two EOF messages"""

        async with self.connect() as conn:
            chan, _ = await _create_session(conn, 'double_eof')

            await chan.wait_closed()

    @asynctest
    async def test_double_close(self):
        """Test receiving two close messages"""

        async with self.connect() as conn:
            chan, _ = await _create_session(conn, 'double_close')
            chan.pause_reading()
            await asyncio.sleep(0.2)
            chan.resume_reading()

            await chan.wait_closed()

    @asynctest
    async def test_request_after_close(self):
        """Test receiving a channel request after a close"""

        async with self.connect() as conn:
            chan, _ = await _create_session(conn, 'request_after_close')

            await chan.wait_closed()

    @asynctest
    async def test_late_auth_banner(self):
        """Test server sending authentication banner after auth completes"""

        async with self.connect() as conn:
            chan, session = await _create_session(conn, 'late_auth_banner')

            await chan.wait_closed()
            self.assertEqual(session.exit_status, 1)

    @asynctest
    async def test_unexpected_userauth_request(self):
        """Test userauth request sent to client"""

        async with self.connect() as conn:
            chan, _ = await _create_session(conn, 'unexpected_auth')

            await chan.wait_closed()

    @asynctest
    async def test_unknown_action(self):
        """Test unknown action"""

        async with self.connect() as conn:
            chan, session = await _create_session(conn, 'unknown')

            await chan.wait_closed()
            self.assertEqual(session.exit_status, 255)


class _TestChannelNoPTY(ServerTestCase):
    """Unit tests for AsyncSSH channel module with PTYs disallowed"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server for the tests to use"""

        return (await cls.create_server(
            _ChannelServer, authorized_client_keys='authorized_keys',
            allow_pty=False))

    @asynctest
    async def test_shell_pty(self):
        """Test starting a shell that request a PTY"""

        async with self.connect() as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                await conn.run(term_type='ansi')

    @asynctest
    async def test_shell_no_pty(self):
        """Test starting a shell that doesn't request a PTY"""

        async with self.connect() as conn:
            await conn.run(request_pty=False, stdin=asyncssh.DEVNULL)

    @asynctest
    async def test_exec_pty(self):
        """Test execution of a remote command that requests a PTY"""

        async with self.connect() as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                await conn.run('echo', request_pty='force')

    @asynctest
    async def test_exec_pty_from_connect(self):
        """Test execution of a command that requests a PTY on the connection"""

        async with self.connect(request_pty='force') as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                await conn.run('echo')

    @asynctest
    async def test_exec_no_pty(self):
        """Test execution of a remote command that doesn't request a PTY"""

        async with self.connect() as conn:
            await conn.run('echo', term_type='ansi', request_pty='auto',
                           stdin=asyncssh.DEVNULL)


class _TestChannelNoAgentForwarding(ServerTestCase):
    """Unit tests for channel module with agent forwarding disallowed"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server with agent forwarding disabled"""

        return (await cls.create_server(
            _ChannelServer, authorized_client_keys='authorized_keys',
            agent_forwarding=False))

    @asynctest
    async def test_agent_forwarding_disallowed(self):
        """Test starting a shell that request a PTY"""

        async with self.connect(agent_forwarding=True) as conn:
            result = await conn.run('agent')

        self.assertEqual(result.exit_status, 1)


class _TestConnectionDropbearClient(ServerTestCase):
    """Unit tests for testing Dropbear client compatibility fix"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server to connect to"""

        return await cls.create_server(_ChannelServer)

    @asynctest
    async def test_dropbear_client(self):
        """Test reduced dropbear send packet size"""

        with patch('asyncssh.connection.SSHServerChannel', _ServerChannel):
            async with self.connect(client_version='dropbear',
                                    max_pktsize=32759) as conn:
                _, stdout, _ = await conn.open_session('send_pktsize')
                self.assertEqual((await stdout.read()), '32758')

            async with self.connect(client_version='dropbear',
                                    max_pktsize=32759,
                                    compression_algs=None) as conn:
                _, stdout, _ = await conn.open_session('send_pktsize')
                self.assertEqual((await stdout.read()), '32759')


class _TestConnectionDropbearServer(ServerTestCase):
    """Unit tests for testing Dropbear server compatibility fix"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server to connect to"""

        return await cls.create_server(
            _ChannelServer, server_version='dropbear', max_pktsize=32759)

    @asynctest
    async def test_dropbear_server(self):
        """Test reduced dropbear send packet size"""

        with patch('asyncssh.connection.SSHClientChannel', _ClientChannel):
            async with self.connect() as conn:
                stdin, _, _ = await conn.open_session()
                self.assertEqual(stdin.channel.get_send_pktsize(), 32758)

            async with self.connect(compression_algs=None) as conn:
                stdin, _, _ = await conn.open_session()
                self.assertEqual(stdin.channel.get_send_pktsize(), 32759)
