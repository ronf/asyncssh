# Copyright (c) 2016 by Ron Frederick <ronf@timeheart.net>.
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

"""Unit tests for AsyncSSH channel API"""

import asyncio
import tempfile

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

    def send_request(self, request, *args):
        """Send a custom request (for unit testing)"""

        self._send_request(request, *args)

    @asyncio.coroutine
    def make_request(self, request, *args):
        """Make a custom request (for unit testing)"""

        yield from self._make_request(request, *args)


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


@asyncio.coroutine
def _create_session(conn, command=None, *, subsystem=None, **kwargs):
    """Create a client session"""

    return (yield from conn.create_session(_ClientSession, command,
                                           subsystem=subsystem, **kwargs))


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

    def send_packet(self, pkttype, *args):
        """Send a packet for unit testing (bypassing state checks)"""

        self._send_packet(pkttype, *args)

    @asyncio.coroutine
    def open_session(self):
        """Attempt to open a session on the client"""

        return (yield from self._open(b'session'))


class _EchoServerSession(asyncssh.SSHServerSession):
    """A shell session which echos data from stdin to stdout/stderr"""

    def __init__(self):
        self._chan = None
        self._pty_ok = True

    def connection_made(self, chan):
        """Handle session open"""

        self._chan = chan

        username = self._chan.get_extra_info('username')

        if username == 'close':
            self._chan.close()
        elif username == 'no_pty':
            self._pty_ok = False
        elif username == 'task_error':
            raise RuntimeError('Exception handler test')

    def pty_requested(self, term_type, term_size, term_modes):
        """Handle pseudo-terminal request"""

        return self._pty_ok

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


class _ChannelServer(Server):
    """Server for testing the AsyncSSH channel API"""

    def _begin_session(self, stdin, stdout, stderr):
        """Begin processing a new session"""

        # pylint: disable=too-many-statements

        action = stdin.channel.get_command() or stdin.channel.get_subsystem()
        if not action:
            action = 'echo'

        if action == 'echo':
            yield from echo(stdin, stdout, stderr)
        elif action == 'conn_close':
            yield from stdin.read(1)
            stdout.write('\n')
            self._conn.close()
        elif action == 'close':
            yield from stdin.read(1)
            stdout.write('\n')
        elif action == 'agent':
            agent = yield from asyncssh.connect_agent(self._conn)
            if agent:
                stdout.write(str(len((yield from agent.get_keys()))) + '\n')
                agent.close()
            else:
                stdout.channel.exit(1)
        elif action == 'agent_sock':
            agent_path = stdin.channel.get_agent_path()

            if agent_path:
                agent = yield from asyncssh.connect_agent(agent_path)
                stdout.write(str(len((yield from agent.get_keys()))) + '\n')
                agent.close()
            else:
                stdout.channel.exit(1)
        elif action == 'rejected_agent':
            agent_path = stdin.channel.get_agent_path()
            stdout.write(str(bool(agent_path)) + '\n')

            chan = self._conn.create_agent_channel()

            try:
                yield from chan.open(SSHUNIXStreamSession)
            except asyncssh.ChannelOpenError:
                stdout.channel.exit(1)
        elif action == 'rejected_session':
            chan = _ServerChannel(self._conn, asyncio.get_event_loop(),
                                  False, False, 0, None, 1, 32768)

            try:
                yield from chan.open_session()
            except asyncssh.ChannelOpenError:
                stdout.channel.exit(1)
        elif action == 'rejected_tcpip_direct':
            chan = self._conn.create_tcp_channel()

            try:
                yield from chan.connect(SSHTCPStreamSession, '', 0, '', 0)
            except asyncssh.ChannelOpenError:
                stdout.channel.exit(1)
        elif action == 'unknown_tcpip_listener':
            chan = self._conn.create_tcp_channel()

            try:
                yield from chan.accept(SSHTCPStreamSession, 'xxx', 0, '', 0)
            except asyncssh.ChannelOpenError:
                stdout.channel.exit(1)
        elif action == 'invalid_tcpip_listener':
            chan = self._conn.create_tcp_channel()

            try:
                yield from chan.accept(SSHTCPStreamSession, b'\xff', 0, '', 0)
            except asyncssh.ChannelOpenError:
                stdout.channel.exit(1)
        elif action == 'rejected_unix_direct':
            chan = self._conn.create_unix_channel()

            try:
                yield from chan.connect(SSHUNIXStreamSession, '')
            except asyncssh.ChannelOpenError:
                stdout.channel.exit(1)
        elif action == 'unknown_unix_listener':
            chan = self._conn.create_unix_channel()

            try:
                yield from chan.accept(SSHUNIXStreamSession, 'xxx')
            except asyncssh.ChannelOpenError:
                stdout.channel.exit(1)
        elif action == 'invalid_unix_listener':
            chan = self._conn.create_unix_channel()

            try:
                yield from chan.accept(SSHUNIXStreamSession, b'\xff')
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
                yield from stdin.readline()
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
            stdin.channel.exit_with_signal('ABRT', False, 'exit_signal')
        elif action == 'closed_signal':
            stdin.channel.close()
            stdin.channel.exit_with_signal('ABRT', False, 'closed_signal')
        elif action == 'invalid_exit_signal':
            stdin.channel.exit_with_signal('invalid')
        elif action == 'invalid_exit_lang':
            stdin.channel.exit_with_signal('ABRT', False, '', 'invalid')
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
        elif action == 'data_after_eof':
            stdin.channel.send_packet(MSG_CHANNEL_EOF)
            stdout.write('xxx')
        elif action == 'data_after_close':
            yield from asyncio.sleep(0.1)
            stdout.write('xxx')
        elif action == 'ext_data_after_eof':
            stdin.channel.send_packet(MSG_CHANNEL_EOF)
            stdin.channel.write_stderr('xxx')
        elif action == 'invalid_datatype':
            stdin.channel.send_packet(MSG_CHANNEL_EXTENDED_DATA,
                                      UInt32(255), String(''))
        elif action == 'double_eof':
            stdin.channel.send_packet(MSG_CHANNEL_EOF)
            stdin.channel.write_eof()
        elif action == 'double_close':
            yield from asyncio.sleep(0.1)
            stdout.write('xxx')
            stdin.channel.send_packet(MSG_CHANNEL_CLOSE)
        elif action == 'request_after_close':
            stdin.channel.send_packet(MSG_CHANNEL_CLOSE)
            stdin.channel.exit(1)
        elif action == 'unexpected_auth':
            self._conn.send_packet(Byte(MSG_USERAUTH_REQUEST), String('guest'),
                                   String('ssh-connection'), String('none'))
        elif action == 'invalid_response':
            stdin.channel.send_packet(MSG_CHANNEL_SUCCESS)
        else:
            stdin.channel.exit(255)

        stdin.channel.close()
        yield from stdin.channel.wait_closed()

    def begin_auth(self, username):
        """Handle client authentication request"""

        return username not in {'guest', 'conn_close', 'close', 'echo',
                                'no_channels', 'no_pty', 'task_error'}

    def session_requested(self):
        """Handle a request to create a new session"""

        username = self._conn.get_extra_info('username')

        with patch('asyncssh.connection.SSHServerChannel', _ServerChannel):
            channel = self._conn.create_server_channel()

            if username == 'conn_close':
                self._conn.close()
                return False
            elif username in {'close', 'echo', 'no_pty', 'task_error'}:
                return (channel, _EchoServerSession())
            elif username != 'no_channels':
                return (channel, self._begin_session)
            else:
                return False


class _TestChannel(ServerTestCase):
    """Unit tests for AsyncSSH channel API"""

    # pylint: disable=too-many-public-methods

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SSH server for the tests to use"""

        return (yield from cls.create_server(
            _ChannelServer, authorized_client_keys='authorized_keys'))

    @asyncio.coroutine
    def _check_action(self, command, expected_result):
        """Run a command on a remote session and check for a specific result"""

        with (yield from self.connect()) as conn:
            chan, session = yield from _create_session(conn, command)

            yield from chan.wait_closed()

            self.assertEqual(session.exit_status, expected_result)

        yield from conn.wait_closed()

    @asyncio.coroutine
    def _check_session(self, conn, command=None, *, subsystem=None,
                       large_block=False, **kwargs):
        """Open a session and test if an input line is echoed back"""

        chan, session = yield from _create_session(conn, command,
                                                   subsystem=subsystem,
                                                   *kwargs)

        if large_block:
            data = 4 * [1025*1024*'\0']
        else:
            data = [str(id(self))]

        self.assertTrue(chan.can_write_eof())

        chan.writelines(data)
        chan.write_eof()

        yield from chan.wait_closed()

        data = ''.join(data)

        for buf in session.recv_buf.values():
            self.assertEqual(data, ''.join(buf))

        chan.close()

    @asynctest
    def test_shell(self):
        """Test starting a shell"""

        with (yield from self.connect(username='echo')) as conn:
            yield from self._check_session(conn)

        yield from conn.wait_closed()

    @asynctest
    def test_shell_failure(self):
        """Test failure to start a shell"""

        with (yield from self.connect(username='no_channels')) as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                yield from _create_session(conn)

        yield from conn.wait_closed()

    @asynctest
    def test_shell_internal_error(self):
        """Test internal error in callback to start a shell"""

        with (yield from self.connect(username='task_error')) as conn:
            with self.assertRaises((OSError, asyncssh.DisconnectError)):
                yield from _create_session(conn)

        yield from conn.wait_closed()

    @asynctest
    def test_shell_large_block(self):
        """Test starting a shell and sending a large block of data"""

        with (yield from self.connect(username='echo')) as conn:
            yield from self._check_session(conn, large_block=True)

        yield from conn.wait_closed()

    @asynctest
    def test_exec(self):
        """Test execution of a remote command"""

        with (yield from self.connect()) as conn:
            yield from self._check_session(conn, 'echo')

        yield from conn.wait_closed()

    @asynctest
    def test_forced_exec(self):
        """Test execution of a forced remote command"""

        ckey = asyncssh.read_private_key('ckey')
        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_USER, ckey, ckey, ['ckey'],
                                options={'force-command': String('echo')})

        with (yield from self.connect(username='ckey',
                                      client_keys=[(ckey, cert)])) as conn:
            yield from self._check_session(conn)

        yield from conn.wait_closed()

    @asynctest
    def test_invalid_exec(self):
        """Test execution of an invalid remote command"""

        with (yield from self.connect()) as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                yield from _create_session(conn, b'\xff')

        yield from conn.wait_closed()

    @asynctest
    def test_exec_failure(self):
        """Test failure to execute a remote command"""

        with (yield from self.connect(username='no_channels')) as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                yield from _create_session(conn, 'echo')

        yield from conn.wait_closed()

    @asynctest
    def test_subsystem(self):
        """Test starting a subsystem"""

        with (yield from self.connect()) as conn:
            yield from self._check_session(conn, subsystem='echo')

        yield from conn.wait_closed()

    @asynctest
    def test_invalid_subsystem(self):
        """Test starting an invalid subsystem"""

        with (yield from self.connect()) as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                yield from _create_session(conn, subsystem=b'\xff')

        yield from conn.wait_closed()

    @asynctest
    def test_subsystem_failure(self):
        """Test failure to start a subsystem"""

        with (yield from self.connect(username='no_channels')) as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                yield from _create_session(conn, subsystem='echo')

        yield from conn.wait_closed()

    @asynctest
    def test_conn_close_during_startup(self):
        """Test connection close during channel startup"""

        with (yield from self.connect(username='conn_close')) as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                yield from _create_session(conn)

        yield from conn.wait_closed()

    @asynctest
    def test_close_during_startup(self):
        """Test channel close during startup"""

        with (yield from self.connect(username='close')) as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                yield from _create_session(conn)

        yield from conn.wait_closed()

    @asynctest
    def test_inbound_conn_close_while_read_paused(self):
        """Test inbound connection close while reading is paused"""

        with (yield from self.connect()) as conn:
            chan, _ = yield from _create_session(conn, 'conn_close')

            chan.pause_reading()
            chan.write('\n')
            yield from asyncio.sleep(0.1)
            conn.close()
            yield from asyncio.sleep(0.1)
            chan.resume_reading()

            yield from chan.wait_closed()

        yield from conn.wait_closed()

    @asynctest
    def test_outbound_conn_close_while_read_paused(self):
        """Test outbound connection close while reading is paused"""

        with (yield from self.connect()) as conn:
            chan, _ = yield from _create_session(conn, 'close')

            chan.pause_reading()
            chan.write('\n')
            yield from asyncio.sleep(0.1)
            conn.close()
            yield from asyncio.sleep(0.1)
            chan.resume_reading()

            yield from chan.wait_closed()

        yield from conn.wait_closed()

    @asynctest
    def test_invalid_open_confirmation(self):
        """Test receiving an open confirmation on already open channel"""

        with (yield from self.connect()) as conn:
            chan, _ = yield from _create_session(conn, 'invalid_open_confirm')

            yield from chan.wait_closed()

        yield from conn.wait_closed()

    @asynctest
    def test_invalid_open_failure(self):
        """Test receiving an open failure on already open channel"""

        with (yield from self.connect()) as conn:
            chan, _ = yield from _create_session(conn, 'invalid_open_failure')

            yield from chan.wait_closed()

        yield from conn.wait_closed()

    @asynctest
    def test_invalid_channel_request(self):
        """Test sending non-ASCII channel request"""

        with patch('asyncssh.connection.SSHClientChannel', _ClientChannel):
            with (yield from self.connect()) as conn:
                chan, _ = yield from _create_session(conn)

                with self.assertRaises(asyncssh.DisconnectError):
                    yield from chan.make_request('\xff')

            yield from conn.wait_closed()

    @asynctest
    def test_delayed_channel_request(self):
        """Test queuing channel requests with delayed response"""

        with patch('asyncssh.connection.SSHClientChannel', _ClientChannel):
            with (yield from self.connect()) as conn:
                chan, _ = yield from _create_session(conn)

                chan.send_request(b'delayed')
                chan.send_request(b'delayed')

            yield from conn.wait_closed()

    @asynctest
    def test_invalid_channel_response(self):
        """Test receiving response for non-existent channel request"""

        with (yield from self.connect()) as conn:
            chan, _ = yield from _create_session(conn, 'invalid_response')

            chan.close()

        yield from conn.wait_closed()

    @asynctest
    def test_already_open(self):
        """Test connect on an already open channel"""

        with (yield from self.connect()) as conn:
            chan, _ = yield from _create_session(conn)

            with self.assertRaises(OSError):
                yield from chan.create(None, None, None, {}, None, None,
                                       None, False, None, None, False, False)

            chan.close()

        yield from conn.wait_closed()

    @asynctest
    def test_write_buffer(self):
        """Test setting write buffer limits"""

        with (yield from self.connect()) as conn:
            chan, _ = yield from _create_session(conn)

            chan.set_write_buffer_limits()
            chan.set_write_buffer_limits(low=8192)
            chan.set_write_buffer_limits(high=32768)
            chan.set_write_buffer_limits(32768, 8192)

            with self.assertRaises(ValueError):
                chan.set_write_buffer_limits(8192, 32768)

            self.assertEqual(chan.get_write_buffer_size(), 0)

            chan.close()

        yield from conn.wait_closed()

    @asynctest
    def test_empty_write(self):
        """Test writing an empty block of data"""

        with (yield from self.connect()) as conn:
            chan, _ = yield from _create_session(conn)
            chan.write('')
            chan.close()

        yield from conn.wait_closed()

    @asynctest
    def test_invalid_write_extended(self):
        """Test writing using an invalid extended data type"""

        with (yield from self.connect()) as conn:
            chan, _ = yield from _create_session(conn)

            with self.assertRaises(OSError):
                chan.write('test', -1)

        yield from conn.wait_closed()

    @asynctest
    def test_unneeded_resume_reading(self):
        """Test resume reading when not paused"""

        with (yield from self.connect()) as conn:
            chan, _ = yield from _create_session(conn)
            chan.resume_reading()
            chan.close()

        yield from conn.wait_closed()

    @asynctest
    def test_agent_forwarding(self):
        """Test SSH agent forwarding"""

        if not self.agent_available(): # pragma: no cover
            self.skipTest('ssh-agent not available')

        with (yield from self.connect(username='ckey',
                                      agent_forwarding=True)) as conn:
            chan, session = yield from _create_session(conn, 'agent')

            yield from chan.wait_closed()

            result = ''.join(session.recv_buf[None])
            self.assertEqual(result, '3\n')

            chan, session = yield from _create_session(conn, 'agent')

            yield from chan.wait_closed()

            result = ''.join(session.recv_buf[None])
            self.assertEqual(result, '3\n')

        yield from conn.wait_closed()

    @asynctest
    def test_agent_forwarding_sock(self):
        """Test SSH agent forwarding via UNIX domain socket"""

        if not self.agent_available(): # pragma: no cover
            self.skipTest('ssh-agent not available')

        with (yield from self.connect(username='ckey',
                                      agent_forwarding=True)) as conn:
            chan, session = yield from _create_session(conn, 'agent_sock')

            yield from chan.wait_closed()

            result = ''.join(session.recv_buf[None])
            self.assertEqual(result, '3\n')

        yield from conn.wait_closed()

    @asynctest
    def test_rejected_session(self):
        """Test receiving inbound session request"""

        yield from self._check_action('rejected_session', 1)

    @asynctest
    def test_rejected_tcpip_direct(self):
        """Test receiving inbound direct TCP/IP connection"""

        yield from self._check_action('rejected_tcpip_direct', 1)

    @asynctest
    def test_unknown_tcpip_listener(self):
        """Test receiving connection on unknown TCP/IP listener"""

        yield from self._check_action('unknown_tcpip_listener', 1)

    @asynctest
    def test_invalid_tcpip_listener(self):
        """Test receiving connection on invalid TCP/IP listener path"""

        yield from self._check_action('invalid_tcpip_listener', None)

    @asynctest
    def test_rejected_unix_direct(self):
        """Test receiving inbound direct UNIX connection"""

        yield from self._check_action('rejected_unix_direct', 1)

    @asynctest
    def test_unknown_unix_listener(self):
        """Test receiving connection on unknown UNIX listener"""

        yield from self._check_action('unknown_unix_listener', 1)

    @asynctest
    def test_invalid_unix_listener(self):
        """Test receiving connection on invalid UNIX listener path"""

        yield from self._check_action('invalid_unix_listener', None)

    @asynctest
    def test_agent_forwarding_failure(self):
        """Test failure of SSH agent forwarding"""

        ckey = asyncssh.read_private_key('ckey')
        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_USER, ckey, ckey, ['ckey'],
                                extensions={'no-agent-forwarding': ''})

        with (yield from self.connect(username='ckey',
                                      client_keys=[(ckey, cert)],
                                      agent_forwarding=True)) as conn:
            chan, session = yield from _create_session(conn, 'agent')

            yield from chan.wait_closed()

            self.assertEqual(session.exit_status, 1)

        yield from conn.wait_closed()

    @asynctest
    def test_agent_forwarding_sock_failure(self):
        """Test failure to create SSH agent forwarding socket"""

        tempfile.tempdir = 'xxx'

        with (yield from self.connect(username='ckey',
                                      agent_forwarding=True)) as conn:
            chan, session = yield from _create_session(conn, 'agent_sock')

            yield from chan.wait_closed()

            self.assertEqual(session.exit_status, 1)

        yield from conn.wait_closed()

        tempfile.tempdir = None

    @asynctest
    def test_agent_forwarding_not_offered(self):
        """Test SSH agent forwarding not offered by client"""

        with (yield from self.connect()) as conn:
            chan, session = yield from _create_session(conn, 'agent')

            yield from chan.wait_closed()

            self.assertEqual(session.exit_status, 1)

        yield from conn.wait_closed()

    @asynctest
    def test_agent_forwarding_rejected(self):
        """Test rejection of SSH agent forwarding by client"""

        with (yield from self.connect()) as conn:
            chan, session = yield from _create_session(conn, 'rejected_agent')

            yield from chan.wait_closed()

            result = ''.join(session.recv_buf[None])
            self.assertEqual(result, 'False\n')

            self.assertEqual(session.exit_status, 1)

        yield from conn.wait_closed()

    @asynctest
    def test_terminal_info(self):
        """Test sending terminal information"""

        modes = {asyncssh.PTY_OP_OSPEED: 9600}

        with (yield from self.connect()) as conn:
            chan, session = yield from _create_session(conn, 'term',
                                                       term_type='ansi',
                                                       term_size=(80, 24),
                                                       term_modes=modes)

            yield from chan.wait_closed()

            result = ''.join(session.recv_buf[None])
            self.assertEqual(result, "('ansi', (80, 24, 0, 0), 9600)\r\n")

        yield from conn.wait_closed()

    @asynctest
    def test_terminal_full_size(self):
        """Test sending terminal information with full size"""

        modes = {asyncssh.PTY_OP_OSPEED: 9600}

        with (yield from self.connect()) as conn:
            chan, session = yield from _create_session(conn, 'term',
                                                       term_type='ansi',
                                                       term_size=(80, 24,
                                                                  480, 240),
                                                       term_modes=modes)

            yield from chan.wait_closed()

            result = ''.join(session.recv_buf[None])
            self.assertEqual(result, "('ansi', (80, 24, 480, 240), 9600)\r\n")

        yield from conn.wait_closed()

    @asynctest
    def test_invalid_terminal_size(self):
        """Test sending invalid terminal size"""

        with (yield from self.connect()) as conn:
            with self.assertRaises(ValueError):
                yield from _create_session(conn, 'term', term_type='ansi',
                                           term_size=(0, 0, 0))

        yield from conn.wait_closed()

    @asynctest
    def test_invalid_terminal_modes(self):
        """Test sending invalid terminal modes"""

        modes = {asyncssh.PTY_OP_RESERVED: 0}

        with (yield from self.connect()) as conn:
            with self.assertRaises(ValueError):
                yield from _create_session(conn, 'term', term_type='ansi',
                                           term_modes=modes)

        yield from conn.wait_closed()

    @asynctest
    def test_pty_disallowed_by_cert(self):
        """Test rejection of pty request by certificate"""

        ckey = asyncssh.read_private_key('ckey')
        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_USER, ckey, ckey, ['ckey'],
                                extensions={'no-pty': ''})

        with (yield from self.connect(username='ckey',
                                      client_keys=[(ckey, cert)])) as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                yield from _create_session(conn, 'term', term_type='ansi')

        yield from conn.wait_closed()

    @asynctest
    def test_pty_disallowed_by_session(self):
        """Test rejection of pty request by session"""

        with (yield from self.connect(username='no_pty')) as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                yield from _create_session(conn, 'term', term_type='ansi')

        yield from conn.wait_closed()

    @asynctest
    def test_invalid_term_type(self):
        """Test requesting an invalid terminal type"""

        with patch('asyncssh.connection.SSHClientChannel', _ClientChannel):
            with (yield from self.connect()) as conn:
                with self.assertRaises(asyncssh.DisconnectError):
                    yield from _create_session(conn, term_type=b'\xff')

            yield from conn.wait_closed()

    @asynctest
    def test_term_modes_missing_end(self):
        """Test sending terminal modes without PTY_OP_END"""

        modes = {asyncssh.PTY_OP_OSPEED: 9600, PTY_OP_NO_END: 0}

        with patch('asyncssh.connection.SSHClientChannel', _ClientChannel):
            with (yield from self.connect()) as conn:
                chan, session = yield from _create_session(conn, 'term',
                                                           term_type='ansi',
                                                           term_modes=modes)

                yield from chan.wait_closed()

                result = ''.join(session.recv_buf[None])
                self.assertEqual(result, "('ansi', (0, 0, 0, 0), 9600)\r\n")

            yield from conn.wait_closed()

    @asynctest
    def test_term_modes_incomplete(self):
        """Test sending terminal modes with incomplete value"""

        modes = {asyncssh.PTY_OP_OSPEED: 9600, PTY_OP_PARTIAL: 0}

        with patch('asyncssh.connection.SSHClientChannel', _ClientChannel):
            with (yield from self.connect()) as conn:
                with self.assertRaises(asyncssh.DisconnectError):
                    yield from _create_session(conn, 'term', term_type='ansi',
                                               term_modes=modes)

            yield from conn.wait_closed()

    @asynctest
    def test_env(self):
        """Test sending environment"""

        with (yield from self.connect()) as conn:
            chan, session = yield from _create_session(conn, 'env',
                                                       env={'TEST': 'test'})

            yield from chan.wait_closed()

            result = ''.join(session.recv_buf[None])
            self.assertEqual(result, 'test\n')

        yield from conn.wait_closed()

    @asynctest
    def test_invalid_env(self):
        """Test sending invalid environment"""

        with patch('asyncssh.connection.SSHClientChannel', _ClientChannel):
            with (yield from self.connect()) as conn:
                chan, session = yield from _create_session(
                    conn, 'env', env={'TEST': 'invalid'})

                yield from chan.wait_closed()

                result = ''.join(session.recv_buf[None])
                self.assertEqual(result, '\n')

            yield from conn.wait_closed()

    @asynctest
    def test_xon_xoff_enable(self):
        """Test enabling XON/XOFF flow control"""

        with (yield from self.connect()) as conn:
            chan, session = yield from _create_session(conn, 'xon_xoff')

            yield from chan.wait_closed()
            self.assertEqual(session.xon_xoff, True)

        yield from conn.wait_closed()

    @asynctest
    def test_xon_xoff_disable(self):
        """Test disabling XON/XOFF flow control"""

        with (yield from self.connect()) as conn:
            chan, session = yield from _create_session(conn, 'no_xon_xoff')

            yield from chan.wait_closed()
            self.assertEqual(session.xon_xoff, False)

        yield from conn.wait_closed()

    @asynctest
    def test_break(self):
        """Test sending a break"""

        with (yield from self.connect()) as conn:
            chan, session = yield from _create_session(conn, 'signals')

            chan.send_break(1000)
            yield from chan.wait_closed()
            self.assertEqual(session.exit_signal_msg, '1000')

        yield from conn.wait_closed()

    @asynctest
    def test_signal(self):
        """Test sending a signal"""

        with (yield from self.connect()) as conn:
            chan, session = yield from _create_session(conn, 'signals')

            chan.send_signal('HUP')
            yield from chan.wait_closed()
            self.assertEqual(session.exit_signal_msg, 'HUP')

        yield from conn.wait_closed()

    @asynctest
    def test_terminate(self):
        """Test sending a terminate signal"""

        with (yield from self.connect()) as conn:
            chan, session = yield from _create_session(conn, 'signals')

            chan.terminate()
            yield from chan.wait_closed()
            self.assertEqual(session.exit_signal_msg, 'TERM')

        yield from conn.wait_closed()

    @asynctest
    def test_kill(self):
        """Test sending a kill signal"""

        with (yield from self.connect()) as conn:
            chan, session = yield from _create_session(conn, 'signals')

            chan.kill()
            yield from chan.wait_closed()
            self.assertEqual(session.exit_signal_msg, 'KILL')

        yield from conn.wait_closed()

    @asynctest
    def test_invalid_signal(self):
        """Test sending an invalid signal"""

        with patch('asyncssh.connection.SSHClientChannel', _ClientChannel):
            with (yield from self.connect()) as conn:
                chan, session = yield from _create_session(conn, 'signals')

                chan.send_signal(b'\xff')
                chan.write('\n')
                yield from chan.wait_closed()
                self.assertEqual(session.exit_status, None)

            yield from conn.wait_closed()

    @asynctest
    def test_terminal_size_change(self):
        """Test sending terminal size change"""

        with (yield from self.connect()) as conn:
            chan, session = yield from _create_session(conn, 'signals',
                                                       term_type='ansi')

            chan.change_terminal_size(80, 24)
            yield from chan.wait_closed()
            self.assertEqual(session.exit_signal_msg, '(80, 24, 0, 0)')

        yield from conn.wait_closed()

    @asynctest
    def test_exit_status(self):
        """Test receiving exit status"""

        with (yield from self.connect()) as conn:
            chan, session = yield from _create_session(conn, 'exit_status')

            yield from chan.wait_closed()
            self.assertEqual(session.exit_status, 1)
            self.assertEqual(chan.get_exit_status(), 1)
            self.assertIsNone(chan.get_exit_signal())

        yield from conn.wait_closed()

    @asynctest
    def test_exit_status_after_close(self):
        """Test delivery of exit status after remote close"""

        with (yield from self.connect()) as conn:
            chan, session = yield from _create_session(conn, 'closed_status')

            yield from chan.wait_closed()
            self.assertIsNone(session.exit_status)
            self.assertIsNone(chan.get_exit_status())
            self.assertIsNone(chan.get_exit_signal())

        yield from conn.wait_closed()

    @asynctest
    def test_exit_signal(self):
        """Test receiving exit signal"""

        with (yield from self.connect()) as conn:
            chan, session = yield from _create_session(conn, 'exit_signal')

            yield from chan.wait_closed()
            self.assertEqual(session.exit_signal_msg, 'exit_signal')
            self.assertEqual(chan.get_exit_status(), -1)
            self.assertEqual(chan.get_exit_signal(), ('ABRT', False,
                                                      'exit_signal',
                                                      DEFAULT_LANG))

        yield from conn.wait_closed()

    @asynctest
    def test_exit_signal_after_close(self):
        """Test delivery of exit signal after remote close"""

        with (yield from self.connect()) as conn:
            chan, session = yield from _create_session(conn, 'closed_signal')

            yield from chan.wait_closed()
            self.assertIsNone(session.exit_signal_msg)
            self.assertIsNone(chan.get_exit_status())
            self.assertIsNone(chan.get_exit_signal())

        yield from conn.wait_closed()

    @asynctest
    def test_invalid_exit_signal(self):
        """Test delivery of invalid exit signal"""

        with (yield from self.connect()) as conn:
            chan, _ = yield from _create_session(conn, 'invalid_exit_signal')

            yield from chan.wait_closed()

        yield from conn.wait_closed()

    @asynctest
    def test_invalid_exit_lang(self):
        """Test delivery of invalid exit signal language"""

        with (yield from self.connect()) as conn:
            chan, _ = yield from _create_session(conn, 'invalid_exit_lang')

            yield from chan.wait_closed()

        yield from conn.wait_closed()

    @asynctest
    def test_window_adjust_after_eof(self):
        """Test receiving window adjust after EOF"""

        with (yield from self.connect()) as conn:
            chan, _ = yield from _create_session(conn, 'window_after_close')

            yield from chan.wait_closed()

        yield from conn.wait_closed()

    @asynctest
    def test_empty_data(self):
        """Test receiving empty data packet"""

        with (yield from self.connect()) as conn:
            chan, _ = yield from _create_session(conn, 'empty_data')

            chan.close()

        yield from conn.wait_closed()

    @asynctest
    def test_partial_unicode(self):
        """Test receiving Unicode data spread across two packets"""

        with (yield from self.connect()) as conn:
            chan, session = yield from _create_session(conn, 'partial_unicode')

            yield from chan.wait_closed()

            result = ''.join(session.recv_buf[None])
            self.assertEqual(result, '\xff\xff')

        yield from conn.wait_closed()

    @asynctest
    def test_partial_unicode_at_eof(self):
        """Test receiving partial Unicode data and then EOF"""

        with (yield from self.connect()) as conn:
            chan, session = yield from _create_session(
                conn, 'partial_unicode_at_eof')

            yield from chan.wait_closed()
            self.assertIsInstance(session.exc, asyncssh.DisconnectError)

        yield from conn.wait_closed()

    @asynctest
    def test_unicode_error(self):
        """Test receiving bad Unicode data"""

        with (yield from self.connect()) as conn:
            with self.assertRaises(asyncssh.DisconnectError):
                yield from _create_session(conn, 'unicode_error')

        yield from conn.wait_closed()

    @asynctest
    def test_data_past_window(self):
        """Test receiving a data packet past the advertised window"""

        with (yield from self.connect()) as conn:
            chan, _ = yield from _create_session(conn, 'data_past_window')

            yield from chan.wait_closed()

        yield from conn.wait_closed()

    @asynctest
    def test_data_after_eof(self):
        """Test receiving data after EOF"""

        with (yield from self.connect()) as conn:
            chan, _ = yield from _create_session(conn, 'data_after_eof')

            yield from chan.wait_closed()

        yield from conn.wait_closed()

    @asynctest
    def test_data_after_close(self):
        """Test receiving data after close"""

        with (yield from self.connect()) as conn:
            chan, _ = yield from _create_session(conn, 'data_after_close')

            chan.write(4*1025*1024*'\0')
            chan.close()
            yield from asyncio.sleep(0.2)
            yield from chan.wait_closed()

        yield from conn.wait_closed()

    @asynctest
    def test_extended_data_after_eof(self):
        """Test receiving extended data after EOF"""

        with (yield from self.connect()) as conn:
            chan, _ = yield from _create_session(conn, 'ext_data_after_eof')

            yield from chan.wait_closed()

        yield from conn.wait_closed()

    @asynctest
    def test_invalid_datatype(self):
        """Test receiving data with invalid data type"""

        with (yield from self.connect()) as conn:
            chan, _ = yield from _create_session(conn, 'invalid_datatype')

            yield from chan.wait_closed()

        yield from conn.wait_closed()

    @asynctest
    def test_double_eof(self):
        """Test receiving two EOF messages"""

        with (yield from self.connect()) as conn:
            chan, _ = yield from _create_session(conn, 'double_eof')

            yield from chan.wait_closed()

        yield from conn.wait_closed()

    @asynctest
    def test_double_close(self):
        """Test receiving two close messages"""

        with (yield from self.connect()) as conn:
            chan, _ = yield from _create_session(conn, 'double_close')
            chan.pause_reading()
            yield from asyncio.sleep(0.2)
            chan.resume_reading()

            yield from chan.wait_closed()

        yield from conn.wait_closed()

    @asynctest
    def test_request_after_close(self):
        """Test receiving a channel request after a close"""

        with (yield from self.connect()) as conn:
            chan, _ = yield from _create_session(conn, 'request_after_close')

            yield from chan.wait_closed()

        yield from conn.wait_closed()

    @asynctest
    def test_late_auth_banner(self):
        """Test server sending authentication banner after auth completes"""

        with (yield from self.connect()) as conn:
            chan, session = yield from _create_session(conn,
                                                       'late_auth_banner')

            yield from chan.wait_closed()
            self.assertEqual(session.exit_status, 1)

        yield from conn.wait_closed()

    @asynctest
    def test_unexpected_userauth_request(self):
        """Test userauth request sent to client"""

        with (yield from self.connect()) as conn:
            chan, _ = yield from _create_session(conn, 'unexpected_auth')

            yield from chan.wait_closed()

        yield from conn.wait_closed()

    @asynctest
    def test_unknown_action(self):
        """Test unknown action"""

        with (yield from self.connect()) as conn:
            chan, session = yield from _create_session(conn, 'unknown')

            yield from chan.wait_closed()
            self.assertEqual(session.exit_status, 255)

        yield from conn.wait_closed()
