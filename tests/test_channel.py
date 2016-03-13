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

from unittest.mock import patch

import asyncssh

from asyncssh.constants import DEFAULT_LANG
from asyncssh.packet import Byte, String
from asyncssh.public_key import CERT_TYPE_USER

from .server import ServerTestCase
from .util import asynctest, make_certificate

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

    @asyncio.coroutine
    def make_request(self, request, *args):
        """Make a custom request (for unit testing)"""

        yield from self._make_request(request, *args)


class _ClientSession:
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

    def session_started(self):
        """Handle the start of a new session"""

        pass

    def data_received(self, data, datatype):
        """Handle data from the channel"""

        self.recv_buf[datatype].append(data)

    def eof_received(self):
        """Handle EOF on the channel"""

        pass

    def pause_writing(self):
        """Handle a request to stop writing to the channel"""

        pass

    def resume_writing(self):
        """Handle a request to resume writing to the channel"""

        pass

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


class _TestChannel(ServerTestCase):
    """Unit tests for AsyncSSH channel API"""

    # pylint: disable=too-many-public-methods

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
            with self.assertRaises(asyncssh.DisconnectError):
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
                                       None, False)

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

        with (yield from self.connect(username='ckey',
                                      agent_forwarding=True)) as conn:
            chan, session = yield from _create_session(conn, 'agent')

            yield from chan.wait_closed()

            result = ''.join(session.recv_buf[None])
            self.assertEqual(result, '1\n')

        yield from conn.wait_closed()

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

            result = ''.join(session.recv_buf[None])
            self.assertEqual(result, 'fail\n')

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
            self.assertEqual(result, "('ansi', (80, 24, 0, 0), 9600)\n")

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
            self.assertEqual(result, "('ansi', (80, 24, 480, 240), 9600)\n")

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
    def test_pty_disallowed(self):
        """Test rejection of pty request"""

        ckey = asyncssh.read_private_key('ckey')
        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_USER, ckey, ckey, ['ckey'],
                                extensions={'no-pty': ''})

        with (yield from self.connect(username='ckey',
                                      client_keys=[(ckey, cert)],
                                      agent_forwarding=True)) as conn:
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
                self.assertEqual(result, "('ansi', (0, 0, 0, 0), 9600)\n")

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
    def test_add_channel_after_close(self):
        """Test opening a connection after a close"""

        with (yield from self.connect()) as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                yield from conn.open_connection('localhost', 9)

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
    def test_unknown_action(self):
        """Test unknown action"""

        with (yield from self.connect()) as conn:
            chan, session = yield from _create_session(conn, 'unknown')

            yield from chan.wait_closed()
            self.assertEqual(session.exit_status, 255)

        yield from conn.wait_closed()
