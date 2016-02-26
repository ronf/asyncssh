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

"""SSH server used for unit tests"""

import asyncio
import os
import signal

from unittest.mock import patch

import asyncssh
from asyncssh.constants import MSG_CHANNEL_OPEN_CONFIRMATION
from asyncssh.constants import MSG_CHANNEL_OPEN_FAILURE
from asyncssh.constants import MSG_CHANNEL_WINDOW_ADJUST
from asyncssh.constants import MSG_CHANNEL_DATA
from asyncssh.constants import MSG_CHANNEL_EXTENDED_DATA
from asyncssh.constants import MSG_CHANNEL_EOF, MSG_CHANNEL_CLOSE
from asyncssh.constants import MSG_CHANNEL_SUCCESS
from asyncssh.packet import String, UInt32

from .util import echo, run, AsyncTestCase


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

    def send_packet(self, pkttype, *args):
        """Send a packet for unit testing (bypassing state checks)"""

        self._send_packet(pkttype, *args)


class _EchoSession(asyncssh.SSHServerSession):
    """A shell session which echos data from stdin to stdout/stderr"""

    def __init__(self):
        self._chan = None

    def connection_made(self, chan):
        """Handle session open"""

        self._chan = chan

    def shell_requested(self):
        """Handle shell request"""

        if self._chan.get_extra_info('username') == 'close':
            self._chan.close()

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


@asyncio.coroutine
def _pause(reader, writer):
    """Sleep to allow buffered data to build up and trigger a pause"""

    yield from asyncio.sleep(0.1)
    yield from reader.read()
    writer.close()


class _Server(asyncssh.SSHServer):
    """Unit test SSH server"""

    def __init__(self):
        self._conn = None

    @asyncio.coroutine
    def _begin_session(self, stdin, stdout, stderr):
        """Begin processing a new session"""

        action = stdin.channel.get_command() or stdin.channel.get_subsystem()
        if not action:
            action = 'echo'

        if action == 'agent':
            agent = yield from asyncssh.connect_agent(self._conn)
            if agent:
                stdout.write(str(len((yield from agent.get_keys()))) + '\n')
            else:
                stdout.write('fail\n')
        elif action == 'close':
            yield from stdin.read(1)
            stdout.write('\n')
        elif action == 'disconnect':
            stdout.write((yield from stdin.read(1)))

            raise asyncssh.DisconnectError(asyncssh.DISC_CONNECTION_LOST,
                                           'Connection lost')
        elif action == 'echo':
            yield from echo(stdin, stdout, stderr)
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
            stdin.channel.send_packet(MSG_CHANNEL_CLOSE)
        elif action == 'request_after_close':
            stdin.channel.send_packet(MSG_CHANNEL_CLOSE)
            stdin.channel.exit(1)
        elif action == 'invalid_response':
            stdin.channel.send_packet(MSG_CHANNEL_SUCCESS)
        else:
            stdin.channel.exit(255)

        stdin.channel.close()
        yield from stdin.channel.wait_closed()

    def _begin_session_non_async(self, stdin, stdout, stderr):
        """Non-async version of session handler"""

        self._conn.create_task(self._begin_session(stdin, stdout, stderr))

    def connection_made(self, conn):
        """Record connection object for later use"""

        self._conn = conn

    def begin_auth(self, username):
        """Require authentication"""

        self._conn.send_auth_banner('auth banner')
        self._conn.send_debug('debug')

        return username not in ('guest', 'close', 'echo', 'no_channels')

    def password_auth_supported(self):
        """Enable password authentication"""

        return True

    def validate_password(self, username, password):
        """Require username and password to both be pw"""

        if password == 'oldpw':
            raise asyncssh.PasswordChangeRequired('Password change required')
        else:
            return password == 'pw'

    def change_password(self, username, old_password, new_password):
        """Only allow password to be changed for user pw"""

        return username == 'pw' and old_password == 'oldpw'

    def kbdint_auth_supported(self):
        """Enable keyboard-interactive authentication"""

        return True

    def get_kbdint_challenge(self, username, lang, submethods):
        """Return a single password prompt"""

        if username == 'kbdint':
            return '', '', '', [('Password:', False)]
        else:
            return False

    def validate_kbdint_response(self, username, responses):
        """Require username and response to both be kbdint"""

        return (username == 'kbdint' and len(responses) == 1 and
                responses[0] == 'kbdint')

    def session_requested(self):
        """Handle a request to create a new session"""

        username = self._conn.get_extra_info('username')

        with patch('asyncssh.connection.SSHServerChannel', _ServerChannel):
            channel = self._conn.create_server_channel()

            if username in {'close', 'echo'}:
                return (channel, _EchoSession())
            elif username == 'non_async':
                return (channel, self._begin_session_non_async)
            elif username != 'no_channels':
                return (channel, self._begin_session)
            else:
                return False

    def connection_requested(self, dest_host, dest_port, orig_host, orig_port):
        """Handle a request to create a new connection"""

        if dest_port == 0:
            return True
        elif dest_port == 7:
            return echo
        elif dest_port == 8:
            return _pause
        else:
            return False

    def unix_connection_requested(self, dest_path):
        """Handle a request to create a new UNIX domain connection"""

        if dest_path == '/echo':
            return echo
        else:
            return False

    def server_requested(self, listen_host, listen_port):
        """Handle a request to create a new socket listener"""

        return listen_host != 'fail'

    def unix_server_requested(self, listen_path):
        """Handle a request to create a new UNIX domain listener"""

        return listen_path != 'fail'


class ServerTestCase(AsyncTestCase):
    """Unit test class which starts an SSH server and agent"""

    # Pylint doesn't like mixed case method names, but this was chosen to
    # match the convention used in the unittest module.

    # pylint: disable=invalid-name

    _server = None
    _server_addr = None
    _server_port = None
    _agent_pid = None

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SSH server for the tests to use"""

        return (yield from asyncssh.create_server(
            _Server, '', 0, loop=cls.loop, server_host_keys=['skey'],
            authorized_client_keys='authorized_keys'))

    @classmethod
    @asyncio.coroutine
    def asyncSetUpClass(cls):
        """Set up keys, an SSH server, and an SSH agent for the tests to use"""

        run('ssh-keygen -q -b 2048 -t rsa -N "" -f ckey')
        run('ssh-keygen -q -b 2048 -t rsa -N "" -f skey')

        run('mkdir .ssh')
        run('chmod 700 .ssh')
        run('cp ckey .ssh/id_rsa')
        run('cp ckey.pub .ssh/id_rsa.pub')
        run('cp ckey.pub authorized_keys')
        run('printf "cert-authority " >> authorized_keys')
        run('cat ckey.pub >> authorized_keys')

        cls._server = yield from cls.start_server()

        sock = cls._server.sockets[0]
        cls._server_addr, cls._server_port = sock.getsockname()[:2]

        output = run('ssh-agent -a agent')
        cls._agent_pid = int(output.splitlines()[2].split()[3][:-1])

        os.environ['SSH_AUTH_SOCK'] = 'agent'
        run('ssh-add ckey')

        os.environ['LOGNAME'] = 'guest'
        os.environ['HOME'] = '.'

    @classmethod
    @asyncio.coroutine
    def asyncTearDownClass(cls):
        """Shut down test server and agent"""

        # Wait a bit for existing tasks to exit
        yield from asyncio.sleep(1)

        cls._server.close()
        yield from cls._server.wait_closed()

        os.kill(cls._agent_pid, signal.SIGTERM)

    # pylint: enable=invalid-name

    @asyncio.coroutine
    def create_connection(self, client_factory,
                          known_hosts=(['skey.pub'], [], []), **kwargs):
        """Create a connection to the test server"""

        return (yield from asyncssh.create_connection(client_factory,
                                                      self._server_addr,
                                                      self._server_port,
                                                      loop=self.loop,
                                                      known_hosts=known_hosts,
                                                      **kwargs))

    @asyncio.coroutine
    def connect(self, known_hosts=(['skey.pub'], [], []), **kwargs):
        """Open a connection to the test server"""

        return (yield from asyncssh.connect(self._server_addr,
                                            self._server_port, loop=self.loop,
                                            known_hosts=known_hosts, **kwargs))
