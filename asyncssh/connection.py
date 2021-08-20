# Copyright (c) 2013-2021 by Ron Frederick <ronf@timeheart.net> and others.
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

"""SSH connection handlers"""

import asyncio
import getpass
import inspect
import io
import os
import shlex
import socket
import sys
import tempfile
import time

from collections import OrderedDict
from functools import partial
from pathlib import Path

from .agent import SSHAgentClient, SSHAgentListener

from .auth import get_client_auth_methods, lookup_client_auth
from .auth import get_server_auth_methods, lookup_server_auth

from .auth_keys import read_authorized_keys

from .channel import SSHClientChannel, SSHServerChannel
from .channel import SSHTCPChannel, SSHUNIXChannel
from .channel import SSHX11Channel, SSHAgentChannel

from .client import SSHClient

from .compression import get_compression_algs, get_default_compression_algs
from .compression import get_compression_params
from .compression import get_compressor, get_decompressor

from .config import SSHClientConfig, SSHServerConfig

from .constants import DEFAULT_LANG, DEFAULT_PORT
from .constants import DISC_BY_APPLICATION
from .constants import EXTENDED_DATA_STDERR
from .constants import MSG_DISCONNECT, MSG_IGNORE, MSG_UNIMPLEMENTED, MSG_DEBUG
from .constants import MSG_SERVICE_REQUEST, MSG_SERVICE_ACCEPT, MSG_EXT_INFO
from .constants import MSG_CHANNEL_OPEN, MSG_CHANNEL_OPEN_CONFIRMATION
from .constants import MSG_CHANNEL_OPEN_FAILURE
from .constants import MSG_CHANNEL_FIRST, MSG_CHANNEL_LAST
from .constants import MSG_KEXINIT, MSG_NEWKEYS, MSG_KEX_FIRST, MSG_KEX_LAST
from .constants import MSG_USERAUTH_REQUEST, MSG_USERAUTH_FAILURE
from .constants import MSG_USERAUTH_SUCCESS, MSG_USERAUTH_BANNER
from .constants import MSG_USERAUTH_FIRST, MSG_USERAUTH_LAST
from .constants import MSG_GLOBAL_REQUEST, MSG_REQUEST_SUCCESS
from .constants import MSG_REQUEST_FAILURE
from .constants import OPEN_ADMINISTRATIVELY_PROHIBITED, OPEN_CONNECT_FAILED
from .constants import OPEN_UNKNOWN_CHANNEL_TYPE

from .encryption import get_encryption_algs, get_default_encryption_algs
from .encryption import get_encryption_params, get_encryption

from .forward import SSHForwarder

from .gss import GSSClient, GSSServer, GSSError

from .kex import get_kex_algs, get_default_kex_algs, expand_kex_algs, get_kex

from .keysign import find_keysign, get_keysign_keys

from .known_hosts import match_known_hosts

from .listener import SSHTCPClientListener, SSHUNIXClientListener
from .listener import create_tcp_forward_listener, create_unix_forward_listener
from .listener import create_socks_listener

from .logging import logger

from .mac import get_mac_algs, get_default_mac_algs

from .misc import ChannelListenError, ChannelOpenError, DisconnectError
from .misc import CompressionError, ConnectionLost, HostKeyNotVerifiable
from .misc import KeyExchangeFailed, IllegalUserName, MACError
from .misc import PasswordChangeRequired, PermissionDenied, ProtocolError
from .misc import ProtocolNotSupported, ServiceNotAvailable, Options
from .misc import async_context_manager, construct_disc_error
from .misc import get_symbol_names, ip_address, map_handler_name
from .misc import parse_byte_count, parse_time_interval

from .packet import Boolean, Byte, NameList, String, UInt32
from .packet import PacketDecodeError, SSHPacket, SSHPacketHandler

from .pattern import WildcardPattern

from .pkcs11 import load_pkcs11_keys

from .process import PIPE, SSHClientProcess, SSHServerProcess

from .public_key import CERT_TYPE_HOST, CERT_TYPE_USER, KeyImportError
from .public_key import decode_ssh_public_key, decode_ssh_certificate
from .public_key import get_public_key_algs, get_default_public_key_algs
from .public_key import get_certificate_algs, get_default_certificate_algs
from .public_key import get_x509_certificate_algs
from .public_key import get_default_x509_certificate_algs
from .public_key import load_keypairs, load_default_keypairs
from .public_key import load_public_keys, load_default_host_public_keys
from .public_key import load_certificates
from .public_key import load_identities, load_default_identities

from .saslprep import saslprep, SASLPrepError

from .server import SSHServer

from .sftp import SFTPServer, start_sftp_client

from .stream import SSHClientStreamSession, SSHServerStreamSession
from .stream import SSHTCPStreamSession, SSHUNIXStreamSession
from .stream import SSHReader, SSHWriter

from .subprocess import SSHSubprocessTransport

from .version import __version__

from .x11 import create_x11_client_listener, create_x11_server_listener


# SSH service names
_USERAUTH_SERVICE = b'ssh-userauth'
_CONNECTION_SERVICE = b'ssh-connection'

# Max banner and version line length and count
_MAX_BANNER_LINES = 1024
_MAX_BANNER_LINE_LEN = 8192
_MAX_VERSION_LINE_LEN = 255

# Max allowed username length
_MAX_USERNAME_LEN = 1024

# Default rekey parameters
_DEFAULT_REKEY_BYTES = 1 << 30      # 1 GiB
_DEFAULT_REKEY_SECONDS = 3600       # 1 hour

# Default login timeout
_DEFAULT_LOGIN_TIMEOUT = 120        # 2 minutes

# Default keepalive interval and count max
_DEFAULT_KEEPALIVE_INTERVAL = 0     # disabled by default
_DEFAULT_KEEPALIVE_COUNT_MAX = 3

# Default channel parameters
_DEFAULT_WINDOW = 2*1024*1024       # 2 MiB
_DEFAULT_MAX_PKTSIZE = 32768        # 32 kiB

# Default line editor parameters
_DEFAULT_LINE_HISTORY = 1000        # 1000 lines
_DEFAULT_MAX_LINE_LENGTH = 1024     # 1024 characters


async def _open_proxy(loop, command, conn_factory):
    """Open a tunnel running a proxy command"""

    class _ProxyCommandTunnel(asyncio.SubprocessProtocol):
        """SSH proxy command tunnel"""

        def __init__(self):
            self._transport = None
            self._stdin = None
            self._conn = conn_factory()
            self._close_event = asyncio.Event()

        def get_owner(self):
            """Return the connection running over this tunnel"""

            return self._conn

        def get_extra_info(self, name, default=None):
            """Return extra information associated with this tunnel"""

            return self._transport.get_extra_info(name, default)

        def connection_made(self, transport):
            """Handle startup of the subprocess"""

            self._transport = transport
            self._stdin = transport.get_pipe_transport(0)
            self._conn.connection_made(self)

        def pipe_data_received(self, fd, data):
            """Handle data received from this tunnel"""

            # pylint: disable=unused-argument

            self._conn.data_received(data)

        def pipe_connection_lost(self, fd, exc):
            """Handle when this tunnel is closed"""

            # pylint: disable=unused-argument

            self._conn.connection_lost(exc)

        def is_closing(self):
            """Return whether the transport is closing or not"""

            return self._transport.is_closing()

        def write(self, data):
            """Write data to this tunnel"""

            self._stdin.write(data)

        def abort(self):
            """Forcibly close this tunnel"""

            self.close()

        def close(self):
            """Close this tunnel"""

            self._transport.close()
            self._close_event.set()


    _, tunnel = await loop.subprocess_exec(_ProxyCommandTunnel, *command)

    return tunnel.get_owner()


async def _open_tunnel(tunnel):
    """Parse and open connection to tunnel over"""

    if isinstance(tunnel, str):
        if '@' in tunnel:
            username, host = tunnel.rsplit('@', 1)
        else:
            username, host = (), tunnel

        if ':' in host:
            host, port = host.rsplit(':', 1)
            port = int(port)
        else:
            port = ()

        return await connect(host, port, username=username)
    else:
        return None


async def _connect(options, loop, flags, conn_factory, msg):
    """Make outbound TCP or SSH tunneled connection"""

    host = options.host
    port = options.port
    tunnel = options.tunnel
    family = options.family
    local_addr = options.local_addr
    proxy_command = options.proxy_command
    free_conn = True

    new_tunnel = await _open_tunnel(tunnel)

    if new_tunnel:
        new_tunnel.logger.info('%s %s via %s', msg, (host, port), tunnel)

        # pylint: disable=broad-except
        try:
            _, conn = await new_tunnel.create_connection(conn_factory,
                                                         host, port)
        except Exception:
            new_tunnel.close()
            await new_tunnel.wait_closed()
            raise
        else:
            conn.set_tunnel(new_tunnel)
    elif tunnel:
        tunnel_logger = getattr(tunnel, 'logger', logger)
        tunnel_logger.info('%s %s via SSH tunnel', msg, (host, port))
        _, conn = await tunnel.create_connection(conn_factory, host, port)
    elif proxy_command:
        conn = await _open_proxy(loop, proxy_command, conn_factory)
    else:
        logger.info('%s %s', msg, (host, port))
        _, conn = await loop.create_connection(conn_factory, host, port,
                                               family=family, flags=flags,
                                               local_addr=local_addr)

    # pylint: disable=broad-except
    try:
        await conn.wait_established()
        free_conn = False

        if new_tunnel:
            conn.set_tunnel(new_tunnel)

        return conn
    finally:
        if free_conn:
            conn.abort()
            await conn.wait_closed()


async def _listen(options, loop, flags, backlog, reuse_address,
                  reuse_port, conn_factory, msg):
    """Make inbound TCP or SSH tunneled listener"""

    def tunnel_factory(_orig_host, _orig_port):
        """Ignore original host and port"""

        return conn_factory()

    host = options.host
    port = options.port
    tunnel = options.tunnel
    family = options.family

    new_tunnel = await _open_tunnel(tunnel)

    if new_tunnel:
        new_tunnel.logger.info('%s %s via %s', msg, (host, port), tunnel)

        # pylint: disable=broad-except
        try:
            server = await new_tunnel.create_server(tunnel_factory, host, port)
        except Exception:
            new_tunnel.close()
            await new_tunnel.wait_closed()
            raise
        else:
            server.set_tunnel(new_tunnel)
    elif tunnel:
        tunnel_logger = getattr(tunnel, 'logger', logger)
        tunnel_logger.info('%s %s via SSH tunnel', msg, (host, port))
        server = await tunnel.create_server(tunnel_factory, host, port)
    else:
        logger.info('%s %s', msg, (host, port))
        server = await loop.create_server(conn_factory, host, port,
                                          family=family, flags=flags,
                                          backlog=backlog,
                                          reuse_address=reuse_address,
                                          reuse_port=reuse_port)

    return SSHAcceptor(server, options)


def _validate_version(version):
    """Validate requested SSH version"""

    if version == ():
        version = b'AsyncSSH_' + __version__.encode('ascii')
    else:
        if isinstance(version, str):
            version = version.encode('ascii')

        # Version including 'SSH-2.0-' and CRLF must be 255 chars or less
        if len(version) > 245:
            raise ValueError('Version string is too long')

        for b in version:
            if b < 0x20 or b > 0x7e:
                raise ValueError('Version string must be printable ASCII')

    return version


def _expand_algs(alg_type, algs, possible_algs, default_algs, strict_match):
    """Expand the set of allowed algorithms"""

    if algs[:1] in '^+-':
        prefix = algs[:1]
        algs = algs[1:]
    else:
        prefix = ''

    matched = []

    for pat in algs.split(','):
        pattern = WildcardPattern(pat)

        matches = [alg for alg in possible_algs
                   if pattern.matches(alg.decode('ascii'))]

        if not matches and strict_match:
            raise ValueError('"%s" matches no valid %s algorithms' %
                             (pat, alg_type))

        matched.extend(matches)

    if prefix == '^':
        return matched + default_algs
    elif prefix == '+':
        return default_algs + matched
    elif prefix == '-':
        return [alg for alg in default_algs if alg not in matched]
    else:
        return matched


def _select_algs(alg_type, algs, possible_algs, default_algs,
                 config_algs, none_value=None):
    """Select a set of allowed algorithms"""

    if algs == ():
        algs = config_algs
        strict_match = False
    else:
        strict_match = True

    if algs in ((), 'default'):
        return default_algs
    elif algs:
        if isinstance(algs, str):
            algs = _expand_algs(alg_type, algs, possible_algs,
                                default_algs, strict_match)
        else:
            algs = [alg.encode('ascii') for alg in algs]

        result = []

        for alg in algs:
            if alg not in possible_algs:
                raise ValueError('%s is not a valid %s algorithm' %
                                 (alg.decode('ascii'), alg_type))

            if alg not in result:
                result.append(alg)

        return result
    elif none_value:
        return [none_value]
    else:
        raise ValueError('No %s algorithms selected' % alg_type)


def _select_host_key_algs(algs, config_algs, default_algs=()):
    """Select a set of allowed host key algorithms"""

    possible_algs = (get_x509_certificate_algs() + get_certificate_algs() +
                     get_public_key_algs())

    return _select_algs('host key', algs, possible_algs,
                        default_algs, config_algs)


def _validate_algs(config, kex_algs, enc_algs, mac_algs, cmp_algs,
                   sig_algs, allow_x509):
    """Validate requested algorithms"""

    kex_algs = _select_algs('key exchange', kex_algs, get_kex_algs(),
                            get_default_kex_algs(),
                            config.get('KexAlgorithms', ()))
    enc_algs = _select_algs('encryption', enc_algs, get_encryption_algs(),
                            get_default_encryption_algs(),
                            config.get('Ciphers', ()))
    mac_algs = _select_algs('MAC', mac_algs, get_mac_algs(),
                            get_default_mac_algs(), config.get('MACs', ()))
    cmp_algs = _select_algs('compression', cmp_algs, get_compression_algs(),
                            get_default_compression_algs(),
                            config.get_compression_algs(()), b'none')

    allowed_sig_algs = get_x509_certificate_algs() if allow_x509 else []
    allowed_sig_algs = allowed_sig_algs + get_public_key_algs()

    default_sig_algs = get_default_x509_certificate_algs() if allow_x509 else []
    default_sig_algs = allowed_sig_algs + get_default_public_key_algs()

    sig_algs = _select_algs('signature', sig_algs,
                            allowed_sig_algs, default_sig_algs,
                            config.get('CASignatureAlgorithms', ()))

    return kex_algs, enc_algs, mac_algs, cmp_algs, sig_algs


class SSHAcceptor:
    """SSH acceptor

       This class in a wrapper around an :class:`asyncio.Server` listener
       which provides the ability to update the the set of SSH client or
       server connection options associated wtih that listener. This is
       accomplished by calling the :meth:`update` method, which takes the
       same keyword arguments as the :class:`SSHClientConnectionOptions`
       and :class:`SSHServerConnectionOptions` classes.

       In addition, this class supports all of the methods supported by
       :class:`asyncio.Server` to control accepting of new connections.

    """

    def __init__(self, server, options):
        self._server = server
        self._options = options

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        self.close()
        await self.wait_closed()

    def __getattr__(self, name):
        return getattr(self._server, name)

    def update(self, **kwargs):
        """Update options on an SSH listener

           Acceptors started by :func:`listen` support options defined
           in :class:`SSHServerConnectionOptions`. Acceptors started
           by :func:`listen_reverse` support options defined in
           :class:`SSHClientConnectionOptions`.

           Changes apply only to SSH client/server connections accepted
           after the change is made. Previously accepted connections
           will continue to use the options set when they were accepted.

        """

        self._options.update(kwargs)


class SSHConnection(SSHPacketHandler, asyncio.Protocol):
    """Parent class for SSH connections"""

    _handler_names = get_symbol_names(globals(), 'MSG_')

    next_conn = 0    # Next connection number, for logging

    @staticmethod
    def _get_next_conn():
        """Return the next available connection number (for logging)"""

        next_conn = SSHConnection.next_conn
        SSHConnection.next_conn += 1
        return next_conn

    def __init__(self, loop, options, acceptor, error_handler, wait, server):
        self._loop = loop
        self._options = options
        self._protocol_factory = options.protocol_factory
        self._acceptor = acceptor
        self._error_handler = error_handler
        self._server = server
        self._wait = wait
        self._waiter = loop.create_future()

        self._transport = None
        self._local_addr = None
        self._local_port = None
        self._peer_host = None
        self._peer_addr = None
        self._peer_port = None
        self._tcp_keepalive = options.tcp_keepalive
        self._owner = None
        self._extra = {}

        self._inpbuf = b''
        self._packet = b''
        self._pktlen = 0
        self._banner_lines = 0

        self._version = options.version
        self._client_version = b''
        self._server_version = b''
        self._client_kexinit = b''
        self._server_kexinit = b''
        self._session_id = None

        self._send_seq = 0
        self._send_encryption = None
        self._send_enchdrlen = 5
        self._send_blocksize = 8
        self._compressor = None
        self._compress_after_auth = False
        self._deferred_packets = []

        self._recv_handler = self._recv_version
        self._recv_seq = 0
        self._recv_encryption = None
        self._recv_blocksize = 8
        self._recv_macsize = 0
        self._decompressor = None
        self._decompress_after_auth = None
        self._next_recv_encryption = None
        self._next_recv_blocksize = 0
        self._next_recv_macsize = 0
        self._next_decompressor = None
        self._next_decompress_after_auth = None

        self._trusted_host_keys = set()
        self._trusted_host_key_algs = []
        self._trusted_ca_keys = set()
        self._revoked_host_keys = set()

        self._x509_trusted_certs = options.x509_trusted_certs
        self._x509_trusted_cert_paths = options.x509_trusted_cert_paths
        self._x509_revoked_certs = []
        self._x509_trusted_subjects = []
        self._x509_revoked_subjects = []
        self._x509_purposes = options.x509_purposes

        self._kex_algs = options.kex_algs
        self._enc_algs = options.encryption_algs
        self._mac_algs = options.mac_algs
        self._cmp_algs = options.compression_algs
        self._sig_algs = options.signature_algs

        self._host_based_auth = options.host_based_auth
        self._public_key_auth = options.public_key_auth
        self._kbdint_auth = options.kbdint_auth
        self._password_auth = options.password_auth

        self._kex = None
        self._kexinit_sent = False
        self._kex_complete = False
        self._ignore_first_kex = False

        self._gss = None
        self._gss_kex = False
        self._gss_auth = False
        self._gss_kex_auth = False
        self._gss_mic_auth = False

        self._preferred_auth = None

        self._rekey_bytes = options.rekey_bytes
        self._rekey_seconds = options.rekey_seconds
        self._rekey_bytes_sent = 0
        self._rekey_time = 0

        self._keepalive_count = 0
        self._keepalive_count_max = options.keepalive_count_max
        self._keepalive_interval = options.keepalive_interval
        self._keepalive_timer = None

        self._tunnel = None

        self._enc_alg_cs = None
        self._enc_alg_sc = None

        self._mac_alg_cs = None
        self._mac_alg_sc = None

        self._cmp_alg_cs = None
        self._cmp_alg_sc = None

        self._can_send_ext_info = False
        self._extensions_to_send = OrderedDict()

        self._server_sig_algs = ()

        self._next_service = None

        self._agent = None
        self._auth = None
        self._auth_in_progress = False
        self._auth_complete = False
        self._auth_methods = [b'none']
        self._auth_was_trivial = True
        self._username = None

        self._channels = {}
        self._next_recv_chan = 0

        self._global_request_queue = []
        self._global_request_waiters = []

        self._local_listeners = {}

        self._x11_listener = None

        self._close_event = asyncio.Event()

        self._server_host_key_algs = []

        self._logger = logger.get_child(context='conn=%d' %
                                        self._get_next_conn())

        if options.login_timeout:
            self._login_timer = self._loop.call_later(
                options.login_timeout, self._login_timer_callback)
        else:
            self._login_timer = None

        self._disable_trivial_auth = False

    async def __aenter__(self):
        """Allow SSHConnection to be used as an async context manager"""

        return self

    async def __aexit__(self, *exc_info):
        """Wait for connection close when used as an async context manager"""

        if not self._loop.is_closed(): # pragma: no branch
            self.close()

        await self.wait_closed()

    @property
    def logger(self):
        """A logger associated with this connection"""

        return self._logger

    def _cleanup(self, exc):
        """Clean up this connection"""

        self._cancel_keepalive_timer()

        for chan in list(self._channels.values()):
            chan.process_connection_close(exc)

        for listener in list(self._local_listeners.values()):
            listener.close()

        while self._global_request_waiters:
            self._process_global_response(MSG_REQUEST_FAILURE, None,
                                          SSHPacket(b''))

        if self._auth:
            self._auth.cancel()
            self._auth = None

        if self._error_handler:
            self._error_handler(self, exc)
            self._acceptor = None
            self._error_handler = None

        if self._wait and not self._waiter.cancelled():
            self._waiter.set_exception(exc)
            self._wait = None

        if self._owner: # pragma: no branch
            self._owner.connection_lost(exc)
            self._owner = None

        self._cancel_login_timer()
        self._close_event.set()

        self._inpbuf = b''
        self._recv_handler = None

        if self._tunnel:
            self._tunnel.close()
            self._tunnel = None

    def _cancel_login_timer(self):
        """Cancel the login timer"""

        if self._login_timer:
            self._login_timer.cancel()
            self._login_timer = None

    def _login_timer_callback(self):
        """Close the connection if authentication hasn't completed yet"""

        self._login_timer = None

        self.connection_lost(ConnectionLost('Login timeout expired'))

    def _cancel_keepalive_timer(self):
        """Cancel the keepalive timer"""

        if self._keepalive_timer:
            self._keepalive_timer.cancel()
            self._keepalive_timer = None

    def _set_keepalive_timer(self):
        """Set the keepalive timer"""

        if self._keepalive_interval:
            self._keepalive_timer = self._loop.call_later(
                self._keepalive_interval, self._keepalive_timer_callback)

    def _reset_keepalive_timer(self):
        """Reset the keepalive timer"""

        if self._auth_complete:
            self._cancel_keepalive_timer()
            self._set_keepalive_timer()

    async def _make_keepalive_request(self):
        """Send keepalive request"""

        self.logger.debug1('Sending keepalive request')

        await self._make_global_request('keepalive@openssh.com')

        if self._keepalive_timer:
            self.logger.debug1('Got keepalive response')

        self._keepalive_count = 0

    def _keepalive_timer_callback(self):
        """Handle keepalive check"""

        self._keepalive_count += 1

        if self._keepalive_count > self._keepalive_count_max:
            self.connection_lost(
                ConnectionLost(('Server' if self.is_client() else 'Client') +
                               ' not responding to keepalive'))
        else:
            self._set_keepalive_timer()
            self.create_task(self._make_keepalive_request())

    def _force_close(self, exc):
        """Force this connection to close immediately"""

        if not self._transport:
            return

        self._transport.abort()
        self._transport = None

        self._loop.call_soon(self._cleanup, exc)

    def _reap_task(self, task_logger, task):
        """Collect result of an async task, reporting errors"""

        # pylint: disable=broad-except
        try:
            task.result()
        except asyncio.CancelledError:
            pass
        except DisconnectError as exc:
            self._send_disconnect(exc.code, exc.reason, exc.lang)
            self._force_close(exc)
        except Exception:
            self.internal_error(error_logger=task_logger)

    def create_task(self, coro, task_logger=None):
        """Create an asynchronous task which catches and reports errors"""

        task = asyncio.ensure_future(coro)
        task.add_done_callback(partial(self._reap_task, task_logger))
        return task

    def is_client(self):
        """Return if this is a client connection"""

        return not self._server

    def is_server(self):
        """Return if this is a server connection"""

        return self._server

    def get_owner(self):
        """Return the SSHClient or SSHServer which owns this connection"""

        return self._owner

    def get_hash_prefix(self):
        """Return the bytes used in calculating unique connection hashes

           This methods returns a packetized version of the client and
           server version and kexinit strings which is needed to perform
           key exchange hashes.

        """

        return b''.join((String(self._client_version),
                         String(self._server_version),
                         String(self._client_kexinit),
                         String(self._server_kexinit)))

    def set_tunnel(self, tunnel):
        """Set tunnel used to open this connection"""

        self._tunnel = tunnel

    def _match_known_hosts(self, known_hosts, host, addr, port):
        """Determine the set of trusted host keys and certificates"""

        trusted_host_keys, trusted_ca_keys, revoked_host_keys, \
            trusted_x509_certs, revoked_x509_certs, \
            trusted_x509_subjects, revoked_x509_subjects = \
                match_known_hosts(known_hosts, host, addr, port)

        for key in trusted_host_keys:
            self._trusted_host_keys.add(key)

            if key.algorithm not in self._trusted_host_key_algs:
                self._trusted_host_key_algs.extend(key.sig_algorithms)

        self._trusted_ca_keys = set(trusted_ca_keys)
        self._revoked_host_keys = set(revoked_host_keys)

        if self._x509_trusted_certs is not None:
            self._x509_trusted_certs = list(self._x509_trusted_certs)
            self._x509_trusted_certs.extend(trusted_x509_certs)
            self._x509_revoked_certs = set(revoked_x509_certs)

            self._x509_trusted_subjects = trusted_x509_subjects
            self._x509_revoked_subjects = revoked_x509_subjects

    def _validate_openssh_host_certificate(self, host, addr, port, cert):
        """Validate an OpenSSH host certificate"""

        if self._trusted_ca_keys is not None:
            if cert.signing_key in self._revoked_host_keys:
                raise ValueError('Host CA key is revoked')

            if cert.signing_key not in self._trusted_ca_keys and \
               not self._owner.validate_host_ca_key(host, addr, port,
                                                    cert.signing_key):
                raise ValueError('Host CA key is not trusted')

            cert.validate(CERT_TYPE_HOST, host)

        return cert.key

    def _validate_x509_host_certificate_chain(self, host, cert):
        """Validate an X.509 host certificate"""

        if (self._x509_revoked_subjects and
                any(pattern.matches(cert.subject)
                    for pattern in self._x509_revoked_subjects)):
            raise ValueError('X.509 subject name is revoked')

        if (self._x509_trusted_subjects and
                not any(pattern.matches(cert.subject)
                        for pattern in self._x509_trusted_subjects)):
            raise ValueError('X.509 subject name is not trusted')

        # Only validate hostname against X.509 certificate host
        # principals when there are no X.509 trusted subject
        # entries matched in known_hosts.
        if self._x509_trusted_subjects:
            host = None

        cert.validate_chain(self._x509_trusted_certs,
                            self._x509_trusted_cert_paths,
                            self._x509_revoked_certs,
                            self._x509_purposes,
                            host_principal=host)

        return cert.key

    def _validate_host_key(self, host, addr, port, key_data):
        """Validate and return a trusted host key"""

        try:
            cert = decode_ssh_certificate(key_data)
        except KeyImportError:
            pass
        else:
            if cert.is_x509_chain:
                return self._validate_x509_host_certificate_chain(host, cert)
            else:
                return self._validate_openssh_host_certificate(host, addr,
                                                               port, cert)

        try:
            key = decode_ssh_public_key(key_data)
        except KeyImportError:
            pass
        else:
            if self._trusted_host_keys is not None:
                if key in self._revoked_host_keys:
                    raise ValueError('Host key is revoked')

                if key not in self._trusted_host_keys and \
                   not self._owner.validate_host_public_key(host, addr,
                                                            port, key):
                    raise ValueError('Host key is not trusted')

            return key

        raise ValueError('Unable to decode host key')

    def connection_made(self, transport):
        """Handle a newly opened connection"""

        self._transport = transport

        sock = transport.get_extra_info('socket')

        if sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE,
                            self._tcp_keepalive)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        sockname = transport.get_extra_info('sockname')

        if sockname: # pragma: no branch
            self._local_addr, self._local_port = sockname[:2]

        peername = transport.get_extra_info('peername')

        if peername: # pragma: no branch
            self._peer_addr, self._peer_port = peername[:2]

        self._owner = self._protocol_factory()
        self._protocol_factory = None

        # pylint: disable=broad-except
        try:
            self._connection_made()
            self._owner.connection_made(self)
            self._send_version()
        except Exception:
            self._loop.call_soon(self.internal_error, sys.exc_info())

    def connection_lost(self, exc=None):
        """Handle the closing of a connection"""

        if exc is None and self._transport:
            exc = ConnectionLost('Connection lost')

        self._force_close(exc)

    def internal_error(self, exc_info=None, error_logger=None):
        """Handle a fatal error in connection processing"""

        if not exc_info:
            exc_info = sys.exc_info()

        if not error_logger:
            error_logger = self.logger

        error_logger.debug1('Uncaught exception', exc_info=exc_info)
        self._force_close(exc_info[1])

    def session_started(self):
        """Handle session start when opening tunneled SSH connection"""

    # pylint: disable=arguments-differ
    def data_received(self, data, datatype=None):
        """Handle incoming data on the connection"""

        # pylint: disable=unused-argument

        self._inpbuf += data

        self._reset_keepalive_timer()

        # pylint: disable=broad-except
        try:
            while self._inpbuf and self._recv_handler():
                pass
        except DisconnectError as exc:
            self._send_disconnect(exc.code, exc.reason, exc.lang)
            self._force_close(exc)
        except Exception:
            self.internal_error()
    # pylint: enable=arguments-differ

    def eof_received(self):
        """Handle an incoming end of file on the connection"""

        self.connection_lost(None)

    def pause_writing(self):
        """Handle a request from the transport to pause writing data"""

        # Do nothing with this for now

    def resume_writing(self):
        """Handle a request from the transport to resume writing data"""

        # Do nothing with this for now

    def add_channel(self, chan):
        """Add a new channel, returning its channel number"""

        if not self._transport:
            raise ChannelOpenError(OPEN_CONNECT_FAILED,
                                   'SSH connection closed')

        while self._next_recv_chan in self._channels: # pragma: no cover
            self._next_recv_chan = (self._next_recv_chan + 1) & 0xffffffff

        recv_chan = self._next_recv_chan
        self._next_recv_chan = (self._next_recv_chan + 1) & 0xffffffff

        self._channels[recv_chan] = chan
        return recv_chan

    def remove_channel(self, recv_chan):
        """Remove the channel with the specified channel number"""

        del self._channels[recv_chan]

    def get_gss_context(self):
        """Return the GSS context associated with this connection"""

        return self._gss

    def enable_gss_kex_auth(self):
        """Enable GSS key exchange authentication"""

        self._gss_kex_auth = self._gss_auth

    def _choose_alg(self, alg_type, local_algs, remote_algs):
        """Choose a common algorithm from the client & server lists

           This method returns the earliest algorithm on the client's
           list which is supported by the server.

        """

        if self.is_client():
            client_algs, server_algs = local_algs, remote_algs
        else:
            client_algs, server_algs = remote_algs, local_algs

        for alg in client_algs:
            if alg in server_algs:
                return alg

        raise KeyExchangeFailed(
            'No matching %s algorithm found, sent %s and received %s' %
            (alg_type, b','.join(local_algs).decode('ascii'),
             b','.join(remote_algs).decode('ascii')))

    def _get_ext_info_kex_alg(self):
        """Return the kex alg to add if any to request extension info"""

        return [b'ext-info-c'] if self.is_client() else [b'ext-info-s']

    def _send(self, data):
        """Send data to the SSH connection"""

        if self._transport:
            if self._transport.is_closing():
                self._force_close(BrokenPipeError)
            else:
                self._transport.write(data)

    def _send_version(self):
        """Start the SSH handshake"""

        version = b'SSH-2.0-' + self._version

        self.logger.debug1('Sending version %s', version)

        if self.is_client():
            self._client_version = version
            self.set_extra_info(client_version=version.decode('ascii'))
        else:
            self._server_version = version
            self.set_extra_info(server_version=version.decode('ascii'))

        self._send(version + b'\r\n')

    def _recv_version(self):
        """Receive and parse the remote SSH version"""

        idx = self._inpbuf.find(b'\n', 0, _MAX_BANNER_LINE_LEN)
        if idx < 0:
            if len(self._inpbuf) >= _MAX_BANNER_LINE_LEN:
                self._force_close(ProtocolError('Banner line too long'))

            return False

        version = self._inpbuf[:idx]
        if version.endswith(b'\r'):
            version = version[:-1]

        self._inpbuf = self._inpbuf[idx+1:]

        if (version.startswith(b'SSH-2.0-') or
                (self.is_client() and version.startswith(b'SSH-1.99-'))):
            if len(version) > _MAX_VERSION_LINE_LEN:
                self._force_close(ProtocolError('Version too long'))

            # Accept version 2.0, or 1.99 if we're a client
            if self.is_server():
                self._client_version = version
                self.set_extra_info(client_version=version.decode('ascii'))
            else:
                self._server_version = version
                self.set_extra_info(server_version=version.decode('ascii'))

            self.logger.debug1('Received version %s', version)

            self._send_kexinit()
            self._kexinit_sent = True
            self._recv_handler = self._recv_pkthdr
        elif self.is_client() and not version.startswith(b'SSH-'):
            # As a client, ignore the line if it doesn't appear to be a version
            self._banner_lines += 1

            if self._banner_lines > _MAX_BANNER_LINES:
                self._force_close(ProtocolError('Too many banner lines'))
                return False
        else:
            # Otherwise, reject the unknown version
            self._force_close(ProtocolNotSupported('Unsupported SSH version'))
            return False

        return True

    def _recv_pkthdr(self):
        """Receive and parse an SSH packet header"""

        if len(self._inpbuf) < self._recv_blocksize:
            return False

        self._packet = self._inpbuf[:self._recv_blocksize]
        self._inpbuf = self._inpbuf[self._recv_blocksize:]

        if self._recv_encryption:
            self._packet, pktlen = \
                self._recv_encryption.decrypt_header(self._recv_seq,
                                                     self._packet, 4)
        else:
            pktlen = self._packet[:4]

        self._pktlen = int.from_bytes(pktlen, 'big')
        self._recv_handler = self._recv_packet
        return True

    def _recv_packet(self):
        """Receive the remainder of an SSH packet and process it"""

        rem = 4 + self._pktlen + self._recv_macsize - self._recv_blocksize
        if len(self._inpbuf) < rem:
            return False

        seq = self._recv_seq
        rest = self._inpbuf[:rem-self._recv_macsize]
        mac = self._inpbuf[rem-self._recv_macsize:rem]

        if self._recv_encryption:
            packet = self._recv_encryption.decrypt_packet(seq, self._packet,
                                                          rest, 4, mac)

            if not packet:
                raise MACError('MAC verification failed')
        else:
            packet = self._packet[4:] + rest

        self._inpbuf = self._inpbuf[rem:]
        self._packet = b''

        payload = packet[1:-packet[0]]

        if self._decompressor and (self._auth_complete or
                                   not self._decompress_after_auth):
            payload = self._decompressor.decompress(payload)

            if payload is None:
                raise CompressionError('Decompression failed')

        packet = SSHPacket(payload)
        pkttype = packet.get_byte()
        handler = self
        skip_reason = ''
        exc_reason = ''

        if self._kex and MSG_KEX_FIRST <= pkttype <= MSG_KEX_LAST:
            if self._ignore_first_kex: # pragma: no cover
                skip_reason = 'ignored first kex'
                self._ignore_first_kex = False
            else:
                handler = self._kex
        elif (self._auth and
              MSG_USERAUTH_FIRST <= pkttype <= MSG_USERAUTH_LAST):
            handler = self._auth
        elif pkttype > MSG_USERAUTH_LAST and not self._auth_complete:
            skip_reason = 'invalid request before auth complete'
            exc_reason = 'Invalid request before authentication was complete'
        elif MSG_CHANNEL_FIRST <= pkttype <= MSG_CHANNEL_LAST:
            try:
                recv_chan = packet.get_uint32()
                handler = self._channels[recv_chan]
            except KeyError:
                skip_reason = 'invalid channel number'
                exc_reason = 'Invalid channel number %d received' % recv_chan
            except PacketDecodeError:
                skip_reason = 'incomplete channel request'
                exc_reason = 'Incomplete channel request received'

        handler.log_received_packet(pkttype, seq, packet, skip_reason)

        if not skip_reason:
            try:
                processed = handler.process_packet(pkttype, seq, packet)
            except PacketDecodeError as exc:
                raise ProtocolError(str(exc)) from None

            if not processed:
                self.logger.debug1('Unknown packet type %d received', pkttype)
                self.send_packet(MSG_UNIMPLEMENTED, UInt32(seq))

        if exc_reason:
            raise ProtocolError(exc_reason)

        if self._transport:
            self._recv_seq = (seq + 1) & 0xffffffff
            self._recv_handler = self._recv_pkthdr

        return True

    def send_packet(self, pkttype, *args, handler=None):
        """Send an SSH packet"""

        if (self._auth_complete and self._kex_complete and
                (self._rekey_bytes_sent >= self._rekey_bytes or
                 (self._rekey_seconds and
                  time.monotonic() >= self._rekey_time))):
            self._send_kexinit()
            self._kexinit_sent = True

        if (((pkttype in {MSG_SERVICE_REQUEST, MSG_SERVICE_ACCEPT} or
              pkttype > MSG_KEX_LAST) and not self._kex_complete) or
                (pkttype == MSG_USERAUTH_BANNER and
                 not (self._auth_in_progress or self._auth_complete)) or
                (pkttype > MSG_USERAUTH_LAST and not self._auth_complete)):
            self._deferred_packets.append((pkttype, args))
            return

        # If we're encrypting and we have no data outstanding, insert an
        # ignore packet into the stream
        if self._send_encryption and pkttype not in (MSG_IGNORE, MSG_EXT_INFO):
            self.send_packet(MSG_IGNORE, String(b''))

        payload = Byte(pkttype) + b''.join(args)
        log_data = payload

        if self._compressor and (self._auth_complete or
                                 not self._compress_after_auth):
            payload = self._compressor.compress(payload)

            if payload is None: # pragma: no cover
                raise CompressionError('Compression failed')

        padlen = -(self._send_enchdrlen + len(payload)) % self._send_blocksize
        if padlen < 4:
            padlen += self._send_blocksize

        packet = Byte(padlen) + payload + os.urandom(padlen)
        pktlen = len(packet)
        hdr = UInt32(pktlen)
        seq = self._send_seq

        if self._send_encryption:
            packet, mac = self._send_encryption.encrypt_packet(seq, hdr, packet)
        else:
            packet = hdr + packet
            mac = b''

        self._send(packet + mac)
        self._send_seq = (seq + 1) & 0xffffffff

        if self._kex_complete:
            self._rekey_bytes_sent += pktlen

        if not handler:
            handler = self

        handler.log_sent_packet(pkttype, seq, log_data)

    def _send_deferred_packets(self):
        """Send packets deferred due to key exchange or auth"""

        deferred_packets = self._deferred_packets
        self._deferred_packets = []

        for pkttype, args in deferred_packets:
            self.send_packet(pkttype, *args)

    def _send_disconnect(self, code, reason, lang):
        """Send a disconnect packet"""

        self.logger.info('Sending disconnect: %s (%d)', reason, code)

        self.send_packet(MSG_DISCONNECT, UInt32(code),
                         String(reason), String(lang))

    def _send_kexinit(self):
        """Start a key exchange"""

        self._kex_complete = False
        self._rekey_bytes_sent = 0

        if self._rekey_seconds:
            self._rekey_time = time.monotonic() + self._rekey_seconds

        gss_mechs = self._gss.mechs if self._gss_kex else []
        kex_algs = expand_kex_algs(self._kex_algs, gss_mechs,
                                   bool(self._server_host_key_algs))

        kex_algs += self._get_ext_info_kex_alg()
        host_key_algs = self._server_host_key_algs or [b'null']

        self.logger.debug1('Requesting key exchange')
        self.logger.debug2('  Key exchange algs: %s', kex_algs)
        self.logger.debug2('  Host key algs: %s', host_key_algs)
        self.logger.debug2('  Encryption algs: %s', self._enc_algs)
        self.logger.debug2('  MAC algs: %s', self._mac_algs)
        self.logger.debug2('  Compression algs: %s', self._cmp_algs)

        cookie = os.urandom(16)
        kex_algs = NameList(kex_algs)
        host_key_algs = NameList(host_key_algs)
        enc_algs = NameList(self._enc_algs)
        mac_algs = NameList(self._mac_algs)
        cmp_algs = NameList(self._cmp_algs)
        langs = NameList([])

        packet = b''.join((Byte(MSG_KEXINIT), cookie, kex_algs, host_key_algs,
                           enc_algs, enc_algs, mac_algs, mac_algs, cmp_algs,
                           cmp_algs, langs, langs, Boolean(False), UInt32(0)))

        if self.is_server():
            self._server_kexinit = packet
        else:
            self._client_kexinit = packet

        self.send_packet(MSG_KEXINIT, packet[1:])

    def _send_ext_info(self):
        """Send extension information"""

        packet = UInt32(len(self._extensions_to_send))

        self.logger.debug2('Sending extension info')

        for name, value in self._extensions_to_send.items():
            packet += String(name) + String(value)

            self.logger.debug2('  %s: %s', name, value)

        self.send_packet(MSG_EXT_INFO, packet)

    def send_newkeys(self, k, h):
        """Finish a key exchange and send a new keys message"""

        if not self._session_id:
            first_kex = True
            self._session_id = h
        else:
            first_kex = False

        enc_keysize_cs, enc_ivsize_cs, enc_blocksize_cs, \
        mac_keysize_cs, mac_hashsize_cs, etm_cs = \
            get_encryption_params(self._enc_alg_cs, self._mac_alg_cs)

        enc_keysize_sc, enc_ivsize_sc, enc_blocksize_sc, \
        mac_keysize_sc, mac_hashsize_sc, etm_sc = \
            get_encryption_params(self._enc_alg_sc, self._mac_alg_sc)

        if mac_keysize_cs == 0:
            self._mac_alg_cs = self._enc_alg_cs

        if mac_keysize_sc == 0:
            self._mac_alg_sc = self._enc_alg_sc

        cmp_after_auth_cs = get_compression_params(self._cmp_alg_cs)
        cmp_after_auth_sc = get_compression_params(self._cmp_alg_sc)

        self.logger.debug2('  Client to server:')
        self.logger.debug2('    Encryption alg: %s', self._enc_alg_cs)
        self.logger.debug2('    MAC alg: %s', self._mac_alg_cs)
        self.logger.debug2('    Compression alg: %s', self._cmp_alg_cs)
        self.logger.debug2('  Server to client:')
        self.logger.debug2('    Encryption alg: %s', self._enc_alg_sc)
        self.logger.debug2('    MAC alg: %s', self._mac_alg_sc)
        self.logger.debug2('    Compression alg: %s', self._cmp_alg_sc)

        iv_cs = self._kex.compute_key(k, h, b'A', self._session_id,
                                      enc_ivsize_cs)
        iv_sc = self._kex.compute_key(k, h, b'B', self._session_id,
                                      enc_ivsize_sc)
        enc_key_cs = self._kex.compute_key(k, h, b'C', self._session_id,
                                           enc_keysize_cs)
        enc_key_sc = self._kex.compute_key(k, h, b'D', self._session_id,
                                           enc_keysize_sc)
        mac_key_cs = self._kex.compute_key(k, h, b'E', self._session_id,
                                           mac_keysize_cs)
        mac_key_sc = self._kex.compute_key(k, h, b'F', self._session_id,
                                           mac_keysize_sc)
        self._kex = None

        next_enc_cs = get_encryption(self._enc_alg_cs, enc_key_cs, iv_cs,
                                     self._mac_alg_cs, mac_key_cs, etm_cs)
        next_enc_sc = get_encryption(self._enc_alg_sc, enc_key_sc, iv_sc,
                                     self._mac_alg_sc, mac_key_sc, etm_sc)

        self.send_packet(MSG_NEWKEYS)

        self._extensions_to_send[b'global-requests-ok'] = ''

        if self.is_client():
            self._send_encryption = next_enc_cs
            self._send_enchdrlen = 1 if etm_cs else 5
            self._send_blocksize = max(8, enc_blocksize_cs)
            self._compressor = get_compressor(self._cmp_alg_cs)
            self._compress_after_auth = cmp_after_auth_cs

            self._next_recv_encryption = next_enc_sc
            self._next_recv_blocksize = max(8, enc_blocksize_sc)
            self._next_recv_macsize = mac_hashsize_sc
            self._next_decompressor = get_decompressor(self._cmp_alg_sc)
            self._next_decompress_after_auth = cmp_after_auth_sc

            self.set_extra_info(
                send_cipher=self._enc_alg_cs.decode('ascii'),
                send_mac=self._mac_alg_cs.decode('ascii'),
                send_compression=self._cmp_alg_cs.decode('ascii'),
                recv_cipher=self._enc_alg_sc.decode('ascii'),
                recv_mac=self._mac_alg_sc.decode('ascii'),
                recv_compression=self._cmp_alg_sc.decode('ascii'))

            if first_kex:
                if self._wait == 'kex' and not self._waiter.cancelled():
                    self._waiter.set_result(None)
                    self._wait = None
                else:
                    self.send_service_request(_USERAUTH_SERVICE)
        else:
            self._send_encryption = next_enc_sc
            self._send_enchdrlen = 1 if etm_sc else 5
            self._send_blocksize = max(8, enc_blocksize_sc)
            self._compressor = get_compressor(self._cmp_alg_sc)
            self._compress_after_auth = cmp_after_auth_sc

            self._next_recv_encryption = next_enc_cs
            self._next_recv_blocksize = max(8, enc_blocksize_cs)
            self._next_recv_macsize = mac_hashsize_cs
            self._next_decompressor = get_decompressor(self._cmp_alg_cs)
            self._next_decompress_after_auth = cmp_after_auth_cs

            self.set_extra_info(
                send_cipher=self._enc_alg_sc.decode('ascii'),
                send_mac=self._mac_alg_sc.decode('ascii'),
                send_compression=self._cmp_alg_sc.decode('ascii'),
                recv_cipher=self._enc_alg_cs.decode('ascii'),
                recv_mac=self._mac_alg_cs.decode('ascii'),
                recv_compression=self._cmp_alg_cs.decode('ascii'))

            if first_kex:
                self._next_service = _USERAUTH_SERVICE

                self._extensions_to_send[b'server-sig-algs'] = \
                    b','.join(self._sig_algs)

        if self._can_send_ext_info:
            self._send_ext_info()

        self._kex_complete = True
        self._send_deferred_packets()

    def send_service_request(self, service):
        """Send a service request"""

        self.logger.debug2('Requesting service %s', service)

        self._next_service = service
        self.send_packet(MSG_SERVICE_REQUEST, String(service))

    def _get_userauth_request_packet(self, method, args):
        """Get packet data for a user authentication request"""

        return b''.join((Byte(MSG_USERAUTH_REQUEST), String(self._username),
                         String(_CONNECTION_SERVICE), String(method)) + args)

    def get_userauth_request_data(self, method, *args):
        """Get signature data for a user authentication request"""

        return (String(self._session_id) +
                self._get_userauth_request_packet(method, args))

    def send_userauth_packet(self, pkttype, *args, handler=None,
                             trivial=True):
        """Send a user authentication packet"""

        self._auth_was_trivial &= trivial
        self.send_packet(pkttype, *args, handler=handler)

    async def send_userauth_request(self, method, *args, key=None,
                                    trivial=True):
        """Send a user authentication request"""

        packet = self._get_userauth_request_packet(method, args)

        if key:
            data = String(self._session_id) + packet

            if getattr(key, 'use_executor', False):
                sig = await self._loop.run_in_executor(None, key.sign, data)
            else:
                sig = key.sign(data)

                if inspect.isawaitable(sig):
                    sig = await sig

            packet += String(sig)

        self.send_userauth_packet(MSG_USERAUTH_REQUEST, packet[1:],
                                  trivial=trivial)

    def send_userauth_failure(self, partial_success):
        """Send a user authentication failure response"""

        methods = get_server_auth_methods(self)

        self.logger.debug2('Remaining auth methods: %s', methods or 'None')

        self._auth = None
        self.send_packet(MSG_USERAUTH_FAILURE, NameList(methods),
                         Boolean(partial_success))

    def send_userauth_success(self):
        """Send a user authentication success response"""

        self.logger.info('Auth for user %s succeeded', self._username)

        self.send_packet(MSG_USERAUTH_SUCCESS)
        self._auth = None
        self._auth_in_progress = False
        self._auth_complete = True
        self._next_service = None
        self.set_extra_info(username=self._username)
        self._send_deferred_packets()

        self._cancel_login_timer()
        self._set_keepalive_timer()
        self._owner.auth_completed()

        if self._acceptor:
            result = self._acceptor(self)

            if inspect.isawaitable(result):
                self.create_task(result)

            self._acceptor = None
            self._error_handler = None

        if self._wait == 'auth' and not self._waiter.cancelled():
            self._waiter.set_result(None)
            self._wait = None

    def send_channel_open_confirmation(self, send_chan, recv_chan,
                                       recv_window, recv_pktsize,
                                       *result_args):
        """Send a channel open confirmation"""

        self.send_packet(MSG_CHANNEL_OPEN_CONFIRMATION, UInt32(send_chan),
                         UInt32(recv_chan), UInt32(recv_window),
                         UInt32(recv_pktsize), *result_args)

    def send_channel_open_failure(self, send_chan, code, reason, lang):
        """Send a channel open failure"""

        self.send_packet(MSG_CHANNEL_OPEN_FAILURE, UInt32(send_chan),
                         UInt32(code), String(reason), String(lang))

    async def _make_global_request(self, request, *args):
        """Send a global request and wait for the response"""

        if not self._transport:
            return MSG_REQUEST_FAILURE, SSHPacket(b'')

        waiter = self._loop.create_future()
        self._global_request_waiters.append(waiter)

        self.send_packet(MSG_GLOBAL_REQUEST, String(request),
                         Boolean(True), *args)

        return await waiter

    def _report_global_response(self, result):
        """Report back the response to a previously issued global request"""

        _, _, want_reply = self._global_request_queue.pop(0)

        if want_reply: # pragma: no branch
            if result:
                response = b'' if result is True else result
                self.send_packet(MSG_REQUEST_SUCCESS, response)
            else:
                self.send_packet(MSG_REQUEST_FAILURE)

        if self._global_request_queue:
            self._service_next_global_request()

    def _service_next_global_request(self):
        """Process next item on global request queue"""

        handler, packet, _ = self._global_request_queue[0]
        if callable(handler):
            handler(packet)
        else:
            self._report_global_response(False)

    def _connection_made(self):
        """Handle the opening of a new connection"""

        raise NotImplementedError

    def _process_disconnect(self, _pkttype, _pktid, packet):
        """Process a disconnect message"""

        code = packet.get_uint32()
        reason = packet.get_string()
        lang = packet.get_string()
        packet.check_end()

        try:
            reason = reason.decode('utf-8')
            lang = lang.decode('ascii')
        except UnicodeDecodeError:
            raise ProtocolError('Invalid disconnect message') from None

        self.logger.debug1('Received disconnect: %s (%d)', reason, code)

        if code != DISC_BY_APPLICATION or self._wait:
            exc = construct_disc_error(code, reason, lang)
        else:
            exc = None

        self._force_close(exc)

    def _process_ignore(self, _pkttype, _pktid, packet):
        """Process an ignore message"""

        # pylint: disable=no-self-use

        _ = packet.get_string()     # data
        packet.check_end()

    def _process_unimplemented(self, _pkttype, _pktid, packet):
        """Process an unimplemented message response"""

        # pylint: disable=no-self-use

        _ = packet.get_uint32()     # seq
        packet.check_end()

    def _process_debug(self, _pkttype, _pktid, packet):
        """Process a debug message"""

        always_display = packet.get_boolean()
        msg = packet.get_string()
        lang = packet.get_string()
        packet.check_end()

        try:
            msg = msg.decode('utf-8')
            lang = lang.decode('ascii')
        except UnicodeDecodeError:
            raise ProtocolError('Invalid debug message') from None

        self.logger.debug1('Received debug message: %s%s', msg,
                           ' (always display)' if always_display else '')

        self._owner.debug_msg_received(msg, lang, always_display)

    def _process_service_request(self, _pkttype, _pktid, packet):
        """Process a service request"""

        service = packet.get_string()
        packet.check_end()

        if service == self._next_service:
            self.logger.debug2('Accepting request for service %s', service)

            self.send_packet(MSG_SERVICE_ACCEPT, String(service))

            if (self.is_server() and               # pragma: no branch
                    not self._auth_in_progress and
                    service == _USERAUTH_SERVICE):
                self._auth_in_progress = True
                self._send_deferred_packets()
        else:
            raise ServiceNotAvailable('Unexpected service request received')

    def _process_service_accept(self, _pkttype, _pktid, packet):
        """Process a service accept response"""

        service = packet.get_string()
        packet.check_end()

        if service == self._next_service:
            self.logger.debug2('Request for service %s accepted', service)

            self._next_service = None

            if (self.is_client() and               # pragma: no branch
                    service == _USERAUTH_SERVICE):
                self.logger.info('Beginning auth for user %s', self._username)

                self._auth_in_progress = True

                # This method is only in SSHClientConnection
                # pylint: disable=no-member
                self.try_next_auth()
        else:
            raise ServiceNotAvailable('Unexpected service accept received')

    def _process_ext_info(self, _pkttype, _pktid, packet):
        """Process extension information"""

        extensions = {}

        self.logger.debug2('Received extension info')

        num_extensions = packet.get_uint32()
        for _ in range(num_extensions):
            name = packet.get_string()
            value = packet.get_string()
            extensions[name] = value

            self.logger.debug2('  %s: %s', name, value)

        packet.check_end()

        if self.is_client():
            self._server_sig_algs = \
                extensions.get(b'server-sig-algs').split(b',')

    def _process_kexinit(self, _pkttype, _pktid, packet):
        """Process a key exchange request"""

        if self._kex:
            raise ProtocolError('Key exchange already in progress')

        _ = packet.get_bytes(16)                        # cookie
        peer_kex_algs = packet.get_namelist()
        peer_host_key_algs = packet.get_namelist()
        enc_algs_cs = packet.get_namelist()
        enc_algs_sc = packet.get_namelist()
        mac_algs_cs = packet.get_namelist()
        mac_algs_sc = packet.get_namelist()
        cmp_algs_cs = packet.get_namelist()
        cmp_algs_sc = packet.get_namelist()
        _ = packet.get_namelist()                       # lang_cs
        _ = packet.get_namelist()                       # lang_sc
        first_kex_follows = packet.get_boolean()
        _ = packet.get_uint32()                         # reserved
        packet.check_end()

        if self.is_server():
            self._client_kexinit = packet.get_consumed_payload()

            if b'ext-info-c' in peer_kex_algs and not self._session_id:
                self._can_send_ext_info = True
        else:
            self._server_kexinit = packet.get_consumed_payload()

            if b'ext-info-s' in peer_kex_algs and not self._session_id:
                self._can_send_ext_info = True

        if self._kexinit_sent:
            self._kexinit_sent = False
        else:
            self._send_kexinit()

        if self._gss:
            self._gss.reset()

        gss_mechs = self._gss.mechs if self._gss_kex else []
        kex_algs = expand_kex_algs(self._kex_algs, gss_mechs,
                                   bool(self._server_host_key_algs))

        self.logger.debug1('Received key exchange request')
        self.logger.debug2('  Key exchange algs: %s', peer_kex_algs)
        self.logger.debug2('  Host key algs: %s', peer_host_key_algs)
        self.logger.debug2('  Client to server:')
        self.logger.debug2('    Encryption algs: %s', enc_algs_cs)
        self.logger.debug2('    MAC algs: %s', mac_algs_cs)
        self.logger.debug2('    Compression algs: %s', cmp_algs_cs)
        self.logger.debug2('  Server to client:')
        self.logger.debug2('    Encryption algs: %s', enc_algs_sc)
        self.logger.debug2('    MAC algs: %s', mac_algs_sc)
        self.logger.debug2('    Compression algs: %s', cmp_algs_sc)

        kex_alg = self._choose_alg('key exchange', kex_algs, peer_kex_algs)
        self._kex = get_kex(self, kex_alg)
        self._ignore_first_kex = (first_kex_follows and
                                  self._kex.algorithm != peer_kex_algs[0])

        if self.is_server():
            # This method is only in SSHServerConnection
            # pylint: disable=no-member
            if (not self._choose_server_host_key(peer_host_key_algs) and
                    not kex_alg.startswith(b'gss-')):
                raise KeyExchangeFailed('Unable to find compatible '
                                        'server host key')

        self._enc_alg_cs = self._choose_alg('encryption', self._enc_algs,
                                            enc_algs_cs)
        self._enc_alg_sc = self._choose_alg('encryption', self._enc_algs,
                                            enc_algs_sc)

        self._mac_alg_cs = self._choose_alg('MAC', self._mac_algs, mac_algs_cs)
        self._mac_alg_sc = self._choose_alg('MAC', self._mac_algs, mac_algs_sc)

        self._cmp_alg_cs = self._choose_alg('compression', self._cmp_algs,
                                            cmp_algs_cs)
        self._cmp_alg_sc = self._choose_alg('compression', self._cmp_algs,
                                            cmp_algs_sc)

        self.logger.debug1('Beginning key exchange')
        self.logger.debug2('  Key exchange alg: %s', self._kex.algorithm)

        self._kex.start()

    def _process_newkeys(self, _pkttype, _pktid, packet):
        """Process a new keys message, finishing a key exchange"""

        packet.check_end()

        if self._next_recv_encryption:
            self._recv_encryption = self._next_recv_encryption
            self._recv_blocksize = self._next_recv_blocksize
            self._recv_macsize = self._next_recv_macsize
            self._decompressor = self._next_decompressor
            self._decompress_after_auth = self._next_decompress_after_auth

            self._next_recv_encryption = None
        else:
            raise ProtocolError('New keys not negotiated')

        self.logger.debug1('Completed key exchange')

    def _process_userauth_request(self, _pkttype, _pktid, packet):
        """Process a user authentication request"""

        username = packet.get_string()
        service = packet.get_string()
        method = packet.get_string()

        if len(username) >= _MAX_USERNAME_LEN:
            raise IllegalUserName('Username too long')

        if service != _CONNECTION_SERVICE:
            raise ServiceNotAvailable('Unexpected service in auth request')

        try:
            username = saslprep(username.decode('utf-8'))
        except (UnicodeDecodeError, SASLPrepError) as exc:
            raise IllegalUserName(str(exc)) from None

        if self.is_client():
            raise ProtocolError('Unexpected userauth request')
        elif self._auth_complete:
            # Silently ignore requests if we're already authenticated
            pass
        else:
            if username != self._username:
                self.logger.info('Beginning auth for user %s', username)

                self._username = username
                begin_auth = True
            else:
                begin_auth = False

            self.create_task(self._finish_userauth(begin_auth, method, packet))

    async def _finish_userauth(self, begin_auth, method, packet):
        """Finish processing a user authentication request"""

        if not self._owner: # pragma: no cover
            return

        if begin_auth:
            # This method is only in SSHServerConnection
            # pylint: disable=no-member
            await self._reload_config()

            result = self._owner.begin_auth(self._username)

            if inspect.isawaitable(result):
                result = await result

            if not result:
                self.send_userauth_success()
                return

        if not self._owner: # pragma: no cover
            return

        if self._auth:
            self._auth.cancel()

        self._auth = lookup_server_auth(self, self._username, method, packet)

    def _process_userauth_failure(self, _pkttype, pktid, packet):
        """Process a user authentication failure response"""

        auth_methods = packet.get_namelist()
        partial_success = packet.get_boolean()
        packet.check_end()

        self.logger.debug2('Remaining auth methods: %s',
                           auth_methods or 'None')

        if self._preferred_auth:
            self.logger.debug2('Preferred auth methods: %s',
                               self._preferred_auth or 'None')

            auth_methods = [method for method in self._preferred_auth
                            if method in auth_methods]

        self._auth_methods = auth_methods

        if self.is_client() and self._auth:
            if partial_success: # pragma: no cover
                # Partial success not implemented yet
                self._auth.auth_succeeded()
            else:
                self._auth.auth_failed()

            # This method is only in SSHClientConnection
            # pylint: disable=no-member
            self.try_next_auth()
        else:
            self.logger.debug2('Unexpected userauth failure response')
            self.send_packet(MSG_UNIMPLEMENTED, UInt32(pktid))

    def _process_userauth_success(self, _pkttype, pktid, packet):
        """Process a user authentication success response"""

        packet.check_end()

        if self.is_client() and self._auth:
            if self._auth_was_trivial and self._disable_trivial_auth:
                raise PermissionDenied('Trivial auth disabled')

            self.logger.info('Auth for user %s succeeded', self._username)

            self._auth.auth_succeeded()
            self._auth.cancel()
            self._auth = None
            self._auth_in_progress = False
            self._auth_complete = True

            if self._agent:
                self._agent.close()

            self.set_extra_info(username=self._username)
            self._cancel_login_timer()
            self._send_deferred_packets()
            self._set_keepalive_timer()
            self._owner.auth_completed()

            if self._acceptor:
                result = self._acceptor(self)

                if inspect.isawaitable(result):
                    self.create_task(result)

                self._acceptor = None
                self._error_handler = None

            if self._wait == 'auth' and not self._waiter.cancelled():
                self._waiter.set_result(None)
                self._wait = None
        else:
            self.logger.debug2('Unexpected userauth success response')
            self.send_packet(MSG_UNIMPLEMENTED, UInt32(pktid))

    def _process_userauth_banner(self, _pkttype, _pktid, packet):
        """Process a user authentication banner message"""

        msg = packet.get_string()
        lang = packet.get_string()
        packet.check_end()

        try:
            msg = msg.decode('utf-8')
            lang = lang.decode('ascii')
        except UnicodeDecodeError:
            raise ProtocolError('Invalid userauth banner') from None

        self.logger.debug1('Received authentication banner')

        if self.is_client():
            self._owner.auth_banner_received(msg, lang)
        else:
            raise ProtocolError('Unexpected userauth banner')

    def _process_global_request(self, _pkttype, _pktid, packet):
        """Process a global request"""

        request = packet.get_string()
        want_reply = packet.get_boolean()

        try:
            request = request.decode('ascii')
        except UnicodeDecodeError:
            raise ProtocolError('Invalid global request') from None

        name = '_process_' + map_handler_name(request) + '_global_request'
        handler = getattr(self, name, None)

        if not handler:
            self.logger.debug1('Received unknown global request: %s', request)

        self._global_request_queue.append((handler, packet, want_reply))
        if len(self._global_request_queue) == 1:
            self._service_next_global_request()

    def _process_global_response(self, pkttype, _pktid, packet):
        """Process a global response"""

        if self._global_request_waiters:
            waiter = self._global_request_waiters.pop(0)
            if not waiter.cancelled(): # pragma: no branch
                waiter.set_result((pkttype, packet))
        else:
            raise ProtocolError('Unexpected global response')

    def _process_channel_open(self, _pkttype, _pktid, packet):
        """Process a channel open request"""

        chantype = packet.get_string()
        send_chan = packet.get_uint32()
        send_window = packet.get_uint32()
        send_pktsize = packet.get_uint32()

        try:
            chantype = chantype.decode('ascii')
        except UnicodeDecodeError:
            raise ProtocolError('Invalid channel open request') from None

        try:
            name = '_process_' + map_handler_name(chantype) + '_open'
            handler = getattr(self, name, None)
            if callable(handler):
                chan, session = handler(packet)
                chan.process_open(send_chan, send_window,
                                  send_pktsize, session)
            else:
                raise ChannelOpenError(OPEN_UNKNOWN_CHANNEL_TYPE,
                                       'Unknown channel type')
        except ChannelOpenError as exc:
            self.logger.debug1('Open failed for channel type %s: %s',
                               chantype, exc.reason)

            self.send_channel_open_failure(send_chan, exc.code,
                                           exc.reason, exc.lang)

    def _process_channel_open_confirmation(self, _pkttype, _pktid, packet):
        """Process a channel open confirmation response"""

        recv_chan = packet.get_uint32()
        send_chan = packet.get_uint32()
        send_window = packet.get_uint32()
        send_pktsize = packet.get_uint32()

        chan = self._channels.get(recv_chan)
        if chan:
            chan.process_open_confirmation(send_chan, send_window,
                                           send_pktsize, packet)
        else:
            self.logger.debug1('Received open confirmation for unknown '
                               'channel %d', recv_chan)

            raise ProtocolError('Invalid channel number')

    def _process_channel_open_failure(self, _pkttype, _pktid, packet):
        """Process a channel open failure response"""

        recv_chan = packet.get_uint32()
        code = packet.get_uint32()
        reason = packet.get_string()
        lang = packet.get_string()
        packet.check_end()

        try:
            reason = reason.decode('utf-8')
            lang = lang.decode('ascii')
        except UnicodeDecodeError:
            raise ProtocolError('Invalid channel open failure') from None

        chan = self._channels.get(recv_chan)
        if chan:
            chan.process_open_failure(code, reason, lang)
        else:
            self.logger.debug1('Received open failure for unknown '
                               'channel %d', recv_chan)

            raise ProtocolError('Invalid channel number')

    def _process_keepalive_at_openssh_dot_com_global_request(self, packet):
        """Process an incoming OpenSSH keepalive request"""

        packet.check_end()

        self.logger.debug2('Received OpenSSH keepalive request')
        self._report_global_response(True)

    _packet_handlers = {
        MSG_DISCONNECT:                 _process_disconnect,
        MSG_IGNORE:                     _process_ignore,
        MSG_UNIMPLEMENTED:              _process_unimplemented,
        MSG_DEBUG:                      _process_debug,
        MSG_SERVICE_REQUEST:            _process_service_request,
        MSG_SERVICE_ACCEPT:             _process_service_accept,
        MSG_EXT_INFO:                   _process_ext_info,

        MSG_KEXINIT:                    _process_kexinit,
        MSG_NEWKEYS:                    _process_newkeys,

        MSG_USERAUTH_REQUEST:           _process_userauth_request,
        MSG_USERAUTH_FAILURE:           _process_userauth_failure,
        MSG_USERAUTH_SUCCESS:           _process_userauth_success,
        MSG_USERAUTH_BANNER:            _process_userauth_banner,

        MSG_GLOBAL_REQUEST:             _process_global_request,
        MSG_REQUEST_SUCCESS:            _process_global_response,
        MSG_REQUEST_FAILURE:            _process_global_response,

        MSG_CHANNEL_OPEN:               _process_channel_open,
        MSG_CHANNEL_OPEN_CONFIRMATION:  _process_channel_open_confirmation,
        MSG_CHANNEL_OPEN_FAILURE:       _process_channel_open_failure
    }

    def abort(self):
        """Forcibly close the SSH connection

           This method closes the SSH connection immediately, without
           waiting for pending operations to complete and wihtout sending
           an explicit SSH disconnect message. Buffered data waiting to be
           sent will be lost and no more data will be received. When the
           the connection is closed, :meth:`connection_lost()
           <SSHClient.connection_lost>` on the associated :class:`SSHClient`
           object will be called with the value `None`.

        """

        self.logger.info('Aborting connection')

        self._force_close(None)

    def close(self):
        """Cleanly close the SSH connection

           This method calls :meth:`disconnect` with the reason set to
           indicate that the connection was closed explicitly by the
           application.

        """

        self.logger.info('Closing connection')

        self.disconnect(DISC_BY_APPLICATION, 'Disconnected by application')

    async def wait_established(self):
        """Wait for connection to be established"""

        await self._waiter

    async def wait_closed(self):
        """Wait for this connection to close

           This method is a coroutine which can be called to block until
           this connection has finished closing.

        """

        if self._agent:
            await self._agent.wait_closed()

        await self._close_event.wait()

    def disconnect(self, code, reason, lang=DEFAULT_LANG):
        """Disconnect the SSH connection

           This method sends a disconnect message and closes the SSH
           connection after buffered data waiting to be written has been
           sent. No more data will be received. When the connection is
           fully closed, :meth:`connection_lost() <SSHClient.connection_lost>`
           on the associated :class:`SSHClient` or :class:`SSHServer` object
           will be called with the value `None`.

           :param code:
               The reason for the disconnect, from
               :ref:`disconnect reason codes <DisconnectReasons>`
           :param reason:
               A human readable reason for the disconnect
           :param lang:
               The language the reason is in
           :type code: `int`
           :type reason: `str`
           :type lang: `str`

        """

        for chan in list(self._channels.values()):
            chan.close()

        self._send_disconnect(code, reason, lang)
        self._force_close(None)

    def get_extra_info(self, name, default=None):
        """Get additional information about the connection

           This method returns extra information about the connection once
           it is established. Supported values include everything supported
           by a socket transport plus:

             | username
             | client_version
             | server_version
             | send_cipher
             | send_mac
             | send_compression
             | recv_cipher
             | recv_mac
             | recv_compression

           See :meth:`get_extra_info() <asyncio.BaseTransport.get_extra_info>`
           in :class:`asyncio.BaseTransport` for more information.

           Additional information stored on the connection by calling
           :meth:`set_extra_info` can also be returned here.

        """

        return self._extra.get(name,
                               self._transport.get_extra_info(name, default)
                               if self._transport else default)

    def set_extra_info(self, **kwargs):
        """Store additional information associated with the connection

           This method allows extra information to be associated with the
           connection. The information to store should be passed in as
           keyword parameters and can later be returned by calling
           :meth:`get_extra_info` with one of the keywords as the name
           to retrieve.

        """

        self._extra.update(**kwargs)

    def set_keepalive(self, interval=None, count_max=None):
        """Set keep-alive timer on this connection

           This method sets the parameters of the keepalive timer on the
           connection. If *interval* is set to a non-zero value,
           keep-alive requests will be sent whenever the connection is
           idle, and if a response is not received after *count_max*
           attempts, the connection is closed.

           :param interval: (optional)
               The time in seconds to wait before sending a keep-alive message
               if no data has been received. This defaults to 0, which
               disables sending these messages.
           :param count_max: (optional)
               The maximum number of keepalive messages which will be sent
               without getting a response before closing the connection.
               This defaults to 3, but only applies when *interval* is
               non-zero.
           :type interval: `int`, `float`, or `str`
           :type count_max: `int`

        """

        if interval is not None:
            if isinstance(interval, str):
                interval = parse_time_interval(interval)

            if interval < 0:
                raise ValueError('Keepalive interval cannot be negative')

            self._keepalive_interval = interval

        if count_max is not None:
            if count_max < 0:
                raise ValueError('Keepalive count max cannot be negative')

            self._keepalive_count_max = count_max

        self._reset_keepalive_timer()

    def send_debug(self, msg, lang=DEFAULT_LANG, always_display=False):
        """Send a debug message on this connection

           This method can be called to send a debug message to the
           other end of the connection.

           :param msg:
               The debug message to send
           :param lang:
               The language the message is in
           :param always_display:
               Whether or not to display the message
           :type msg: `str`
           :type lang: `str`
           :type always_display: `bool`

        """

        self.logger.debug1('Sending debug message: %s%s', msg,
                           ' (always display)' if always_display else '')

        self.send_packet(MSG_DEBUG, Boolean(always_display),
                         String(msg), String(lang))

    def create_tcp_channel(self, encoding=None, errors='strict',
                           window=_DEFAULT_WINDOW,
                           max_pktsize=_DEFAULT_MAX_PKTSIZE):
        """Create an SSH TCP channel for a new direct TCP connection

           This method can be called by :meth:`connection_requested()
           <SSHServer.connection_requested>` to create an
           :class:`SSHTCPChannel` with the desired encoding, Unicode
           error handling strategy, window, and max packet size for
           a newly created SSH direct connection.

           :param encoding: (optional)
               The Unicode encoding to use for data exchanged on the
               connection. This defaults to `None`, allowing the
               application to send and receive raw bytes.
           :param errors: (optional)
               The error handling strategy to apply on encode/decode errors
           :param window: (optional)
               The receive window size for this session
           :param max_pktsize: (optional)
               The maximum packet size for this session
           :type encoding: `str`
           :type errors: `str`
           :type window: `int`
           :type max_pktsize: `int`

           :returns: :class:`SSHTCPChannel`

        """

        return SSHTCPChannel(self, self._loop, encoding,
                             errors, window, max_pktsize)

    def create_unix_channel(self, encoding=None, errors='strict',
                            window=_DEFAULT_WINDOW,
                            max_pktsize=_DEFAULT_MAX_PKTSIZE):
        """Create an SSH UNIX channel for a new direct UNIX domain connection

           This method can be called by :meth:`unix_connection_requested()
           <SSHServer.unix_connection_requested>` to create an
           :class:`SSHUNIXChannel` with the desired encoding, Unicode
           error handling strategy, window, and max packet size for
           a newly created SSH direct UNIX domain socket connection.

           :param encoding: (optional)
               The Unicode encoding to use for data exchanged on the
               connection. This defaults to `None`, allowing the
               application to send and receive raw bytes.
           :param errors: (optional)
               The error handling strategy to apply on encode/decode errors
           :param window: (optional)
               The receive window size for this session
           :param max_pktsize: (optional)
               The maximum packet size for this session
           :type encoding: `str`
           :type errors: `str`
           :type window: `int`
           :type max_pktsize: `int`

           :returns: :class:`SSHUNIXChannel`

        """

        return SSHUNIXChannel(self, self._loop, encoding,
                              errors, window, max_pktsize)

    def create_x11_channel(self, window=_DEFAULT_WINDOW,
                           max_pktsize=_DEFAULT_MAX_PKTSIZE):
        """Create an SSH X11 channel to use in X11 forwarding"""

        return SSHX11Channel(self, self._loop, None, 'strict',
                             window, max_pktsize)

    def create_agent_channel(self, window=_DEFAULT_WINDOW,
                             max_pktsize=_DEFAULT_MAX_PKTSIZE):
        """Create an SSH agent channel to use in agent forwarding"""

        return SSHAgentChannel(self, self._loop, None, 'strict',
                               window, max_pktsize)

    async def create_connection(self, session_factory, remote_host, remote_port,
                                orig_host='', orig_port=0, *, encoding=None,
                                errors='strict', window=_DEFAULT_WINDOW,
                                max_pktsize=_DEFAULT_MAX_PKTSIZE):
        """Create an SSH direct or forwarded TCP connection"""

        raise NotImplementedError

    async def create_unix_connection(self, session_factory, remote_path, *,
                                     encoding=None, errors='strict',
                                     window=_DEFAULT_WINDOW,
                                     max_pktsize=_DEFAULT_MAX_PKTSIZE):
        """Create an SSH direct or forwarded UNIX domain socket connection"""

        raise NotImplementedError

    async def forward_connection(self, dest_host, dest_port):
        """Forward a tunneled TCP connection

           This method is a coroutine which can be returned by a
           `session_factory` to forward connections tunneled over
           SSH to the specified destination host and port.

           :param dest_host:
               The hostname or address to forward the connections to
           :param dest_port:
               The port number to forward the connections to
           :type dest_host: `str`
           :type dest_port: `int`

           :returns: :class:`SSHTCPSession`

        """

        try:
            if dest_host == '':
                dest_host = None

            _, peer = await self._loop.create_connection(SSHForwarder,
                                                         dest_host, dest_port)

            self.logger.info('  Forwarding TCP connection to %s',
                             (dest_host, dest_port))
        except OSError as exc:
            raise ChannelOpenError(OPEN_CONNECT_FAILED, str(exc)) from None

        return SSHForwarder(peer)

    async def forward_unix_connection(self, dest_path):
        """Forward a tunneled UNIX domain socket connection

           This method is a coroutine which can be returned by a
           `session_factory` to forward connections tunneled over
           SSH to the specified destination path.

           :param dest_path:
               The path to forward the connection to
           :type dest_path: `str`

           :returns: :class:`SSHUNIXSession`

        """

        try:
            _, peer = \
                await self._loop.create_unix_connection(SSHForwarder, dest_path)

            self.logger.info('  Forwarding UNIX connection to %s', dest_path)
        except OSError as exc:
            raise ChannelOpenError(OPEN_CONNECT_FAILED, str(exc)) from None

        return SSHForwarder(peer)

    @async_context_manager
    async def forward_local_port(self, listen_host, listen_port,
                                 dest_host, dest_port):
        """Set up local port forwarding

           This method is a coroutine which attempts to set up port
           forwarding from a local listening port to a remote host and port
           via the SSH connection. If the request is successful, the
           return value is an :class:`SSHListener` object which can be used
           later to shut down the port forwarding.

           :param listen_host:
               The hostname or address on the local host to listen on
           :param listen_port:
               The port number on the local host to listen on
           :param dest_host:
               The hostname or address to forward the connections to
           :param dest_port:
               The port number to forward the connections to
           :type listen_host: `str`
           :type listen_port: `int`
           :type dest_host: `str`
           :type dest_port: `int`

           :returns: :class:`SSHListener`

           :raises: :exc:`OSError` if the listener can't be opened

        """

        async def tunnel_connection(session_factory, orig_host, orig_port):
            """Forward a local connection over SSH"""

            return (await self.create_connection(session_factory,
                                                 dest_host, dest_port,
                                                 orig_host, orig_port))

        if (listen_host, listen_port) == (dest_host, dest_port):
            self.logger.info('Creating local TCP forwarder on %s',
                             (listen_host, listen_port))
        else:
            self.logger.info('Creating local TCP forwarder from %s to %s',
                             (listen_host, listen_port), (dest_host, dest_port))

        try:
            listener = await create_tcp_forward_listener(self, self._loop,
                                                         tunnel_connection,
                                                         listen_host,
                                                         listen_port)
        except OSError as exc:
            self.logger.debug1('Failed to create local TCP listener: %s', exc)
            raise

        if listen_port == 0:
            listen_port = listener.get_port()

        self._local_listeners[listen_host, listen_port] = listener

        return listener

    @async_context_manager
    async def forward_local_path(self, listen_path, dest_path):
        """Set up local UNIX domain socket forwarding

           This method is a coroutine which attempts to set up UNIX domain
           socket forwarding from a local listening path to a remote path
           via the SSH connection. If the request is successful, the
           return value is an :class:`SSHListener` object which can be used
           later to shut down the UNIX domain socket forwarding.

           :param listen_path:
               The path on the local host to listen on
           :param dest_path:
               The path on the remote host to forward the connections to
           :type listen_path: `str`
           :type dest_path: `str`

           :returns: :class:`SSHListener`

           :raises: :exc:`OSError` if the listener can't be opened

        """

        async def tunnel_connection(session_factory):
            """Forward a local connection over SSH"""

            return await self.create_unix_connection(session_factory, dest_path)

        self.logger.info('Creating local UNIX forwarder from %s to %s',
                         listen_path, dest_path)

        try:
            listener = await create_unix_forward_listener(self, self._loop,
                                                          tunnel_connection,
                                                          listen_path)
        except OSError as exc:
            self.logger.debug1('Failed to create local UNIX listener: %s', exc)
            raise

        self._local_listeners[listen_path] = listener

        return listener

    def close_forward_listener(self, listen_key):
        """Mark a local forwarding listener as closed"""

        self._local_listeners.pop(listen_key, None)


class SSHClientConnection(SSHConnection):
    """SSH client connection

       This class represents an SSH client connection.

       Once authentication is successful on a connection, new client
       sessions can be opened by calling :meth:`create_session`.

       Direct TCP connections can be opened by calling
       :meth:`create_connection`.

       Remote listeners for forwarded TCP connections can be opened by
       calling :meth:`create_server`.

       Direct UNIX domain socket connections can be opened by calling
       :meth:`create_unix_connection`.

       Remote listeners for forwarded UNIX domain socket connections
       can be opened by calling :meth:`create_unix_server`.

       TCP port forwarding can be set up by calling :meth:`forward_local_port`
       or :meth:`forward_remote_port`.

       UNIX domain socket forwarding can be set up by calling
       :meth:`forward_local_path` or :meth:`forward_remote_path`.

    """

    def __init__(self, loop, options, acceptor=None,
                 error_handler=None, wait=None):
        super().__init__(loop, options, acceptor, error_handler,
                         wait, server=False)

        self._host = options.host
        self._port = options.port

        self._known_hosts = options.known_hosts
        self._host_key_alias = options.host_key_alias

        self._server_host_key_algs = options.server_host_key_algs
        self._server_host_key = None

        self._username = options.username
        self._password = options.password

        self._client_host_keysign = options.client_host_keysign
        self._client_host_keys = None if options.client_host_keys is None else \
                                 list(options.client_host_keys)
        self._client_host = options.client_host
        self._client_username = options.client_username
        self._client_keys = None if options.client_keys is None else \
                            list(options.client_keys)

        if options.preferred_auth != ():
            self._preferred_auth = [method.encode('ascii') for method in
                                    options.preferred_auth]
        else:
            self._preferred_auth = get_client_auth_methods()

        self._disable_trivial_auth = options.disable_trivial_auth

        if options.agent_path is not None:
            self._agent = SSHAgentClient(options.agent_path)

        self._agent_identities = options.agent_identities
        self._agent_forward_path = options.agent_forward_path
        self._get_agent_keys = bool(self._agent)

        self._pkcs11_provider = options.pkcs11_provider
        self._pkcs11_pin = options.pkcs11_pin
        self._get_pkcs11_keys = bool(self._pkcs11_provider)

        gss_host = options.gss_host if options.gss_host != () else options.host

        if gss_host:
            try:
                self._gss = GSSClient(gss_host, options.gss_delegate_creds)
                self._gss_kex = options.gss_kex
                self._gss_auth = options.gss_auth
                self._gss_mic_auth = self._gss_auth
            except GSSError:
                pass

        self._kbdint_password_auth = False

        self._remote_listeners = {}
        self._dynamic_remote_listeners = {}

    def _connection_made(self):
        """Handle the opening of a new connection"""

        if not self._host:
            if self._peer_addr:
                self._host = self._peer_addr
                self._port = self._peer_port
            else:
                remote_peer = self.get_extra_info('remote_peername')
                self._host, self._port = remote_peer

        if self._client_host_keysign:
            sock = self._transport.get_extra_info('socket')
            self._client_host_keys = get_keysign_keys(self._client_host_keysign,
                                                      sock.fileno(),
                                                      self._client_host_keys)

        if self._known_hosts is None:
            self._trusted_host_keys = None
            self._trusted_ca_keys = None
        else:
            if not self._known_hosts:
                default_known_hosts = Path('~', '.ssh',
                                           'known_hosts').expanduser()

                if (default_known_hosts.is_file() and
                        os.access(default_known_hosts, os.R_OK)):
                    self._known_hosts = str(default_known_hosts)
                else:
                    self._known_hosts = b''

            port = self._port if self._port != DEFAULT_PORT else None

            self._match_known_hosts(self._known_hosts,
                                    self._host_key_alias or self._host,
                                    self._peer_addr, port)

        default_host_key_algs = []

        if self._server_host_key_algs != 'default':
            if self._trusted_host_key_algs:
                default_host_key_algs = self._trusted_host_key_algs

            if self._trusted_ca_keys:
                default_host_key_algs = \
                    get_default_certificate_algs() + default_host_key_algs

        if not default_host_key_algs:
            default_host_key_algs = \
                get_default_certificate_algs() + get_default_public_key_algs()

        if self._x509_trusted_certs is not None:
            if self._x509_trusted_certs or self._x509_trusted_cert_paths:
                default_host_key_algs = \
                    get_default_x509_certificate_algs() + default_host_key_algs

        self._server_host_key_algs = \
            _select_host_key_algs(
                self._server_host_key_algs,
                self._options.config.get('HostKeyAlgorithms', ()),
                default_host_key_algs)

        self.logger.info('Connected to SSH server at %s',
                         (self._host, self._port))

        if self._options.proxy_command:
            proxy_command = ' '.join(shlex.quote(arg) for arg in
                                     self._options.proxy_command)
            self.logger.info('  Proxy command: %s', proxy_command)
        else:
            self.logger.info('  Local address: %s',
                             (self._local_addr, self._local_port))
            self.logger.info('  Peer address: %s',
                             (self._peer_addr, self._peer_port))


    def _cleanup(self, exc):
        """Clean up this client connection"""

        if self._agent:
            self._agent.close()

        if self._remote_listeners:
            for listener in list(self._remote_listeners.values()):
                listener.close()

            self._remote_listeners = {}
            self._dynamic_remote_listeners = {}

        if exc is None:
            self.logger.info('Connection closed')
        elif isinstance(exc, ConnectionLost):
            self.logger.info(str(exc))
        else:
            self.logger.info('Connection failure: ' + str(exc))

        super()._cleanup(exc)


    def _choose_signature_alg(self, keypair):
        """Choose signature algorithm to use for key-based authentication"""

        if self._server_sig_algs:
            for alg in keypair.sig_algorithms:
                if alg in self._sig_algs and alg in self._server_sig_algs:
                    keypair.set_sig_algorithm(alg)
                    return True

        return keypair.sig_algorithms[-1] in self._sig_algs

    def validate_server_host_key(self, key_data):
        """Validate and return the server's host key"""

        try:
            host_key = self._validate_host_key(
                self._host_key_alias or self._host,
                self._peer_addr, self._port, key_data)
        except ValueError as exc:
            raise HostKeyNotVerifiable(str(exc)) from None

        self._server_host_key = host_key
        return host_key

    def get_server_host_key(self):
        """Return the server host key used in the key exchange

           This method returns the server host key used to complete the
           key exchange with the server.

           If GSS key exchange is used, `None` is returned.

           :returns: An :class:`SSHKey` public key or `None`

        """

        return self._server_host_key

    def try_next_auth(self):
        """Attempt client authentication using the next compatible method"""

        if self._auth:
            self._auth.cancel()
            self._auth = None

        while self._auth_methods:
            method = self._auth_methods.pop(0)

            self._auth = lookup_client_auth(self, method)

            if self._auth:
                return

        self.logger.info('Auth failed for user %s', self._username)

        self._force_close(PermissionDenied('Permission denied'))

    def gss_kex_auth_requested(self):
        """Return whether to allow GSS key exchange authentication or not"""

        if self._gss_kex_auth:
            self._gss_kex_auth = False
            return True
        else:
            return False

    def gss_mic_auth_requested(self):
        """Return whether to allow GSS MIC authentication or not"""

        if self._gss_mic_auth:
            self._gss_mic_auth = False
            return True
        else:
            return False

    async def host_based_auth_requested(self):
        """Return a host key pair, host, and user to authenticate with"""

        if not self._host_based_auth:
            return None, None, None

        while True:
            try:
                keypair = self._client_host_keys.pop(0)
            except IndexError:
                keypair = None
                break

            if self._choose_signature_alg(keypair):
                break

        if self._client_host is None:
            self._client_host, _ = await self._loop.getnameinfo(
                self.get_extra_info('sockname'), socket.NI_NUMERICSERV)

        # Add a trailing '.' to the client host to be compatible with
        # ssh-keysign from OpenSSH
        if self._client_host_keysign and self._client_host[-1:] != '.':
            self._client_host += '.'

        return keypair, self._client_host, self._client_username

    async def public_key_auth_requested(self):
        """Return a client key pair to authenticate with"""

        if not self._public_key_auth:
            return None

        if self._get_agent_keys:
            try:
                agent_keys = await self._agent.get_keys(self._agent_identities)
                self._client_keys = agent_keys + (self._client_keys or [])
            except ValueError:
                pass

            self._get_agent_keys = False

        if self._get_pkcs11_keys:
            pkcs11_keys = await self._loop.run_in_executor(
                None, load_pkcs11_keys, self._pkcs11_provider, self._pkcs11_pin)

            self._client_keys = pkcs11_keys + (self._client_keys or [])
            self._get_pkcs11_keys = False

        while True:
            if not self._client_keys:
                result = self._owner.public_key_auth_requested()

                if inspect.isawaitable(result):
                    result = await result

                if not result:
                    return None

                self._client_keys = load_keypairs(result)

            keypair = self._client_keys.pop(0)

            if self._choose_signature_alg(keypair):
                return keypair

    async def password_auth_requested(self):
        """Return a password to authenticate with"""

        if not self._password_auth and not self._kbdint_password_auth:
            return None

        if self._password is not None:
            result = self._password
            self._password = None
        else:
            result = self._owner.password_auth_requested()

            if inspect.isawaitable(result):
                result = await result

        return result

    async def password_change_requested(self, prompt, lang):
        """Return a password to authenticate with and what to change it to"""

        result = self._owner.password_change_requested(prompt, lang)

        if inspect.isawaitable(result):
            result = await result

        return result

    def password_changed(self):
        """Report a successful password change"""

        self._owner.password_changed()

    def password_change_failed(self):
        """Report a failed password change"""

        self._owner.password_change_failed()

    async def kbdint_auth_requested(self):
        """Return the list of supported keyboard-interactive auth methods

           If keyboard-interactive auth is not supported in the client but
           a password was provided when the connection was opened, this
           will allow sending the password via keyboard-interactive auth.

        """

        if not self._kbdint_auth:
            return None

        result = self._owner.kbdint_auth_requested()

        if inspect.isawaitable(result):
            result = await result

        if result is NotImplemented:
            if self._password is not None and not self._kbdint_password_auth:
                self._kbdint_password_auth = True
                result = ''
            else:
                result = None

        return result

    async def kbdint_challenge_received(self, name, instructions,
                                        lang, prompts):
        """Return responses to a keyboard-interactive auth challenge"""

        if self._kbdint_password_auth:
            if not prompts:
                # Silently drop any empty challenges used to print messages
                result = []
            elif len(prompts) == 1:
                prompt = prompts[0][0].lower()

                if 'password' in prompt or 'passcode' in prompt:
                    password = await self.password_auth_requested()

                    result = [password] if password is not None else None
                else:
                    result = None
            else:
                result = None
        else:
            result = self._owner.kbdint_challenge_received(name, instructions,
                                                           lang, prompts)

            if inspect.isawaitable(result):
                result = await result

        return result

    def _process_session_open(self, _packet):
        """Process an inbound session open request

           These requests are disallowed on an SSH client.

        """

        # pylint: disable=no-self-use

        raise ChannelOpenError(OPEN_ADMINISTRATIVELY_PROHIBITED,
                               'Session open forbidden on client')

    def _process_direct_tcpip_open(self, _packet):
        """Process an inbound direct TCP/IP channel open request

           These requests are disallowed on an SSH client.

        """

        # pylint: disable=no-self-use

        raise ChannelOpenError(OPEN_ADMINISTRATIVELY_PROHIBITED,
                               'Direct TCP/IP open forbidden on client')

    def _process_forwarded_tcpip_open(self, packet):
        """Process an inbound forwarded TCP/IP channel open request"""

        dest_host = packet.get_string()
        dest_port = packet.get_uint32()
        orig_host = packet.get_string()
        orig_port = packet.get_uint32()
        packet.check_end()

        try:
            dest_host = dest_host.decode('utf-8')
            orig_host = orig_host.decode('utf-8')
        except UnicodeDecodeError:
            raise ProtocolError('Invalid forwarded TCP/IP channel '
                                'open request') from None

        # Some buggy servers send back a port of `0` instead of the actual
        # listening port when reporting connections which arrive on a listener
        # set up on a dynamic port. This lookup attempts to work around that.
        listener = (self._remote_listeners.get((dest_host, dest_port)) or
                    self._dynamic_remote_listeners.get(dest_host))

        if listener:
            chan, session = listener.process_connection(orig_host, orig_port)

            self.logger.info('Accepted forwarded TCP connection on %s',
                             (dest_host, dest_port))
            self.logger.info('  Client address: %s', (orig_host, orig_port))

            return chan, session
        else:
            raise ChannelOpenError(OPEN_CONNECT_FAILED, 'No such listener')

    async def close_client_tcp_listener(self, listen_host, listen_port):
        """Close a remote TCP/IP listener"""

        await self._make_global_request(
            b'cancel-tcpip-forward', String(listen_host), UInt32(listen_port))

        self.logger.info('Closed remote TCP listener on %s',
                         (listen_host, listen_port))

        listener = self._remote_listeners.get((listen_host, listen_port))

        if listener:
            if self._dynamic_remote_listeners.get(listen_host) == listener:
                del self._dynamic_remote_listeners[listen_host]

            del self._remote_listeners[listen_host, listen_port]

    def _process_direct_streamlocal_at_openssh_dot_com_open(self, _packet):
        """Process an inbound direct UNIX domain channel open request

           These requests are disallowed on an SSH client.

        """

        # pylint: disable=no-self-use

        raise ChannelOpenError(OPEN_ADMINISTRATIVELY_PROHIBITED,
                               'Direct UNIX domain socket open '
                               'forbidden on client')

    def _process_forwarded_streamlocal_at_openssh_dot_com_open(self, packet):
        """Process an inbound forwarded UNIX domain channel open request"""

        dest_path = packet.get_string()
        _ = packet.get_string()                         # reserved
        packet.check_end()

        try:
            dest_path = dest_path.decode('utf-8')
        except UnicodeDecodeError:
            raise ProtocolError('Invalid forwarded UNIX domain channel '
                                'open request') from None

        listener = self._remote_listeners.get(dest_path)

        if listener:
            chan, session = listener.process_connection()

            self.logger.info('Accepted remote UNIX connection on %s', dest_path)

            return chan, session
        else:
            raise ChannelOpenError(OPEN_CONNECT_FAILED, 'No such listener')

    async def close_client_unix_listener(self, listen_path):
        """Close a remote UNIX domain socket listener"""

        await self._make_global_request(
            b'cancel-streamlocal-forward@openssh.com', String(listen_path))

        self.logger.info('Closed UNIX listener on %s', listen_path)

        if listen_path in self._remote_listeners:
            del self._remote_listeners[listen_path]

    def _process_x11_open(self, packet):
        """Process an inbound X11 channel open request"""

        orig_host = packet.get_string()
        orig_port = packet.get_uint32()

        packet.check_end()

        if self._x11_listener:
            self.logger.info('Accepted X11 connection')
            self.logger.info('  Client address: %s', (orig_host, orig_port))

            chan = self.create_x11_channel()

            chan.set_inbound_peer_names(orig_host, orig_port)

            return chan, self._x11_listener.forward_connection()
        else:
            raise ChannelOpenError(OPEN_CONNECT_FAILED,
                                   'X11 forwarding disabled')

    def _process_auth_agent_at_openssh_dot_com_open(self, packet):
        """Process an inbound auth agent channel open request"""

        packet.check_end()

        if self._agent_forward_path:
            self.logger.info('Accepted SSH agent connection')

            return (self.create_unix_channel(),
                    self.forward_unix_connection(self._agent_forward_path))
        else:
            raise ChannelOpenError(OPEN_CONNECT_FAILED,
                                   'Auth agent forwarding disabled')

    async def attach_x11_listener(self, chan, display, auth_path,
                                  single_connection):
        """Attach a channel to a local X11 display"""

        if not display:
            display = os.environ.get('DISPLAY')

        if not display:
            raise ValueError('X11 display not set')

        if not self._x11_listener:
            self._x11_listener = await create_x11_client_listener(
                self._loop, display, auth_path)

        return self._x11_listener.attach(display, chan, single_connection)

    def detach_x11_listener(self, chan):
        """Detach a session from a local X11 listener"""

        if self._x11_listener:
            if self._x11_listener.detach(chan):
                self._x11_listener = None

    async def create_session(self, session_factory, command=(), *,
                             subsystem=(), env=(), send_env=(),
                             request_pty=(), term_type=(), term_size=(),
                             term_modes=(), x11_forwarding=(),
                             x11_display=(), x11_auth_path=(),
                             x11_single_connection=(), encoding=(),
                             errors=(), window=(), max_pktsize=()):
        """Create an SSH client session

           This method is a coroutine which can be called to create an SSH
           client session used to execute a command, start a subsystem
           such as sftp, or if no command or subsystem is specified run an
           interactive shell. Optional arguments allow terminal and
           environment information to be provided.

           By default, this class expects string data in its send and
           receive functions, which it encodes on the SSH connection in
           UTF-8 (ISO 10646) format. An optional encoding argument can
           be passed in to select a different encoding, or `None` can
           be passed in if the application wishes to send and receive
           raw bytes. When an encoding is set, an optional errors
           argument can be passed in to select what Unicode error
           handling strategy to use.

           Other optional arguments include the SSH receive window size and
           max packet size which default to 2 MB and 32 KB, respectively.

           :param session_factory:
               A `callable` which returns an :class:`SSHClientSession` object
               that will be created to handle activity on this session
           :param command: (optional)
               The remote command to execute. By default, an interactive
               shell is started if no command or subsystem is provided.
           :param subsystem: (optional)
               The name of a remote subsystem to start up.
           :param env: (optional)
               The  environment variables to set for this session. Keys and
               values passed in here will be converted to Unicode strings
               encoded as UTF-8 (ISO 10646) for transmission.

               .. note:: Many SSH servers restrict which environment
                         variables a client is allowed to set. The
                         server's configuration may need to be edited
                         before environment variables can be
                         successfully set in the remote environment.
           :param send_env: (optional)
               A list of environment variable names to pull from
               `os.environ` and set for this session. Wildcards patterns
               using `'*'` and `'?'` are allowed, and all variables with
               matching names will be sent with whatever value is set
               in the local environment. If a variable is present in both
               env and send_env, the value from env will be used.
           :param request_pty: (optional)
               Whether or not to request a pseudo-terminal (PTY) for this
               session. This defaults to `True`, which means to request a
               PTY whenever the `term_type` is set. Other possible values
               include `False` to never request a PTY, `'force'` to always
               request a PTY even without `term_type` being set, or `'auto'`
               to request a TTY when `term_type` is set but only when
               starting an interactive shell.
           :param term_type: (optional)
               The terminal type to set for this session.
           :param term_size: (optional)
               The terminal width and height in characters and optionally
               the width and height in pixels.
           :param term_modes: (optional)
               POSIX terminal modes to set for this session, where keys are
               taken from :ref:`POSIX terminal modes <PTYModes>` with values
               defined in section 8 of :rfc:`RFC 4254 <4254#section-8>`.
           :param x11_forwarding: (optional)
               Whether or not to request X11 forwarding for this session,
               defaulting to `False`. If set to `True`, X11 forwarding will
               be requested and a failure will raise :exc:`ChannelOpenError`.
               It can also be set to `'ignore_failure'` to attempt X11
               forwarding but ignore failures.
           :param x11_display: (optional)
               The display that X11 connections should be forwarded to,
               defaulting to the value in the environment variable `DISPLAY`.
           :param x11_auth_path: (optional)
               The path to the Xauthority file to read X11 authentication
               data from, defaulting to the value in the environment variable
               `XAUTHORITY` or the file :file:`.Xauthority` in the user's
               home directory if that's not set.
           :param x11_single_connection: (optional)
               Whether or not to limit X11 forwarding to a single connection,
               defaulting to `False`.
           :param encoding: (optional)
               The Unicode encoding to use for data exchanged on this session.
           :param errors: (optional)
               The error handling strategy to apply on Unicode encode/decode
               errors.
           :param window: (optional)
               The receive window size for this session.
           :param max_pktsize: (optional)
               The maximum packet size for this session.
           :type session_factory: `callable`
           :type command: `str`
           :type subsystem: `str`
           :type env: `dict`
           :type send_env: `str` or `list` of `str`
           :type request_pty: `bool`, `'force'`, or `'auto'`
           :type term_type: `str`
           :type term_size: `tuple` of 2 or 4 `int` values
           :type term_modes: `dict`
           :type x11_forwarding: `bool` or `'ignore_failure'`
           :type x11_display: `str`
           :type x11_auth_path: `str`
           :type x11_single_connection: `bool`
           :type encoding: `str`
           :type errors: `str`
           :type window: `int`
           :type max_pktsize: `int`

           :returns: an :class:`SSHClientChannel` and :class:`SSHClientSession`

           :raises: :exc:`ChannelOpenError` if the session can't be opened

        """

        if command == ():
            command = self._options.command

        if subsystem == ():
            subsystem = self._options.subsystem

        if env == ():
            env = self._options.env

        if send_env == ():
            send_env = self._options.send_env

        if request_pty == ():
            request_pty = self._options.request_pty

        if term_type == ():
            term_type = self._options.term_type

        if term_size == ():
            term_size = self._options.term_size

        if term_modes == ():
            term_modes = self._options.term_modes

        if x11_forwarding == ():
            x11_forwarding = self._options.x11_forwarding

        if x11_display == ():
            x11_display = self._options.x11_display

        if x11_auth_path == ():
            x11_auth_path = self._options.x11_auth_path

        if x11_single_connection == ():
            x11_single_connection = self._options.x11_single_connection

        if encoding == ():
            encoding = self._options.encoding

        if errors == ():
            errors = self._options.errors

        if window == ():
            window = self._options.window

        if max_pktsize == ():
            max_pktsize = self._options.max_pktsize

        new_env = {}

        if send_env:
            for key in send_env:
                pattern = WildcardPattern(key)
                new_env.update((key, value) for key, value in os.environ.items()
                               if pattern.matches(key))

        if env:
            try:
                if isinstance(env, list):
                    env = (item.split('=', 2) for item in env)

                new_env.update(env)
            except ValueError:
                raise ValueError('Invalid environment value') from None

        if request_pty == 'force':
            request_pty = True
        elif request_pty == 'auto':
            request_pty = bool(term_type and not (command or subsystem))
        elif request_pty:
            request_pty = bool(term_type)

        chan = SSHClientChannel(self, self._loop, encoding, errors,
                                window, max_pktsize)

        session = await chan.create(session_factory, command, subsystem,
                                    new_env, request_pty, term_type, term_size,
                                    term_modes or {}, x11_forwarding,
                                    x11_display, x11_auth_path,
                                    x11_single_connection,
                                    bool(self._agent_forward_path))

        return chan, session

    async def open_session(self, *args, **kwargs):
        """Open an SSH client session

           This method is a coroutine wrapper around :meth:`create_session`
           designed to provide a "high-level" stream interface for creating
           an SSH client session. Instead of taking a `session_factory`
           argument for constructing an object which will handle activity
           on the session via callbacks, it returns an :class:`SSHWriter`
           and two :class:`SSHReader` objects representing stdin, stdout,
           and stderr which can be used to perform I/O on the session. With
           the exception of `session_factory`, all of the arguments to
           :meth:`create_session` are supported and have the same meaning.

        """

        chan, session = await self.create_session(SSHClientStreamSession,
                                                  *args, **kwargs)

        return (SSHWriter(session, chan), SSHReader(session, chan),
                SSHReader(session, chan, EXTENDED_DATA_STDERR))

    # pylint: disable=redefined-builtin
    @async_context_manager
    async def create_process(self, *args, bufsize=io.DEFAULT_BUFFER_SIZE,
                             input=None, stdin=PIPE, stdout=PIPE, stderr=PIPE,
                             **kwargs):
        """Create a process on the remote system

           This method is a coroutine wrapper around :meth:`create_session`
           which can be used to execute a command, start a subsystem,
           or start an interactive shell, optionally redirecting stdin,
           stdout, and stderr to and from files or pipes attached to
           other local and remote processes.

           By default, the stdin, stdout, and stderr arguments default
           to the special value `PIPE` which means that they can be
           read and written interactively via stream objects which are
           members of the :class:`SSHClientProcess` object this method
           returns. If other file-like objects are provided as arguments,
           input or output will automatically be redirected to them. The
           special value `DEVNULL` can be used to provide no input or
           discard all output, and the special value `STDOUT` can be
           provided as `stderr` to send its output to the same stream
           as `stdout`.

           In addition to the arguments below, all arguments to
           :meth:`create_session` except for `session_factory` are
           supported and have the same meaning.

           :param bufsize: (optional)
               Buffer size to use when feeding data from a file to stdin
           :param input: (optional)
               Input data to feed to standard input of the remote process.
               If specified, this argument takes precedence over stdin.
               Data should be a `str` if encoding is set, or `bytes` if not.
           :param stdin: (optional)
               A filename, file-like object, file descriptor, socket, or
               :class:`SSHReader` to feed to standard input of the remote
               process, or `DEVNULL` to provide no input.
           :param stdout: (optional)
               A filename, file-like object, file descriptor, socket, or
               :class:`SSHWriter` to feed standard output of the remote
               process to, or `DEVNULL` to discard this output.
           :param stderr: (optional)
               A filename, file-like object, file descriptor, socket, or
               :class:`SSHWriter` to feed standard error of the remote
               process to, `DEVNULL` to discard this output, or `STDOUT`
               to feed standard error to the same place as stdout.
           :type bufsize: `int`
           :type input: `str` or `bytes`

           :returns: :class:`SSHClientProcess`

           :raises: :exc:`ChannelOpenError` if the channel can't be opened

        """

        chan, process = await self.create_session(SSHClientProcess,
                                                  *args, **kwargs)

        if input:
            chan.write(input)
            chan.write_eof()
            stdin = None

        await process.redirect(stdin, stdout, stderr, bufsize)

        return process

    async def create_subprocess(self, protocol_factory, *args, input=None,
                                bufsize=io.DEFAULT_BUFFER_SIZE, encoding=None,
                                stdin=PIPE, stdout=PIPE, stderr=PIPE, **kwargs):
        """Create a subprocess on the remote system

           This method is a coroutine wrapper around :meth:`create_session`
           which can be used to execute a command, start a subsystem,
           or start an interactive shell, optionally redirecting stdin,
           stdout, and stderr to and from files or pipes attached to
           other local and remote processes similar to :meth:`create_process`.
           However, instead of performing interactive I/O using
           :class:`SSHReader` and :class:`SSHWriter` objects, the caller
           provides a function which returns an object which conforms
           to the :class:`asyncio.SubprocessProtocol` and this call
           returns that and an :class:`SSHSubprocessTransport` object which
           conforms to :class:`asyncio.SubprocessTransport`.

           With the exception of the addition of `protocol_factory`, all
           of the arguments are the same as :meth:`create_process`.

           :param protocol_factory:
               A `callable` which returns an :class:`SSHSubprocessProtocol`
               object that will be created to handle activity on this
               session.
           :type protocol_factory: `callable`

           :returns: an :class:`SSHSubprocessTransport` and
                     :class:`SSHSubprocessProtocol`

           :raises: :exc:`ChannelOpenError` if the channel can't be opened

        """

        def transport_factory():
            """Return a subprocess transport"""

            return SSHSubprocessTransport(protocol_factory)

        _, transport = await self.create_session(
            transport_factory, *args, encoding=encoding, **kwargs)

        if input:
            stdin_pipe = transport.get_pipe_transport(0)
            stdin_pipe.write(input)
            stdin_pipe.write_eof()
            stdin = None

        await transport.redirect(stdin, stdout, stderr, bufsize)

        return transport, transport.get_protocol()
    # pylint: enable=redefined-builtin

    async def run(self, *args, check=False, timeout=None, **kwargs):
        """Run a command on the remote system and collect its output

           This method is a coroutine wrapper around :meth:`create_process`
           which can be used to run a process to completion when no
           interactivity is needed. All of the arguments to
           :meth:`create_process` can be passed in to provide input or
           redirect stdin, stdout, and stderr, but this method waits until
           the process exits and returns an :class:`SSHCompletedProcess`
           object with the exit status or signal information and the
           output to stdout and stderr (if not redirected).

           If the check argument is set to `True`, a non-zero exit status
           from the remote process will trigger the :exc:`ProcessError`
           exception to be raised.

           In addition to the argument below, all arguments to
           :meth:`create_process` are supported and have the same meaning.

           If a timeout is specified and it expires before the process
           exits, the :exc:`TimeoutError` exception will be raised. By
           default, no timeout is set and this call will wait indefinitely.

           :param check: (optional)
               Whether or not to raise :exc:`ProcessError` when a non-zero
               exit status is returned
           :param timeout:
               Amount of time in seconds to wait for process to exit or
               `None` to wait indefinitely
           :type check: `bool`
           :type timeout: `int`, `float`, or `None`

           :returns: :class:`SSHCompletedProcess`

           :raises: | :exc:`ChannelOpenError` if the session can't be opened
                    | :exc:`ProcessError` if checking non-zero exit status
                    | :exc:`TimeoutError` if the timeout expires before exit

        """

        process = await self.create_process(*args, **kwargs)

        return await process.wait(check, timeout)

    async def create_connection(self, session_factory, remote_host, remote_port,
                                orig_host='', orig_port=0, *, encoding=None,
                                errors='strict', window=_DEFAULT_WINDOW,
                                max_pktsize=_DEFAULT_MAX_PKTSIZE):
        """Create an SSH TCP direct connection

           This method is a coroutine which can be called to request that
           the server open a new outbound TCP connection to the specified
           destination host and port. If the connection is successfully
           opened, a new SSH channel will be opened with data being handled
           by a :class:`SSHTCPSession` object created by `session_factory`.

           Optional arguments include the host and port of the original
           client opening the connection when performing TCP port forwarding.

           By default, this class expects data to be sent and received as
           raw bytes. However, an optional encoding argument can be passed
           in to select the encoding to use, allowing the application send
           and receive string data. When encoding is set, an optional errors
           argument can be passed in to select what Unicode error handling
           strategy to use.

           Other optional arguments include the SSH receive window size and
           max packet size which default to 2 MB and 32 KB, respectively.

           :param session_factory:
               A `callable` which returns an :class:`SSHClientSession` object
               that will be created to handle activity on this session
           :param remote_host:
               The remote hostname or address to connect to
           :param remote_port:
               The remote port number to connect to
           :param orig_host: (optional)
               The hostname or address of the client requesting the connection
           :param orig_port: (optional)
               The port number of the client requesting the connection
           :param encoding: (optional)
               The Unicode encoding to use for data exchanged on the connection
           :param errors: (optional)
               The error handling strategy to apply on encode/decode errors
           :param window: (optional)
               The receive window size for this session
           :param max_pktsize: (optional)
               The maximum packet size for this session
           :type session_factory: `callable`
           :type remote_host: `str`
           :type remote_port: `int`
           :type orig_host: `str`
           :type orig_port: `int`
           :type encoding: `str`
           :type errors: `str`
           :type window: `int`
           :type max_pktsize: `int`

           :returns: an :class:`SSHTCPChannel` and :class:`SSHTCPSession`

           :raises: :exc:`ChannelOpenError` if the connection can't be opened

        """

        self.logger.info('Opening direct TCP connection to %s',
                         (remote_host, remote_port))
        self.logger.info('  Client address: %s', (orig_host, orig_port))

        chan = self.create_tcp_channel(encoding, errors, window, max_pktsize)

        session = await chan.connect(session_factory, remote_host, remote_port,
                                     orig_host, orig_port)

        return chan, session

    async def open_connection(self, *args, **kwargs):
        """Open an SSH TCP direct connection

           This method is a coroutine wrapper around :meth:`create_connection`
           designed to provide a "high-level" stream interface for creating
           an SSH TCP direct connection. Instead of taking a
           `session_factory` argument for constructing an object which will
           handle activity on the session via callbacks, it returns
           :class:`SSHReader` and :class:`SSHWriter` objects which can be
           used to perform I/O on the connection.

           With the exception of `session_factory`, all of the arguments
           to :meth:`create_connection` are supported and have the same
           meaning here.

           :returns: an :class:`SSHReader` and :class:`SSHWriter`

           :raises: :exc:`ChannelOpenError` if the connection can't be opened

        """

        chan, session = await self.create_connection(SSHTCPStreamSession,
                                                     *args, **kwargs)

        return SSHReader(session, chan), SSHWriter(session, chan)

    @async_context_manager
    async def create_server(self, session_factory, listen_host, listen_port, *,
                            encoding=None, errors='strict',
                            window=_DEFAULT_WINDOW,
                            max_pktsize=_DEFAULT_MAX_PKTSIZE):
        """Create a remote SSH TCP listener

           This method is a coroutine which can be called to request that
           the server listen on the specified remote address and port for
           incoming TCP connections. If the request is successful, the
           return value is an :class:`SSHListener` object which can be
           used later to shut down the listener. If the request fails,
           `None` is returned.

           :param session_factory:
               A `callable` or coroutine which takes arguments of the
               original host and port of the client and decides whether
               to accept the connection or not, either returning an
               :class:`SSHTCPSession` object used to handle activity on
               that connection or raising :exc:`ChannelOpenError` to
               indicate that the connection should not be accepted
           :param listen_host:
               The hostname or address on the remote host to listen on
           :param listen_port:
               The port number on the remote host to listen on
           :param encoding: (optional)
               The Unicode encoding to use for data exchanged on the connection
           :param errors: (optional)
               The error handling strategy to apply on encode/decode errors
           :param window: (optional)
               The receive window size for this session
           :param max_pktsize: (optional)
               The maximum packet size for this session
           :type session_factory: `callable` or coroutine
           :type listen_host: `str`
           :type listen_port: `int`
           :type encoding: `str`
           :type errors: `str`
           :type window: `int`
           :type max_pktsize: `int`

           :returns: :class:`SSHListener`

           :raises: :class:`ChannelListenError` if the listener can't be opened

        """

        listen_host = listen_host.lower()

        self.logger.info('Creating remote TCP listener on %s',
                         (listen_host, listen_port))

        pkttype, packet = await self._make_global_request(
            b'tcpip-forward', String(listen_host), UInt32(listen_port))

        if pkttype == MSG_REQUEST_SUCCESS:
            if listen_port == 0:
                listen_port = packet.get_uint32()
                dynamic = True
            else:
                # OpenSSH 6.8 introduced a bug which causes the reply
                # to contain an extra uint32 value of 0 when non-dynamic
                # ports are requested, causing the check_end() call below
                # to fail. This check works around this problem.
                if len(packet.get_remaining_payload()) == 4: # pragma: no cover
                    packet.get_uint32()

                dynamic = False

            packet.check_end()

            listener = SSHTCPClientListener(self, session_factory,
                                            listen_host, listen_port, encoding,
                                            errors, window, max_pktsize)

            if dynamic:
                self.logger.debug1('Assigning dynamic port %d', listen_port)

                self._dynamic_remote_listeners[listen_host] = listener

            self._remote_listeners[listen_host, listen_port] = listener
            return listener
        else:
            packet.check_end()
            self.logger.debug1('Failed to create remote TCP listener')
            raise ChannelListenError('Failed to create remote TCP listener')

    @async_context_manager
    async def start_server(self, handler_factory, *args, **kwargs):
        """Start a remote SSH TCP listener

           This method is a coroutine wrapper around :meth:`create_server`
           designed to provide a "high-level" stream interface for creating
           remote SSH TCP listeners. Instead of taking a `session_factory`
           argument for constructing an object which will handle activity on
           the session via callbacks, it takes a `handler_factory` which
           returns a `callable` or coroutine that will be passed
           :class:`SSHReader` and :class:`SSHWriter` objects which can be
           used to perform I/O on each new connection which arrives. Like
           :meth:`create_server`, `handler_factory` can also raise
           :exc:`ChannelOpenError` if the connection should not be accepted.

           With the exception of `handler_factory` replacing
           `session_factory`, all of the arguments to :meth:`create_server`
           are supported and have the same meaning here.

           :param handler_factory:
               A `callable` or coroutine which takes arguments of the
               original host and port of the client and decides whether to
               accept the connection or not, either returning a callback
               or coroutine used to handle activity on that connection
               or raising :exc:`ChannelOpenError` to indicate that the
               connection should not be accepted
           :type handler_factory: `callable` or coroutine

           :returns: :class:`SSHListener`

           :raises: :class:`ChannelListenError` if the listener can't be opened

        """

        def session_factory(orig_host, orig_port):
            """Return a TCP stream session handler"""

            return SSHTCPStreamSession(handler_factory(orig_host, orig_port))

        return await self.create_server(session_factory, *args, **kwargs)

    async def create_unix_connection(self, session_factory, remote_path, *,
                                     encoding=None, errors='strict',
                                     window=_DEFAULT_WINDOW,
                                     max_pktsize=_DEFAULT_MAX_PKTSIZE):
        """Create an SSH UNIX domain socket direct connection

           This method is a coroutine which can be called to request that
           the server open a new outbound UNIX domain socket connection to
           the specified destination path. If the connection is successfully
           opened, a new SSH channel will be opened with data being handled
           by a :class:`SSHUNIXSession` object created by `session_factory`.

           By default, this class expects data to be sent and received as
           raw bytes. However, an optional encoding argument can be passed
           in to select the encoding to use, allowing the application to
           send and receive string data. When encoding is set, an optional
           errors argument can be passed in to select what Unicode error
           handling strategy to use.

           Other optional arguments include the SSH receive window size and
           max packet size which default to 2 MB and 32 KB, respectively.

           :param session_factory:
               A `callable` which returns an :class:`SSHClientSession` object
               that will be created to handle activity on this session
           :param remote_path:
               The remote path to connect to
           :param encoding: (optional)
               The Unicode encoding to use for data exchanged on the connection
           :param errors: (optional)
               The error handling strategy to apply on encode/decode errors
           :param window: (optional)
               The receive window size for this session
           :param max_pktsize: (optional)
               The maximum packet size for this session
           :type session_factory: `callable`
           :type remote_path: `str`
           :type encoding: `str`
           :type errors: `str`
           :type window: `int`
           :type max_pktsize: `int`

           :returns: an :class:`SSHUNIXChannel` and :class:`SSHUNIXSession`

           :raises: :exc:`ChannelOpenError` if the connection can't be opened

        """

        self.logger.info('Opening direct UNIX connection to %s', remote_path)

        chan = self.create_unix_channel(encoding, errors, window, max_pktsize)

        session = await chan.connect(session_factory, remote_path)

        return chan, session

    async def open_unix_connection(self, *args, **kwargs):
        """Open an SSH UNIX domain socket direct connection

           This method is a coroutine wrapper around
           :meth:`create_unix_connection` designed to provide a "high-level"
           stream interface for creating an SSH UNIX domain socket direct
           connection. Instead of taking a `session_factory` argument for
           constructing an object which will handle activity on the session
           via callbacks, it returns :class:`SSHReader` and :class:`SSHWriter`
           objects which can be used to perform I/O on the connection.

           With the exception of `session_factory`, all of the arguments
           to :meth:`create_unix_connection` are supported and have the same
           meaning here.

           :returns: an :class:`SSHReader` and :class:`SSHWriter`

           :raises: :exc:`ChannelOpenError` if the connection can't be opened

        """

        chan, session = \
            await self.create_unix_connection(SSHUNIXStreamSession,
                                              *args, **kwargs)

        return SSHReader(session, chan), SSHWriter(session, chan)

    @async_context_manager
    async def create_unix_server(self, session_factory, listen_path, *,
                                 encoding=None, errors='strict',
                                 window=_DEFAULT_WINDOW,
                                 max_pktsize=_DEFAULT_MAX_PKTSIZE):
        """Create a remote SSH UNIX domain socket listener

           This method is a coroutine which can be called to request that
           the server listen on the specified remote path for incoming UNIX
           domain socket connections. If the request is successful, the
           return value is an :class:`SSHListener` object which can be
           used later to shut down the listener. If the request fails,
           `None` is returned.

           :param session_factory:
               A `callable` or coroutine which takes arguments of the
               original host and port of the client and decides whether
               to accept the connection or not, either returning an
               :class:`SSHUNIXSession` object used to handle activity
               on that connection or raising :exc:`ChannelOpenError`
               to indicate that the connection should not be accepted
           :param listen_path:
               The path on the remote host to listen on
           :param encoding: (optional)
               The Unicode encoding to use for data exchanged on the connection
           :param errors: (optional)
               The error handling strategy to apply on encode/decode errors
           :param window: (optional)
               The receive window size for this session
           :param max_pktsize: (optional)
               The maximum packet size for this session
           :type session_factory: `callable` or coroutine
           :type listen_path: `str`
           :type encoding: `str`
           :type errors: `str`
           :type window: `int`
           :type max_pktsize: `int`

           :returns: :class:`SSHListener`

           :raises: :class:`ChannelListenError` if the listener can't be opened

        """

        self.logger.info('Creating remote UNIX listener on %s', listen_path)

        pkttype, packet = await self._make_global_request(
            b'streamlocal-forward@openssh.com', String(listen_path))

        packet.check_end()

        if pkttype == MSG_REQUEST_SUCCESS:
            listener = SSHUNIXClientListener(self, session_factory,
                                             listen_path, encoding, errors,
                                             window, max_pktsize)

            self._remote_listeners[listen_path] = listener
            return listener
        else:
            self.logger.debug1('Failed to create remote UNIX listener')
            raise ChannelListenError('Failed to create remote UNIX listener')

    @async_context_manager
    async def start_unix_server(self, handler_factory, *args, **kwargs):
        """Start a remote SSH UNIX domain socket listener

           This method is a coroutine wrapper around :meth:`create_unix_server`
           designed to provide a "high-level" stream interface for creating
           remote SSH UNIX domain socket listeners. Instead of taking a
           `session_factory` argument for constructing an object which
           will handle activity on the session via callbacks, it takes a
           `handler_factory` which returns a `callable` or coroutine that
           will be passed :class:`SSHReader` and :class:`SSHWriter` objects
           which can be used to perform I/O on each new connection which
           arrives. Like :meth:`create_unix_server`, `handler_factory`
           can also raise :exc:`ChannelOpenError` if the connection should
           not be accepted.

           With the exception of `handler_factory` replacing
           `session_factory`, all of the arguments to
           :meth:`create_unix_server` are supported and have the same
           meaning here.

           :param handler_factory:
               A `callable` or coroutine which takes arguments of the
               original host and port of the client and decides whether to
               accept the connection or not, either returning a callback
               or coroutine used to handle activity on that connection
               or raising :exc:`ChannelOpenError` to indicate that the
               connection should not be accepted
           :type handler_factory: `callable` or coroutine

           :returns: :class:`SSHListener`

           :raises: :class:`ChannelListenError` if the listener can't be opened

        """

        def session_factory():
            """Return a UNIX domain socket stream session handler"""

            return SSHUNIXStreamSession(handler_factory())

        return await self.create_unix_server(session_factory, *args, **kwargs)

    async def create_ssh_connection(self, client_factory, host,
                                    port=(), **kwargs):
        """Create a tunneled SSH client connection

           This method is a coroutine which can be called to open an
           SSH client connection to the requested host and port tunneled
           inside this already established connection. It takes all the
           same arguments as :func:`create_connection` but requests
           that the upstream SSH server open the connection rather than
           connecting directly.

        """

        return (await create_connection(client_factory, host, port,
                                        tunnel=self, **kwargs))

    @async_context_manager
    async def connect_ssh(self, host, port=(), **kwargs):
        """Make a tunneled SSH client connection

           This method is a coroutine which can be called to open an
           SSH client connection to the requested host and port tunneled
           inside this already established connection. It takes all the
           same arguments as :func:`connect` but requests that the upstream
           SSH server open the connection rather than connecting directly.

        """

        return await connect(host, port, tunnel=self, **kwargs)

    @async_context_manager
    async def connect_reverse_ssh(self, host, port=(), **kwargs):
        """Make a tunneled reverse direction SSH connection

           This method is a coroutine which can be called to open an
           SSH client connection to the requested host and port tunneled
           inside this already established connection. It takes all the
           same arguments as :func:`connect` but requests that the upstream
           SSH server open the connection rather than connecting directly.

        """

        return await connect_reverse(host, port, tunnel=self, **kwargs)

    @async_context_manager
    async def listen_ssh(self, host='', port=(), **kwargs):
        """Create a tunneled SSH listener

           This method is a coroutine which can be called to open a remote
           SSH listener on the requested host and port tunneled inside this
           already established connection. It takes all the same arguments as
           :func:`listen` but requests that the upstream SSH server open the
           listener rather than listening directly via TCP/IP.

        """

        return await listen(host, port, tunnel=self, **kwargs)

    @async_context_manager
    async def listen_reverse_ssh(self, host='', port=(), **kwargs):
        """Create a tunneled reverse direction SSH listener

           This method is a coroutine which can be called to open a remote
           SSH listener on the requested host and port tunneled inside this
           already established connection. It takes all the same arguments as
           :func:`listen_reverse` but requests that the upstream SSH server
           open the listener rather than listening directly via TCP/IP.

        """

        return await listen_reverse(host, port, tunnel=self, **kwargs)

    @async_context_manager
    async def forward_remote_port(self, listen_host, listen_port,
                                  dest_host, dest_port):
        """Set up remote port forwarding

           This method is a coroutine which attempts to set up port
           forwarding from a remote listening port to a local host and port
           via the SSH connection. If the request is successful, the
           return value is an :class:`SSHListener` object which can be
           used later to shut down the port forwarding. If the request
           fails, `None` is returned.

           :param listen_host:
               The hostname or address on the remote host to listen on
           :param listen_port:
               The port number on the remote host to listen on
           :param dest_host:
               The hostname or address to forward connections to
           :param dest_port:
               The port number to forward connections to
           :type listen_host: `str`
           :type listen_port: `int`
           :type dest_host: `str`
           :type dest_port: `int`

           :returns: :class:`SSHListener`

           :raises: :class:`ChannelListenError` if the listener can't be opened

        """

        def session_factory(_orig_host, _orig_port):
            """Return an SSHTCPSession used to do remote port forwarding"""

            return self.forward_connection(dest_host, dest_port)

        self.logger.info('Creating remote TCP forwarder from %s to %s',
                         (listen_host, listen_port), (dest_host, dest_port))

        return await self.create_server(session_factory, listen_host,
                                        listen_port)

    @async_context_manager
    async def forward_remote_path(self, listen_path, dest_path):
        """Set up remote UNIX domain socket forwarding

           This method is a coroutine which attempts to set up UNIX domain
           socket forwarding from a remote listening path to a local path
           via the SSH connection. If the request is successful, the
           return value is an :class:`SSHListener` object which can be
           used later to shut down the port forwarding. If the request
           fails, `None` is returned.

           :param listen_path:
               The path on the remote host to listen on
           :param dest_path:
               The path on the local host to forward connections to
           :type listen_path: `str`
           :type dest_path: `str`

           :returns: :class:`SSHListener`

           :raises: :class:`ChannelListenError` if the listener can't be opened

        """

        def session_factory():
            """Return an SSHUNIXSession used to do remote path forwarding"""

            return self.forward_unix_connection(dest_path)

        self.logger.info('Creating remote UNIX forwarder from %s to %s',
                         listen_path, dest_path)

        return await self.create_unix_server(session_factory, listen_path)

    @async_context_manager
    async def forward_socks(self, listen_host, listen_port):
        """Set up local port forwarding via SOCKS

           This method is a coroutine which attempts to set up dynamic
           port forwarding via SOCKS on the specified local host and
           port. Each SOCKS request contains the destination host and
           port to connect to and triggers a request to tunnel traffic
           to the requested host and port via the SSH connection.

           If the request is successful, the return value is an
           :class:`SSHListener` object which can be used later to shut
           down the port forwarding.

           :param listen_host:
               The hostname or address on the local host to listen on
           :param listen_port:
               The port number on the local host to listen on
           :type listen_host: `str`
           :type listen_port: `int`

           :returns: :class:`SSHListener`

           :raises: :exc:`OSError` if the listener can't be opened

        """

        async def tunnel_socks(session_factory, dest_host, dest_port,
                               orig_host, orig_port):
            """Forward a local SOCKS connection over SSH"""

            return await self.create_connection(session_factory,
                                                dest_host, dest_port,
                                                orig_host, orig_port)

        self.logger.info('Creating local SOCKS forwarder on %s',
                         (listen_host, listen_port))

        try:
            listener = await create_socks_listener(self, self._loop,
                                                   tunnel_socks,
                                                   listen_host, listen_port)
        except OSError as exc:
            self.logger.debug1('Failed to create local SOCKS listener: %s', exc)
            raise

        if listen_port == 0:
            listen_port = listener.get_port()

        self._local_listeners[listen_host, listen_port] = listener

        return listener

    @async_context_manager
    async def start_sftp_client(self, env=(), send_env=(),
                                path_encoding='utf-8', path_errors='strict'):
        """Start an SFTP client

           This method is a coroutine which attempts to start a secure
           file transfer session. If it succeeds, it returns an
           :class:`SFTPClient` object which can be used to copy and
           access files on the remote host.

           An optional Unicode encoding can be specified for sending and
           receiving pathnames, defaulting to UTF-8 with strict error
           checking. If an encoding of `None` is specified, pathnames
           will be left as bytes rather than being converted to & from
           strings.

           :param env: (optional)
               The environment variables to set for this SFTP session. Keys
               and values passed in here will be converted to Unicode
               strings encoded as UTF-8 (ISO 10646) for transmission.

               .. note:: Many SSH servers restrict which environment
                         variables a client is allowed to set. The
                         server's configuration may need to be edited
                         before environment variables can be
                         successfully set in the remote environment.
           :param send_env: (optional)
               A list of environment variable names to pull from
               `os.environ` and set for this SFTP session. Wildcards
               patterns using `'*'` and `'?'` are allowed, and all variables
               with matching names will be sent with whatever value is set
               in the local environment. If a variable is present in both
               env and send_env, the value from env will be used.
           :param path_encoding:
               The Unicode encoding to apply when sending and receiving
               remote pathnames
           :param path_errors:
               The error handling strategy to apply on encode/decode errors
           :type env: `dict`
           :type send_env: `list` of `str`
           :type path_encoding: `str`
           :type path_errors: `str`

           :returns: :class:`SFTPClient`

           :raises: :exc:`SFTPError` if the session can't be opened

        """

        writer, reader, _ = await self.open_session(subsystem='sftp',
                                                    env=env, send_env=send_env,
                                                    encoding=None)

        return await start_sftp_client(self, self._loop, reader, writer,
                                       path_encoding, path_errors)


class SSHServerConnection(SSHConnection):
    """SSH server connection

       This class represents an SSH server connection.

       During authentication, :meth:`send_auth_banner` can be called to
       send an authentication banner to the client.

       Once authenticated, :class:`SSHServer` objects wishing to create
       session objects with non-default channel properties can call
       :meth:`create_server_channel` from their :meth:`session_requested()
       <SSHServer.session_requested>` method and return a tuple of
       the :class:`SSHServerChannel` object returned from that and either
       an :class:`SSHServerSession` object or a coroutine which returns
       an :class:`SSHServerSession`.

       Similarly, :class:`SSHServer` objects wishing to create TCP
       connection objects with non-default channel properties can call
       :meth:`create_tcp_channel` from their :meth:`connection_requested()
       <SSHServer.connection_requested>` method and return a tuple of
       the :class:`SSHTCPChannel` object returned from that and either
       an :class:`SSHTCPSession` object or a coroutine which returns an
       :class:`SSHTCPSession`.

       :class:`SSHServer` objects wishing to create UNIX domain socket
       connection objects with non-default channel properties can call
       :meth:`create_unix_channel` from the :meth:`unix_connection_requested()
       <SSHServer.unix_connection_requested>` method and return a tuple of
       the :class:`SSHUNIXChannel` object returned from that and either
       an :class:`SSHUNIXSession` object or a coroutine which returns an
       :class:`SSHUNIXSession`.

    """

    def __init__(self, loop, options, acceptor=None,
                 error_handler=None, wait=None):
        super().__init__(loop, options, acceptor, error_handler,
                         wait, server=True)

        self._options = options

        self._server_host_keys = options.server_host_keys
        self._server_host_key_algs = list(options.server_host_keys.keys())
        self._known_client_hosts = options.known_client_hosts
        self._trust_client_host = options.trust_client_host
        self._client_keys = options.authorized_client_keys
        self._allow_pty = options.allow_pty
        self._line_editor = options.line_editor
        self._line_history = options.line_history
        self._max_line_length = options.max_line_length
        self._rdns_lookup = options.rdns_lookup
        self._x11_forwarding = options.x11_forwarding
        self._x11_auth_path = options.x11_auth_path
        self._agent_forwarding = options.agent_forwarding
        self._process_factory = options.process_factory
        self._session_factory = options.session_factory
        self._encoding = options.encoding
        self._errors = options.errors
        self._sftp_factory = options.sftp_factory
        self._allow_scp = options.allow_scp
        self._window = options.window
        self._max_pktsize = options.max_pktsize

        if options.gss_host:
            try:
                self._gss = GSSServer(options.gss_host)
                self._gss_kex = options.gss_kex
                self._gss_auth = options.gss_auth
                self._gss_mic_auth = self._gss_auth
            except GSSError:
                pass

        self._server_host_key = None
        self._key_options = {}
        self._cert_options = None
        self._kbdint_password_auth = False

        self._agent_listener = None

    def _cleanup(self, exc):
        """Clean up this server connection"""

        if self._agent_listener:
            self._agent_listener.close()
            self._agent_listener = None

        super()._cleanup(exc)

    def _connection_made(self):
        """Handle the opening of a new connection"""

        self.logger.info('Accepted SSH client connection')

        if self._options.proxy_command:
            proxy_command = ' '.join(shlex.quote(arg) for arg in
                                     self._options.proxy_command)
            self.logger.info('  Proxy command: %s', proxy_command)
        else:
            self.logger.info('  Local address: %s',
                             (self._local_addr, self._local_port))
            self.logger.info('  Peer address: %s',
                             (self._peer_addr, self._peer_port))

    async def _reload_config(self):
        """Re-evaluate config with updated match options"""

        if self._rdns_lookup:
            self._peer_host, _ = await self._loop.getnameinfo(
                (self._peer_addr, self._peer_port), socket.NI_NUMERICSERV)

        options = SSHServerConnectionOptions(
            options=self._options, reload=True,
            accept_addr=self._local_addr, accept_port=self._local_port,
            username=self._username, client_host=self._peer_host,
            client_addr=self._peer_addr)

        self._options = options

        self._host_based_auth = options.host_based_auth
        self._public_key_auth = options.public_key_auth
        self._kbdint_auth = options.kbdint_auth
        self._password_auth = options.password_auth

        self._client_keys = options.authorized_client_keys
        self._allow_pty = options.allow_pty
        self._x11_forwarding = options.x11_forwarding
        self._agent_forwarding = options.agent_forwarding

        self._rekey_bytes = options.rekey_bytes
        self._rekey_seconds = options.rekey_seconds

        self._keepalive_count_max = options.keepalive_count_max
        self._keepalive_interval = options.keepalive_interval

    def _choose_server_host_key(self, peer_host_key_algs):
        """Choose the server host key to use

           Given a list of host key algorithms supported by the client,
           select the first compatible server host key we have and return
           whether or not we were able to find a match.

        """

        for alg in peer_host_key_algs:
            keypair = self._server_host_keys.get(alg)
            if keypair:
                if alg != keypair.algorithm:
                    keypair.set_sig_algorithm(alg)

                self._server_host_key = keypair
                return True

        return False

    def get_server_host_key(self):
        """Return the chosen server host key

           This method returns a keypair object containing the
           chosen server host key and a corresponding public key
           or certificate.

        """

        return self._server_host_key

    def gss_kex_auth_supported(self):
        """Return whether GSS key exchange authentication is supported"""

        return self._gss_kex_auth and self._gss.complete

    def gss_mic_auth_supported(self):
        """Return whether GSS MIC authentication is supported"""

        return self._gss_mic_auth

    async def validate_gss_principal(self, username, user_principal,
                                     host_principal):
        """Validate the GSS principal name for the specified user

           Return whether the user principal acquired during GSS
           authentication is valid for the specified user.

        """

        result = self._owner.validate_gss_principal(username, user_principal,
                                                    host_principal)

        if inspect.isawaitable(result):
            result = await result

        return result

    def host_based_auth_supported(self):
        """Return whether or not host based authentication is supported"""

        return (self._host_based_auth and
                (bool(self._known_client_hosts) or
                 self._owner.host_based_auth_supported()))

    async def validate_host_based_auth(self, username, key_data, client_host,
                                       client_username, msg, signature):
        """Validate host based authentication for the specified host and user"""

        # Remove a trailing '.' from the client host if present
        if client_host[-1:] == '.':
            client_host = client_host[:-1]

        if self._trust_client_host:
            resolved_host = client_host
        else:
            resolved_host, _ = await self._loop.getnameinfo(
                self.get_extra_info('peername'), socket.NI_NUMERICSERV)

            if resolved_host != client_host:
                self.logger.info('Client host mismatch: received %s, '
                                 'resolved %s', client_host, resolved_host)

        if self._known_client_hosts:
            self._match_known_hosts(self._known_client_hosts, resolved_host,
                                    self._peer_addr, None)

        try:
            key = self._validate_host_key(resolved_host, self._peer_addr,
                                          self._peer_port, key_data)
        except ValueError as exc:
            self.logger.debug1('Invalid host key: %s', exc)
            return False

        if not key.verify(String(self._session_id) + msg, signature):
            self.logger.debug1('Invalid host-based auth signature')
            return False

        result = self._owner.validate_host_based_user(username, client_host,
                                                      client_username)

        if inspect.isawaitable(result):
            result = await result

        return result

    async def _validate_openssh_certificate(self, username, cert):
        """Validate an OpenSSH client certificate for the specified user"""

        options = None

        if self._client_keys:
            options = self._client_keys.validate(cert.signing_key,
                                                 self._peer_host,
                                                 self._peer_addr,
                                                 cert.principals, ca=True)

        if options is None:
            result = self._owner.validate_ca_key(username, cert.signing_key)

            if inspect.isawaitable(result):
                result = await result

            if not result:
                return None

            options = {}

        self._key_options = options

        if self.get_key_option('principals'):
            username = None

        try:
            cert.validate(CERT_TYPE_USER, username)
        except ValueError:
            return None

        allowed_addresses = cert.options.get('source-address')
        if allowed_addresses:
            ip = ip_address(self._peer_addr)
            if not any(ip in network for network in allowed_addresses):
                return None

        self._cert_options = cert.options

        cert.key.set_touch_required(
            not (self.get_key_option('no-touch-required', False) and
                 self.get_certificate_option('no-touch-required', False)))

        return cert.key

    async def _validate_x509_certificate_chain(self, username, cert):
        """Validate an X.509 client certificate for the specified user"""

        if not self._client_keys:
            return None

        options, trusted_cert = \
            self._client_keys.validate_x509(cert, self._peer_host,
                                            self._peer_addr)

        if options is None:
            return None

        self._key_options = options

        if self.get_key_option('principals'):
            username = None

        if trusted_cert:
            trusted_certs = self._x509_trusted_certs + [trusted_cert]
        else:
            trusted_certs = self._x509_trusted_certs

        try:
            cert.validate_chain(trusted_certs, self._x509_trusted_cert_paths,
                                None, self._x509_purposes,
                                user_principal=username)
        except ValueError:
            return None

        return cert.key

    async def _validate_client_certificate(self, username, key_data):
        """Validate a client certificate for the specified user"""

        try:
            cert = decode_ssh_certificate(key_data)
        except KeyImportError:
            return None

        if cert.is_x509_chain:
            return await self._validate_x509_certificate_chain(username, cert)
        else:
            return await self._validate_openssh_certificate(username, cert)

    async def _validate_client_public_key(self, username, key_data):
        """Validate a client public key for the specified user"""

        try:
            key = decode_ssh_public_key(key_data)
        except KeyImportError:
            return None

        options = None

        if self._client_keys:
            options = self._client_keys.validate(key, self._peer_host,
                                                 self._peer_addr)

        if options is None:
            result = self._owner.validate_public_key(username, key)

            if inspect.isawaitable(result):
                result = await result

            if not result:
                return None

            options = {}

        self._key_options = options

        key.set_touch_required(
            not self.get_key_option('no-touch-required', False))

        return key

    def public_key_auth_supported(self):
        """Return whether or not public key authentication is supported"""

        return (self._public_key_auth and
                (bool(self._client_keys) or
                 self._owner.public_key_auth_supported()))

    async def validate_public_key(self, username, key_data, msg, signature):
        """Validate the public key or certificate for the specified user

           This method validates that the public key or certificate provided
           is allowed for the specified user. If msg and signature are
           provided, the key is used to also validate the message signature.
           It returns `True` when the key is allowed and the signature (if
           present) is valid. Otherwise, it returns `False`.

        """

        key = ((await self._validate_client_certificate(username, key_data)) or
               (await self._validate_client_public_key(username, key_data)))

        if key is None:
            return False
        elif msg:
            return key.verify(String(self._session_id) + msg, signature)
        else:
            return True

    def password_auth_supported(self):
        """Return whether or not password authentication is supported"""

        return self._password_auth and self._owner.password_auth_supported()

    async def validate_password(self, username, password):
        """Return whether password is valid for this user"""

        result = self._owner.validate_password(username, password)

        if inspect.isawaitable(result):
            result = await result

        return result

    async def change_password(self, username, old_password, new_password):
        """Handle a password change request for a user"""

        result = self._owner.change_password(username, old_password,
                                             new_password)

        if inspect.isawaitable(result):
            result = await result

        return result

    def kbdint_auth_supported(self):
        """Return whether or not keyboard-interactive authentication
           is supported"""

        result = self._kbdint_auth and self._owner.kbdint_auth_supported()

        if result is True:
            return True
        elif (result is NotImplemented and
              self._owner.password_auth_supported()):
            self._kbdint_password_auth = True
            return True
        else:
            return False

    async def get_kbdint_challenge(self, username, lang, submethods):
        """Return a keyboard-interactive auth challenge"""

        if self._kbdint_password_auth:
            result = ('', '', DEFAULT_LANG, (('Password:', False),))
        else:
            result = self._owner.get_kbdint_challenge(username, lang,
                                                      submethods)

            if inspect.isawaitable(result):
                result = await result

        return result

    async def validate_kbdint_response(self, username, responses):
        """Return whether the keyboard-interactive response is valid
           for this user"""

        if self._kbdint_password_auth:
            if len(responses) != 1:
                return False

            try:
                result = self._owner.validate_password(username, responses[0])

                if inspect.isawaitable(result):
                    result = await result
            except PasswordChangeRequired:
                # Don't support password change requests for now in
                # keyboard-interactive auth
                result = False
        else:
            result = self._owner.validate_kbdint_response(username, responses)

            if inspect.isawaitable(result):
                result = await result

        return result

    def _process_session_open(self, packet):
        """Process an incoming session open request"""

        packet.check_end()

        if self._process_factory or self._session_factory or self._sftp_factory:
            chan = self.create_server_channel(self._encoding, self._errors,
                                              self._window, self._max_pktsize)

            if self._process_factory:
                session = SSHServerProcess(self._process_factory,
                                           self._sftp_factory,
                                           self._allow_scp)
            else:
                session = SSHServerStreamSession(self._session_factory,
                                                 self._sftp_factory,
                                                 self._allow_scp)
        else:
            result = self._owner.session_requested()

            if not result:
                raise ChannelOpenError(OPEN_CONNECT_FAILED, 'Session refused')

            if isinstance(result, tuple):
                chan, result = result
            else:
                chan = self.create_server_channel(self._encoding, self._errors,
                                                  self._window,
                                                  self._max_pktsize)

            if callable(result):
                session = SSHServerStreamSession(result, None, False)
            else:
                session = result

        return chan, session

    def _process_direct_tcpip_open(self, packet):
        """Process an incoming direct TCP/IP open request"""

        dest_host = packet.get_string()
        dest_port = packet.get_uint32()
        orig_host = packet.get_string()
        orig_port = packet.get_uint32()
        packet.check_end()

        try:
            dest_host = dest_host.decode('utf-8')
            orig_host = orig_host.decode('utf-8')
        except UnicodeDecodeError:
            raise ProtocolError('Invalid direct TCP/IP channel '
                                'open request') from None

        if not self.check_key_permission('port-forwarding') or \
           not self.check_certificate_permission('port-forwarding'):
            raise ChannelOpenError(OPEN_ADMINISTRATIVELY_PROHIBITED,
                                   'Port forwarding not permitted')

        permitted_opens = self.get_key_option('permitopen')

        if permitted_opens and \
           (dest_host, dest_port) not in permitted_opens and \
           (dest_host, None) not in permitted_opens:
            raise ChannelOpenError(OPEN_ADMINISTRATIVELY_PROHIBITED,
                                   'Port forwarding not permitted to %s '
                                   'port %s' % (dest_host, dest_port))

        result = self._owner.connection_requested(dest_host, dest_port,
                                                  orig_host, orig_port)

        if not result:
            raise ChannelOpenError(OPEN_CONNECT_FAILED, 'Connection refused')

        if result is True:
            result = self.forward_connection(dest_host, dest_port)

        if isinstance(result, tuple):
            chan, result = result
        else:
            chan = self.create_tcp_channel()

        if callable(result):
            session = SSHTCPStreamSession(result)
        else:
            session = result

        self.logger.info('Accepted direct TCP connection request to %s',
                         (dest_host, dest_port))
        self.logger.info('  Client address: %s', (orig_host, orig_port))

        chan.set_inbound_peer_names(dest_host, dest_port, orig_host, orig_port)

        return chan, session

    def _process_tcpip_forward_global_request(self, packet):
        """Process an incoming TCP/IP port forwarding request"""

        listen_host = packet.get_string()
        listen_port = packet.get_uint32()
        packet.check_end()

        try:
            listen_host = listen_host.decode('utf-8').lower()
        except UnicodeDecodeError:
            raise ProtocolError('Invalid TCP/IP forward request') from None

        if not self.check_key_permission('port-forwarding') or \
           not self.check_certificate_permission('port-forwarding'):
            self.logger.info('Request for TCP listener on %s denied: port '
                             'forwarding not permitted',
                             (listen_host, listen_port))

            self._report_global_response(False)
            return

        result = self._owner.server_requested(listen_host, listen_port)

        self.create_task(self._finish_port_forward(result, listen_host,
                                                   listen_port))

    async def _finish_port_forward(self, listener, listen_host, listen_port):
        """Finish processing a TCP/IP port forwarding request"""

        try:
            if inspect.isawaitable(listener):
                listener = await listener

            if listener is True:
                listener = await self.forward_local_port(
                    listen_host, listen_port, listen_host, listen_port)
        except OSError:
            self.logger.debug1('Failed to create TCP listener')
            self._report_global_response(False)
            return

        if not listener:
            self.logger.info('Request for TCP listener on %s denied by '
                             'application', (listen_host, listen_port))

            self._report_global_response(False)
            return

        if listen_port == 0:
            listen_port = listener.get_port()
            result = UInt32(listen_port)
        else:
            result = True

        self._local_listeners[listen_host, listen_port] = listener

        self.logger.info('Created TCP listener on %s',
                         (listen_host, listen_port))

        self._report_global_response(result)

    def _process_cancel_tcpip_forward_global_request(self, packet):
        """Process a request to cancel TCP/IP port forwarding"""

        listen_host = packet.get_string()
        listen_port = packet.get_uint32()
        packet.check_end()

        try:
            listen_host = listen_host.decode('utf-8').lower()
        except UnicodeDecodeError:
            raise ProtocolError('Invalid TCP/IP cancel '
                                'forward request') from None

        try:
            listener = self._local_listeners.pop((listen_host, listen_port))
        except KeyError:
            raise ProtocolError('TCP/IP listener not found') from None

        self.logger.info('Closed TCP listener on %s',
                         (listen_host, listen_port))

        listener.close()

        self._report_global_response(True)

    def _process_direct_streamlocal_at_openssh_dot_com_open(self, packet):
        """Process an incoming direct UNIX domain socket open request"""

        dest_path = packet.get_string()

        # OpenSSH appears to have a bug which sends this extra data
        _ = packet.get_string()                         # originator
        _ = packet.get_uint32()                         # originator_port

        packet.check_end()

        try:
            dest_path = dest_path.decode('utf-8')
        except UnicodeDecodeError:
            raise ProtocolError('Invalid direct UNIX domain channel '
                                'open request') from None

        if not self.check_key_permission('port-forwarding') or \
           not self.check_certificate_permission('port-forwarding'):
            raise ChannelOpenError(OPEN_ADMINISTRATIVELY_PROHIBITED,
                                   'Port forwarding not permitted')

        result = self._owner.unix_connection_requested(dest_path)

        if not result:
            raise ChannelOpenError(OPEN_CONNECT_FAILED, 'Connection refused')

        if result is True:
            result = self.forward_unix_connection(dest_path)

        if isinstance(result, tuple):
            chan, result = result
        else:
            chan = self.create_unix_channel()

        if callable(result):
            session = SSHUNIXStreamSession(result)
        else:
            session = result

        self.logger.info('Accepted direct UNIX connection on %s', dest_path)

        chan.set_inbound_peer_names(dest_path)

        return chan, session

    def _process_streamlocal_forward_at_openssh_dot_com_global_request(self,
                                                                       packet):
        """Process an incoming UNIX domain socket forwarding request"""

        listen_path = packet.get_string()
        packet.check_end()

        try:
            listen_path = listen_path.decode('utf-8')
        except UnicodeDecodeError:
            raise ProtocolError('Invalid UNIX domain socket '
                                'forward request') from None

        if not self.check_key_permission('port-forwarding') or \
           not self.check_certificate_permission('port-forwarding'):
            self.logger.info('Request for UNIX listener on %s denied: port '
                             'forwarding not permitted', listen_path)

            self._report_global_response(False)
            return

        result = self._owner.unix_server_requested(listen_path)

        if not result:
            self.logger.info('Request for UNIX listener on %s denied by '
                             'application', listen_path)

            self._report_global_response(False)
            return

        self.logger.info('Creating UNIX listener on %s', listen_path)

        if result is True:
            result = self.forward_local_path(listen_path, listen_path)

        self.create_task(self._finish_path_forward(result, listen_path))

    async def _finish_path_forward(self, listener, listen_path):
        """Finish processing a UNIX domain socket forwarding request"""

        try:
            if inspect.isawaitable(listener):
                listener = await listener

            self._local_listeners[listen_path] = listener
            self._report_global_response(True)
        except OSError:
            self.logger.debug1('Failed to create UNIX listener')
            self._report_global_response(False)

    def _process_cancel_streamlocal_forward_at_openssh_dot_com_global_request(
            self, packet):
        """Process a request to cancel UNIX domain socket forwarding"""

        listen_path = packet.get_string()
        packet.check_end()

        try:
            listen_path = listen_path.decode('utf-8')
        except UnicodeDecodeError:
            raise ProtocolError('Invalid UNIX domain cancel '
                                'forward request') from None

        try:
            listener = self._local_listeners.pop(listen_path)
        except KeyError:
            raise ProtocolError('UNIX domain listener not found') from None

        self.logger.info('Closed UNIX listener on %s', listen_path)

        listener.close()

        self._report_global_response(True)

    async def attach_x11_listener(self, chan, auth_proto, auth_data, screen):
        """Attach a channel to a remote X11 display"""

        if (not self._x11_forwarding or
                not self.check_key_permission('X11-forwarding') or
                not self.check_certificate_permission('X11-forwarding')):
            self.logger.info('X11 forwarding request denied: X11 '
                             'forwarding not permitted')

            return None

        if not self._x11_listener:
            self._x11_listener = await create_x11_server_listener(
                self, self._loop, self._x11_auth_path, auth_proto, auth_data)

        if self._x11_listener:
            return self._x11_listener.attach(chan, screen)
        else:
            return None

    def detach_x11_listener(self, chan):
        """Detach a session from a remote X11 listener"""

        if self._x11_listener:
            if self._x11_listener.detach(chan):
                self._x11_listener = None

    async def create_agent_listener(self):
        """Create a listener for forwarding ssh-agent connections"""

        if (not self._agent_forwarding or
                not self.check_key_permission('agent-forwarding') or
                not self.check_certificate_permission('agent-forwarding')):
            self.logger.info('Agent forwarding request denied: Agent '
                             'forwarding not permitted')

            return False

        if self._agent_listener:
            return True

        try:
            tempdir = tempfile.TemporaryDirectory(prefix='asyncssh-')
            path = str(Path(tempdir.name, 'agent'))

            unix_listener = await create_unix_forward_listener(
                self, self._loop, self.create_agent_connection, path)

            self._agent_listener = SSHAgentListener(tempdir, path,
                                                    unix_listener)
            return True
        except OSError:
            return False

    def get_agent_path(self):
        """Return the path of the ssh-agent listener, if one exists"""

        if self._agent_listener:
            return self._agent_listener.get_path()
        else:
            return None

    def send_auth_banner(self, msg, lang=DEFAULT_LANG):
        """Send an authentication banner to the client

           This method can be called to send an authentication banner to
           the client, displaying information while authentication is
           in progress. It is an error to call this method after the
           authentication is complete.

           :param msg:
               The message to display
           :param lang:
               The language the message is in
           :type msg: `str`
           :type lang: `str`

           :raises: :exc:`OSError` if authentication is already completed

        """

        if self._auth_complete:
            raise OSError('Authentication already completed')

        self.logger.debug1('Sending authentication banner')

        self.send_packet(MSG_USERAUTH_BANNER, String(msg), String(lang))

    def set_authorized_keys(self, authorized_keys):
        """Set the keys trusted for client public key authentication

           This method can be called to set the trusted user and
           CA keys for client public key authentication. It should
           generally be called from the :meth:`begin_auth
           <SSHServer.begin_auth>` method of :class:`SSHServer` to
           set the appropriate keys for the user attempting to
           authenticate.

           :param authorized_keys:
               The keys to trust for client public key authentication
           :type authorized_keys: *see* :ref:`SpecifyingAuthorizedKeys`

        """

        if isinstance(authorized_keys, (str, list)):
            authorized_keys = read_authorized_keys(authorized_keys)

        self._client_keys = authorized_keys

    def get_key_option(self, option, default=None):
        """Return option from authorized_keys

           If a client key or certificate was presented during authentication,
           this method returns the value of the requested option in the
           corresponding authorized_keys entry if it was set. Otherwise, it
           returns the default value provided.

           The following standard options are supported:

               | command (string)
               | environment (dictionary of name/value pairs)
               | from (list of host patterns)
               | no-touch-required (boolean)
               | permitopen (list of host/port tuples)
               | principals (list of usernames)

           Non-standard options are also supported and will return the
           value `True` if the option is present without a value or
           return a list of strings containing the values associated
           with each occurrence of that option name. If the option is
           not present, the specified default value is returned.

           :param option:
               The name of the option to look up.
           :param default:
               The default value to return if the option is not present.
           :type option: `str`

           :returns: The value of the option in authorized_keys, if set

        """

        return self._key_options.get(option, default)

    def check_key_permission(self, permission):
        """Check permissions in authorized_keys

           If a client key or certificate was presented during
           authentication, this method returns whether the specified
           permission is allowed by the corresponding authorized_keys
           entry. By default, all permissions are granted, but they
           can be revoked by specifying an option starting with
           'no-' without a value.

           The following standard options are supported:

               | X11-forwarding
               | agent-forwarding
               | port-forwarding
               | pty
               | user-rc

           AsyncSSH internally enforces X11-forwarding, agent-forwarding,
           port-forwarding and pty permissions but ignores user-rc since
           it does not implement that feature.

           Non-standard permissions can also be checked, as long as the
           option follows the convention of starting with 'no-'.

           :param permission:
               The name of the permission to check (without the 'no-').
           :type permission: `str`

           :returns: A `bool` indicating if the permission is granted.

        """

        return not self._key_options.get('no-' + permission, False)

    def get_certificate_option(self, option, default=None):
        """Return option from user certificate

           If a user certificate was presented during authentication,
           this method returns the value of the requested option in
           the certificate if it was set. Otherwise, it returns the
           default value provided.

           The following options are supported:

               | force-command (string)
               | no-touch-required (boolean)
               | source-address (list of CIDR-style IP network addresses)

           :param option:
               The name of the option to look up.
           :param default:
               The default value to return if the option is not present.
           :type option: `str`

           :returns: The value of the option in the user certificate, if set

        """

        if self._cert_options is not None:
            return self._cert_options.get(option, default)
        else:
            return default

    def check_certificate_permission(self, permission):
        """Check permissions in user certificate

           If a user certificate was presented during authentication,
           this method returns whether the specified permission was
           granted in the certificate. Otherwise, it acts as if all
           permissions are granted and returns `True`.

           The following permissions are supported:

               | X11-forwarding
               | agent-forwarding
               | port-forwarding
               | pty
               | user-rc

           AsyncSSH internally enforces agent-forwarding, port-forwarding
           and pty permissions but ignores the other values since it does
           not implement those features.

           :param permission:
               The name of the permission to check (without the 'permit-').
           :type permission: `str`

           :returns: A `bool` indicating if the permission is granted.

        """

        if self._cert_options is not None:
            return self._cert_options.get('permit-' + permission, False)
        else:
            return True

    def create_server_channel(self, encoding='utf-8', errors='strict',
                              window=_DEFAULT_WINDOW,
                              max_pktsize=_DEFAULT_MAX_PKTSIZE):
        """Create an SSH server channel for a new SSH session

           This method can be called by :meth:`session_requested()
           <SSHServer.session_requested>` to create an
           :class:`SSHServerChannel` with the desired encoding, Unicode
           error handling strategy, window, and max packet size for a
           newly created SSH server session.

           :param encoding: (optional)
               The Unicode encoding to use for data exchanged on the
               session, defaulting to UTF-8 (ISO 10646) format. If `None`
               is passed in, the application can send and receive raw
               bytes.
           :param errors: (optional)
               The error handling strategy to apply on encode/decode errors
           :param window: (optional)
               The receive window size for this session
           :param max_pktsize: (optional)
               The maximum packet size for this session
           :type encoding: `str`
           :type errors: `str`
           :type window: `int`
           :type max_pktsize: `int`

           :returns: :class:`SSHServerChannel`

        """

        return SSHServerChannel(self, self._loop, self._allow_pty,
                                self._line_editor, self._line_history,
                                self._max_line_length, encoding, errors,
                                window, max_pktsize)

    async def create_connection(self, session_factory, remote_host, remote_port,
                                orig_host='', orig_port=0, *, encoding=None,
                                errors='strict', window=_DEFAULT_WINDOW,
                                max_pktsize=_DEFAULT_MAX_PKTSIZE):
        """Create an SSH TCP forwarded connection

           This method is a coroutine which can be called to notify the
           client about a new inbound TCP connection arriving on the
           specified remote host and port. If the connection is successfully
           opened, a new SSH channel will be opened with data being handled
           by a :class:`SSHTCPSession` object created by `session_factory`.

           Optional arguments include the host and port of the original
           client opening the connection when performing TCP port forwarding.

           By default, this class expects data to be sent and received as
           raw bytes. However, an optional encoding argument can be
           passed in to select the encoding to use, allowing the
           application to send and receive string data. When encoding is
           set, an optional errors argument can be passed in to select
           what Unicode error handling strategy to use.

           Other optional arguments include the SSH receive window size and
           max packet size which default to 2 MB and 32 KB, respectively.

           :param session_factory:
               A `callable` which returns an :class:`SSHClientSession` object
               that will be created to handle activity on this session
           :param remote_host:
               The hostname or address the connection was received on
           :param remote_port:
               The port number the connection was received on
           :param orig_host: (optional)
               The hostname or address of the client requesting the connection
           :param orig_port: (optional)
               The port number of the client requesting the connection
           :param encoding: (optional)
               The Unicode encoding to use for data exchanged on the connection
           :param errors: (optional)
               The error handling strategy to apply on encode/decode errors
           :param window: (optional)
               The receive window size for this session
           :param max_pktsize: (optional)
               The maximum packet size for this session
           :type session_factory: `callable`
           :type remote_host: `str`
           :type remote_port: `int`
           :type orig_host: `str`
           :type orig_port: `int`
           :type encoding: `str`
           :type errors: `str`
           :type window: `int`
           :type max_pktsize: `int`

           :returns: an :class:`SSHTCPChannel` and :class:`SSHTCPSession`

        """

        self.logger.info('Opening forwarded TCP connection to %s',
                         (remote_host, remote_port))
        self.logger.info('  Client address: %s', (orig_host, orig_port))

        chan = self.create_tcp_channel(encoding, errors, window, max_pktsize)

        session = await chan.accept(session_factory, remote_host,
                                    remote_port, orig_host, orig_port)

        return chan, session

    async def open_connection(self, *args, **kwargs):
        """Open an SSH TCP forwarded connection

           This method is a coroutine wrapper around :meth:`create_connection`
           designed to provide a "high-level" stream interface for creating
           an SSH TCP forwarded connection. Instead of taking a
           `session_factory` argument for constructing an object which will
           handle activity on the session via callbacks, it returns
           :class:`SSHReader` and :class:`SSHWriter` objects which can be
           used to perform I/O on the connection.

           With the exception of `session_factory`, all of the arguments
           to :meth:`create_connection` are supported and have the same
           meaning here.

           :returns: an :class:`SSHReader` and :class:`SSHWriter`

        """

        chan, session = await self.create_connection(SSHTCPStreamSession,
                                                     *args, **kwargs)

        return SSHReader(session, chan), SSHWriter(session, chan)

    async def create_unix_connection(self, session_factory, remote_path, *,
                                     encoding=None, errors='strict',
                                     window=_DEFAULT_WINDOW,
                                     max_pktsize=_DEFAULT_MAX_PKTSIZE):
        """Create an SSH UNIX domain socket forwarded connection

           This method is a coroutine which can be called to notify the
           client about a new inbound UNIX domain socket connection arriving
           on the specified remote path. If the connection is successfully
           opened, a new SSH channel will be opened with data being handled
           by a :class:`SSHUNIXSession` object created by `session_factory`.

           By default, this class expects data to be sent and received as
           raw bytes. However, an optional encoding argument can be
           passed in to select the encoding to use, allowing the
           application to send and receive string data. When encoding is
           set, an optional errors argument can be passed in to select
           what Unicode error handling strategy to use.

           Other optional arguments include the SSH receive window size and
           max packet size which default to 2 MB and 32 KB, respectively.

           :param session_factory:
               A `callable` which returns an :class:`SSHClientSession` object
               that will be created to handle activity on this session
           :param remote_path:
               The path the connection was received on
           :param encoding: (optional)
               The Unicode encoding to use for data exchanged on the connection
           :param errors: (optional)
               The error handling strategy to apply on encode/decode errors
           :param window: (optional)
               The receive window size for this session
           :param max_pktsize: (optional)
               The maximum packet size for this session
           :type session_factory: `callable`
           :type remote_path: `str`
           :type encoding: `str`
           :type errors: `str`
           :type window: `int`
           :type max_pktsize: `int`

           :returns: an :class:`SSHTCPChannel` and :class:`SSHUNIXSession`

        """

        self.logger.info('Opening forwarded UNIX connection to %s', remote_path)

        chan = self.create_unix_channel(encoding, errors, window, max_pktsize)

        session = await chan.accept(session_factory, remote_path)

        return chan, session

    async def open_unix_connection(self, *args, **kwargs):
        """Open an SSH UNIX domain socket forwarded connection

           This method is a coroutine wrapper around
           :meth:`create_unix_connection` designed to provide a "high-level"
           stream interface for creating an SSH UNIX domain socket forwarded
           connection. Instead of taking a `session_factory` argument for
           constructing an object which will handle activity on the session
           via callbacks, it returns :class:`SSHReader` and :class:`SSHWriter`
           objects which can be used to perform I/O on the connection.

           With the exception of `session_factory`, all of the arguments
           to :meth:`create_unix_connection` are supported and have the same
           meaning here.

           :returns: an :class:`SSHReader` and :class:`SSHWriter`

        """

        chan, session = \
            await self.create_unix_connection(SSHUNIXStreamSession,
                                              *args, **kwargs)

        return SSHReader(session, chan), SSHWriter(session, chan)

    async def create_x11_connection(self, session_factory, orig_host='',
                                    orig_port=0, *, window=_DEFAULT_WINDOW,
                                    max_pktsize=_DEFAULT_MAX_PKTSIZE):
        """Create an SSH X11 forwarded connection"""

        self.logger.info('Opening forwarded X11 connection')

        chan = self.create_x11_channel(window, max_pktsize)

        session = await chan.open(session_factory, orig_host, orig_port)

        return chan, session

    async def create_agent_connection(self, session_factory, *,
                                      window=_DEFAULT_WINDOW,
                                      max_pktsize=_DEFAULT_MAX_PKTSIZE):
        """Create a forwarded ssh-agent connection back to the client"""

        if not self._agent_listener:
            raise ChannelOpenError(OPEN_ADMINISTRATIVELY_PROHIBITED,
                                   'Agent forwarding not permitted')

        self.logger.info('Opening forwarded agent connection')

        chan = self.create_agent_channel(window, max_pktsize)

        session = await chan.open(session_factory)

        return chan, session

    async def open_agent_connection(self):
        """Open a forwarded ssh-agent connection back to the client"""

        chan, session = \
            await self.create_agent_connection(SSHUNIXStreamSession)

        return SSHReader(session, chan), SSHWriter(session, chan)


class SSHConnectionOptions(Options):
    """SSH connection options"""

    def __init__(self, options=None, **kwargs):
        last_config = options.config if options else None
        super().__init__(options=options, last_config=last_config, **kwargs)

    # pylint: disable=arguments-differ
    def prepare(self, config, protocol_factory, version, host, port, tunnel,
                proxy_command, family, local_addr, tcp_keepalive, kex_algs,
                encryption_algs, mac_algs, compression_algs, signature_algs,
                host_based_auth, public_key_auth, kbdint_auth, password_auth,
                x509_trusted_certs, x509_trusted_cert_paths, x509_purposes,
                rekey_bytes, rekey_seconds, login_timeout, keepalive_interval,
                keepalive_count_max):
        """Prepare common connection configuration options"""

        self.config = config
        self.protocol_factory = protocol_factory
        self.version = _validate_version(version)

        self.host = config.get('Hostname', host)
        self.port = port if port != () else config.get('Port', DEFAULT_PORT)

        self.tunnel = tunnel if tunnel != () else config.get('ProxyJump')

        if isinstance(proxy_command, str):
            proxy_command = shlex.split(proxy_command)

        self.proxy_command = proxy_command or config.get('ProxyCommand')

        self.family = family if family != () else \
            config.get('AddressFamily', socket.AF_UNSPEC)
        self.local_addr = local_addr if local_addr != () else \
            (config.get('BindAddress'), 0)
        self.tcp_keepalive = tcp_keepalive if tcp_keepalive != () else \
            config.get('TCPKeepAlive', True)

        self.kex_algs, self.encryption_algs, self.mac_algs, \
        self.compression_algs, self.signature_algs = \
            _validate_algs(config, kex_algs, encryption_algs, mac_algs,
                           compression_algs, signature_algs,
                           x509_trusted_certs is not None)

        if host_based_auth == ():
            host_based_auth = config.get('HostbasedAuthentication', True)

        if public_key_auth == ():
            public_key_auth = config.get('PubkeyAuthentication', True)

        if kbdint_auth == ():
            kbdint_auth = \
                config.get('KbdInteractiveAuthentication',
                           config.get('ChallengeResponseAuthentication', True))

        if password_auth == ():
            password_auth = config.get('PasswordAuthentication', True)

        self.host_based_auth = host_based_auth
        self.public_key_auth = public_key_auth
        self.kbdint_auth = kbdint_auth
        self.password_auth = password_auth

        if x509_trusted_certs is not None:
            x509_trusted_certs = load_certificates(x509_trusted_certs)

        if x509_trusted_cert_paths:
            for path in x509_trusted_cert_paths:
                if not Path(path).is_dir():
                    raise ValueError('Path not a directory: ' + str(path))

        self.x509_trusted_certs = x509_trusted_certs
        self.x509_trusted_cert_paths = x509_trusted_cert_paths
        self.x509_purposes = x509_purposes

        config_rekey_bytes, config_rekey_seconds = \
            config.get('RekeyLimit', ((), ()))

        if rekey_bytes == ():
            rekey_bytes = config_rekey_bytes

        if rekey_bytes == ():
            rekey_bytes = _DEFAULT_REKEY_BYTES
        elif isinstance(rekey_bytes, str):
            rekey_bytes = parse_byte_count(rekey_bytes)

        if rekey_bytes <= 0:
            raise ValueError('Rekey bytes cannot be negative or zero')

        if rekey_seconds == ():
            rekey_seconds = config_rekey_seconds

        if rekey_seconds == ():
            rekey_seconds = _DEFAULT_REKEY_SECONDS
        elif isinstance(rekey_seconds, str):
            rekey_seconds = parse_time_interval(rekey_seconds)

        if rekey_seconds and rekey_seconds <= 0:
            raise ValueError('Rekey seconds cannot be negative or zero')

        if isinstance(login_timeout, str):
            login_timeout = parse_time_interval(login_timeout)

        if login_timeout and login_timeout < 0:
            raise ValueError('Login timeout cannot be negative')

        if isinstance(keepalive_interval, str):
            keepalive_interval = parse_time_interval(keepalive_interval)

        if keepalive_interval and keepalive_interval < 0:
            raise ValueError('Keepalive interval cannot be negative')

        if keepalive_count_max <= 0:
            raise ValueError('Keepalive count max cannot be negative or zero')

        self.rekey_bytes = int(rekey_bytes)
        self.rekey_seconds = rekey_seconds
        self.login_timeout = login_timeout
        self.keepalive_interval = keepalive_interval
        self.keepalive_count_max = keepalive_count_max


class SSHClientConnectionOptions(SSHConnectionOptions):
    """SSH client connection options

       The following options are available to control the establishment
       of SSH client connections:

       :param client_factory: (optional)
           A `callable` which returns an :class:`SSHClient` object that will
           be created for each new connection.
       :param proxy_command: (optional)
           A string or list of strings specifying a command and arguments
           to run to make a connection to the SSH server. Data will be
           forwarded to this process over stdin/stdout instead of opening a
           TCP connection. If specified as a string, standard shell quoting
           will be applied when splitting the command and its arguments.
       :param known_hosts: (optional)
           The list of keys which will be used to validate the server host
           key presented during the SSH handshake. If this is not specified,
           the keys will be looked up in the file :file:`.ssh/known_hosts`.
           If this is explicitly set to `None`, server host key validation
           will be disabled.
       :param host_key_alias: (optional)
           An alias to use instead of the real host name when looking up a host
           key in known_hosts and when validating host certificates.
       :param server_host_key_algs: (optional)
           A list of server host key algorithms to use instead of the
           default of those present in known_hosts when performing the SSH
           handshake, taken from :ref:`server host key algorithms
           <PublicKeyAlgs>`. This is useful when using the
           validate_host_public_key callback to validate server host keys,
           since AsyncSSH can not determine which server host key algorithms
           are preferred. This argument can also be set to 'default' to
           specify that the client should always send its default list of
           supported algorithms to avoid leaking information about what
           algorithms are present for the server in known_hosts.

               .. note:: The 'default' keyword should be used with
                         caution, as it can result in a host key mismatch
                         if the client trusts only a subset of the host
                         keys the server might return.
       :param x509_trusted_certs: (optional)
           A list of certificates which should be trusted for X.509 server
           certificate authentication. If no trusted certificates are
           specified, an attempt will be made to load them from the file
           :file:`.ssh/ca-bundle.crt`. If this argument is explicitly set
           to `None`, X.509 server certificate authentication will not
           be performed.

               .. note:: X.509 certificates to trust can also be provided
                         through a :ref:`known_hosts <KnownHosts>` file
                         if they are converted into OpenSSH format.
                         This allows their trust to be limited to only
                         specific host names.
       :param x509_trusted_cert_paths: (optional)
           A list of path names to "hash directories" containing certificates
           which should be trusted for X.509 server certificate authentication.
           Each certificate should be in a separate file with a name of the
           form *hash.number*, where *hash* is the OpenSSL hash value of the
           certificate subject name and *number* is an integer counting up
           from zero if multiple certificates have the same hash. If no
           paths are specified, an attempt with be made to use the directory
           :file:`.ssh/crt` as a certificate hash directory.
       :param x509_purposes: (optional)
           A list of purposes allowed in the ExtendedKeyUsage of a
           certificate used for X.509 server certificate authentication,
           defulting to 'secureShellServer'. If this argument is explicitly
           set to `None`, the server certificate's ExtendedKeyUsage will
           not be checked.
       :param username: (optional)
           Username to authenticate as on the server. If not specified,
           the currently logged in user on the local machine will be used.
       :param password: (optional)
           The password to use for client password authentication or
           keyboard-interactive authentication which prompts for a password.
           If this is not specified, client password authentication will
           not be performed.
       :param client_host_keysign: (optional)
           Whether or not to use `ssh-keysign` to sign host-based
           authentication requests. If set to `True`, an attempt will be
           made to find `ssh-keysign` in its typical locations. If set to
           a string, that will be used as the `ssh-keysign` path. When set,
           client_host_keys should be a list of public keys. Otherwise,
           client_host_keys should be a list of private keys with optional
           paired certificates.
       :param client_host_keys: (optional)
           A list of keys to use to authenticate this client via host-based
           authentication. If `client_host_keysign` is set and no host keys
           or certificates are specified, an attempt will be made to find
           them in their typical locations. If `client_host_keysign` is
           not set, host private keys must be specified explicitly or
           host-based authentication will not be performed.
       :param client_host_certs: (optional)
           A list of optional certificates which can be paired with the
           provided client host keys.
       :param client_host: (optional)
           The local hostname to use when performing host-based
           authentication. If not specified, the hostname associated with
           the local IP address of the SSH connection will be used.
       :param client_username: (optional)
           The local username to use when performing host-based
           authentication. If not specified, the username of the currently
           logged in user will be used.
       :param client_keys: (optional)
           A list of keys which will be used to authenticate this client
           via public key authentication. If no client keys are specified,
           an attempt will be made to get them from an ssh-agent process
           and/or load them from the files :file:`.ssh/id_ed25519_sk`,
           :file:`.ssh/id_ecdsa_sk`, :file:`.ssh/id_ed448`,
           :file:`.ssh/id_ed25519`, :file:`.ssh/id_ecdsa`,
           :file:`.ssh/id_rsa`, and :file:`.ssh/id_dsa` in the user's
           home directory, with optional certificates loaded from the files
           :file:`.ssh/id_ed25519_sk-cert.pub`,
           :file:`.ssh/id_ecdsa_sk-cert.pub`, :file:`.ssh/id_ed448-cert.pub`,
           :file:`.ssh/id_ed25519-cert.pub`, :file:`.ssh/id_ecdsa-cert.pub`,
           :file:`.ssh/id_rsa-cert.pub`, and :file:`.ssh/id_dsa-cert.pub`.
           If this argument is explicitly set to `None`, client public key
           authentication will not be performed.
       :param client_certs: (optional)
           A list of optional certificates which can be paired with the
           provided client keys.
       :param passphrase: (optional)
           The passphrase to use to decrypt client keys when loading them,
           if they are encrypted. If this is not specified, only unencrypted
           client keys can be loaded. If the keys passed into client_keys
           are already loaded, this argument is ignored.
       :param ignore_encrypted: (optional)
           Whether or not to ignore encrypted keys when no passphrase is
           provided. This is intended to allow encrypted keys specified via
           the IdentityFile config option to be ignored if a passphrase
           is not specified, loading only unencrypted local keys. Note
           that encrypted keys loaded into an SSH agent can still be used
           when this option is set.
       :param host_based_auth: (optional)
           Whether or not to allow host-based authentication. By default,
           host-based authentication is enabled if client host keys are
           made available.
       :param public_key_auth: (optional)
           Whether or not to allow public key authentication. By default,
           public key authentication is enabled if client keys are made
           available.
       :param kbdint_auth: (optional)
           Whether or not to allow keyboard-interactive authentication. By
           default, keyboard-interactive authentication is enabled if a
           password is specified or if callbacks to respond to challenges
           are made available.
       :param password_auth: (optional)
           Whether or not to allow password authentication. By default,
           password authentication is enabled if a password is specified
           or if callbacks to provide a password are made availble.
       :param gss_host: (optional)
           The principal name to use for the host in GSS key exchange and
           authentication. If not specified, this value will be the same
           as the `host` argument. If this argument is explicitly set to
           `None`, GSS key exchange and authentication will not be performed.
       :param gss_kex: (optional)
           Whether or not to allow GSS key exchange. By default, GSS
           key exchange is enabled.
       :param gss_auth: (optional)
           Whether or not to allow GSS authentication. By default, GSS
           authentication is enabled.
       :param gss_delegate_creds: (optional)
           Whether or not to forward GSS credentials to the server being
           accessed. By default, GSS credential delegation is disabled.
       :param preferred_auth:
           A list of authentication methods the client should attempt to
           use in order of preference. By default, the preferred list is
           gssapi-keyex, gssapi-with-mic, hostbased, publickey,
           keyboard-interactive, and then password. This list may be
           limited by which auth methods are implemented by the client
           and which methods the server accepts.
       :param disable_trivial_auth: (optional)
           Whether or not to allow "trivial" forms of auth where the
           client is not actually challenged for credentials. Setting
           this will cause the connection to fail if a server does not
           perform some non-trivial form of auth during the initial
           SSH handshake. If not specified, all forms of auth supported
           by the server are allowed, including none.
       :param agent_path: (optional)
           The path of a UNIX domain socket to use to contact an ssh-agent
           process which will perform the operations needed for client
           public key authentication, or the :class:`SSHServerConnection`
           to use to forward ssh-agent requests over. If this is not
           specified and the environment variable `SSH_AUTH_SOCK` is
           set, its value will be used as the path. If `client_keys`
           is specified or this argument is explicitly set to `None`,
           an ssh-agent will not be used.
       :param agent_identities: (optional)
           A list of identities used to restrict which SSH agent keys may
           be used. These may be specified as byte strings in binary SSH
           format or as public keys or certificates (*see*
           :ref:`SpecifyingPublicKeys` and :ref:`SpecifyingCertificates`).
           If set to `None`, all keys loaded into the SSH agent will be
           made available for use. This is the default.
       :param agent_forwarding: (optional)
           Whether or not to allow forwarding of ssh-agent requests from
           processes running on the server. By default, ssh-agent forwarding
           requests from the server are not allowed.
       :param pkcs11_provider: (optional)
           The path of a shared library which should be used as a PKCS#11
           provider for accessing keys on PIV security tokens. By default,
           no local security tokens will be accessed.
       :param pkcs11_pin: (optional)
           The PIN to use when accessing security tokens via PKCS#11.

               .. note:: If your application opens multiple SSH connections
                         using PKCS#11 keys, you should consider calling
                         :func:`load_pkcs11_keys` explicitly instead of
                         using these arguments. This allows you to pay
                         the cost of loading the key information from the
                         security tokens only once. You can then pass the
                         returned keys via the `client_keys` argument to
                         any calls that need them.

                         Calling :func:`load_pkcs11_keys` explicitly also
                         gives you the ability to load keys from multiple
                         tokens with different PINs and to select which
                         tokens to load keys from and which keys on those
                         tokens to load.

       :param client_version: (optional)
           An ASCII string to advertise to the SSH server as the version of
           this client, defaulting to `'AsyncSSH'` and its version number.
       :param kex_algs: (optional)
           A list of allowed key exchange algorithms in the SSH handshake,
           taken from :ref:`key exchange algorithms <KexAlgs>`.
       :param encryption_algs: (optional)
           A list of encryption algorithms to use during the SSH handshake,
           taken from :ref:`encryption algorithms <EncryptionAlgs>`.
       :param mac_algs: (optional)
           A list of MAC algorithms to use during the SSH handshake, taken
           from :ref:`MAC algorithms <MACAlgs>`.
       :param compression_algs: (optional)
           A list of compression algorithms to use during the SSH handshake,
           taken from :ref:`compression algorithms <CompressionAlgs>`, or
           `None` to disable compression.
       :param signature_algs: (optional)
           A list of public key signature algorithms to use during the SSH
           handshake, taken from :ref:`signature algorithms <SignatureAlgs>`.
       :param rekey_bytes: (optional)
           The number of bytes which can be sent before the SSH session
           key is renegotiated. This defaults to 1 GB.
       :param rekey_seconds: (optional)
           The maximum time in seconds before the SSH session key is
           renegotiated. This defaults to 1 hour.
       :param login_timeout: (optional)
           The maximum time in seconds allowed for authentication to
           complete, defaulting to 2 minutes. Setting this to 0 will
           disable the login timeout.
       :param keepalive_interval: (optional)
           The time in seconds to wait before sending a keepalive message
           if no data has been received from the server. This defaults to
           0, which disables sending these messages.
       :param keepalive_count_max: (optional)
           The maximum number of keepalive messages which will be sent
           without getting a response before disconnecting from the
           server. This defaults to 3, but only applies when
           keepalive_interval is non-zero.
       :param command: (optional)
           The default remote command to execute on client sessions.
           An interactive shell is started if no command or subsystem is
           specified.
       :param subsystem: (optional)
           The default remote subsystem to start on client sessions.
       :param env: (optional)
           The  default environment variables to set for client sessions.
           Keys and values passed in here will be converted to Unicode
           strings encoded as UTF-8 (ISO 10646) for transmission.

           .. note:: Many SSH servers restrict which environment
                     variables a client is allowed to set. The
                     server's configuration may need to be edited
                     before environment variables can be
                     successfully set in the remote environment.
       :param send_env: (optional)
           A list of environment variable names to pull from
           `os.environ` and set by default for client sessions. Wildcards
           patterns using `'*'` and `'?'` are allowed, and all variables
           with matching names will be sent with whatever value is set in
           the local environment. If a variable is present in both env
           and send_env, the value from env will be used.
       :param request_pty: (optional)
           Whether or not to request a pseudo-terminal (PTY) by default for
           client sessions. This defaults to `True`, which means to request
           a PTY whenever the `term_type` is set. Other possible values
           include `False` to never request a PTY, `'force'` to always
           request a PTY even without `term_type` being set, or `'auto'`
           to request a TTY when `term_type` is set but only when starting
           an interactive shell.
       :param term_type: (optional)
           The default terminal type to set for client sessions.
       :param term_size: (optional)
           The terminal width and height in characters and optionally
           the width and height in pixels to set for client sessions.
       :param term_modes: (optional)
           POSIX terminal modes to set for client sessions, where keys are
           taken from :ref:`POSIX terminal modes <PTYModes>` with values
           defined in section 8 of :rfc:`RFC 4254 <4254#section-8>`.
       :param x11_forwarding: (optional)
           Whether or not to request X11 forwarding for client sessions,
           defaulting to `False`. If set to `True`, X11 forwarding will be
           requested and a failure will raise :exc:`ChannelOpenError`. It
           can also be set to `'ignore_failure'` to attempt X11 forwarding
           but ignore failures.
       :param x11_display: (optional)
           The display that X11 connections should be forwarded to,
           defaulting to the value in the environment variable `DISPLAY`.
       :param x11_auth_path: (optional)
           The path to the Xauthority file to read X11 authentication
           data from, defaulting to the value in the environment variable
           `XAUTHORITY` or the file :file:`.Xauthority` in the user's
           home directory if that's not set.
       :param x11_single_connection: (optional)
           Whether or not to limit X11 forwarding to a single connection,
           defaulting to `False`.
       :param encoding: (optional)
           The default Unicode encoding to use for data exchanged on client
           sessions.
       :param errors: (optional)
           The default error handling strategy to apply on Unicode
           encode/decode errors.
       :param window: (optional)
           The default receive window size to set for client sessions.
       :param max_pktsize: (optional)
           The default maximum packet size to set for client sessions.
       :param config: (optional)
           Paths to OpenSSH client configuration files to load. This
           configuration will be used as a fallback to override the
           defaults for settings which are not explcitly specified using
           AsyncSSH's configuration options.

               .. note:: Specifying configuration files when creating an
                         :class:`SSHClientConnectionOptions` object will
                         cause the config file to be read and parsed at
                         the time of creation of the object, including
                         evaluation of any conditional blocks. If you want
                         the config to be parsed for every new connection,
                         this argument should be added to the connect or
                         listen calls instead. However, if you want to
                         save the parsing overhead and your configuration
                         doesn't depend on conditions that would change
                         between calls, this argument may be an option.
       :param options: (optional)
           A previous set of options to use as the base to incrementally
           build up a configuration. When an option is not explicitly
           specified, its value will be pulled from this options object
           (if present) before falling back to the default value.
       :type client_factory: `callable`
       :type proxy_command: `str` or `list` of `str`
       :type known_hosts: *see* :ref:`SpecifyingKnownHosts`
       :type host_key_alias: `str`
       :type server_host_key_algs: `str` or `list` of `str`
       :type x509_trusted_certs: *see* :ref:`SpecifyingCertificates`
       :type x509_trusted_cert_paths: `list` of `str`
       :type x509_purposes: *see* :ref:`SpecifyingX509Purposes`
       :type username: `str`
       :type password: `str`
       :type client_host_keysign: `bool` or `str`
       :type client_host_keys:
           *see* :ref:`SpecifyingPrivateKeys` or :ref:`SpecifyingPublicKeys`
       :type client_host_certs: *see* :ref:`SpecifyingCertificates`
       :type client_host: `str`
       :type client_username: `str`
       :type client_keys: *see* :ref:`SpecifyingPrivateKeys`
       :type client_certs: *see* :ref:`SpecifyingCertificates`
       :type passphrase: `str`
       :type ignore_encrypted: `bool`
       :type host_based_auth: `bool`
       :type public_key_auth: `bool`
       :type kbdint_auth: `bool`
       :type password_auth: `bool`
       :type gss_host: `str`
       :type gss_kex: `bool`
       :type gss_auth: `bool`
       :type gss_delegate_creds: `bool`
       :type preferred_auth: `str` or `list` of `str`
       :type disable_trivial_auth: `bool`
       :type agent_path: `str` or :class:`SSHServerConnection`
       :type agent_identities:
           *see* :ref:`SpecifyingPublicKeys` and :ref:`SpecifyingCertificates`
       :type agent_forwarding: `bool`
       :type pkcs11_provider: `str`
       :type pkcs11_pin: `str`
       :type client_version: `str`
       :type kex_algs: `str` or `list` of `str`
       :type encryption_algs: `str` or `list` of `str`
       :type mac_algs: `str` or `list` of `str`
       :type compression_algs: `str` or `list` of `str`
       :type signature_algs: `str` or `list` of `str`
       :type rekey_bytes: *see* :ref:`SpecifyingByteCounts`
       :type rekey_seconds: *see* :ref:`SpecifyingTimeIntervals`
       :type login_timeout: *see* :ref:`SpecifyingTimeIntervals`
       :type keepalive_interval: *see* :ref:`SpecifyingTimeIntervals`
       :type keepalive_count_max: `int`
       :type command: `str`
       :type subsystem: `str`
       :type env: `dict`
       :type send_env: `str` or `list` of `str`
       :type request_pty: `bool`, `'force'`, or `'auto'`
       :type term_type: `str`
       :type term_size: `tuple` of 2 or 4 `int` values
       :type term_modes: `dict`
       :type x11_forwarding: `bool` or `'ignore_failure'`
       :type x11_display: `str`
       :type x11_auth_path: `str`
       :type x11_single_connection: `bool`
       :type encoding: `str`
       :type errors: `str`
       :type window: `int`
       :type max_pktsize: `int`
       :type config: `list` of `str`
       :type options: :class:`SSHClientConnectionOptions`

    """

    # pylint: disable=arguments-differ
    def prepare(self, last_config=None, config=(), reload=False,
                client_factory=None, client_version=(), host='', port=(),
                tunnel=(), proxy_command=(), family=(), local_addr=(),
                tcp_keepalive=(), kex_algs=(), encryption_algs=(), mac_algs=(),
                compression_algs=(), signature_algs=(), host_based_auth=(),
                public_key_auth=(), kbdint_auth=(), password_auth=(),
                x509_trusted_certs=(), x509_trusted_cert_paths=(),
                x509_purposes='secureShellServer', rekey_bytes=(),
                rekey_seconds=(), login_timeout=(), keepalive_interval=(),
                keepalive_count_max=(), known_hosts=(), host_key_alias=None,
                server_host_key_algs=(), username=(), password=None,
                client_host_keysign=(), client_host_keys=None,
                client_host_certs=(), client_host=None, client_username=(),
                client_keys=(), client_certs=(), passphrase=None,
                ignore_encrypted=False, gss_host=(), gss_kex=(), gss_auth=(),
                gss_delegate_creds=(), preferred_auth=(),
                disable_trivial_auth=False, agent_path=(),
                agent_identities=(), agent_forwarding=(), pkcs11_provider=(),
                pkcs11_pin=None, command=(), subsystem=None, env=(),
                send_env=(), request_pty=(), term_type=None, term_size=None,
                term_modes=None, x11_forwarding=(), x11_display=None,
                x11_auth_path=None, x11_single_connection=False,
                encoding='utf-8', errors='strict', window=_DEFAULT_WINDOW,
                max_pktsize=_DEFAULT_MAX_PKTSIZE):
        """Prepare client connection configuration options"""

        try:
            local_username = getpass.getuser()
        except KeyError:
            raise ValueError('Unknown local username: set one of '
                             'LOGNAME, USER, LNAME, or USERNAME in '
                             'the environment') from None

        if config == () and not last_config:
            default_config = Path('~', '.ssh', 'config').expanduser()
            config = [default_config] if os.access(default_config,
                                                   os.R_OK) else []

        config = SSHClientConfig.load(last_config, config, reload,
                                      local_username, username, host, port)

        if x509_trusted_certs == ():
            default_x509_certs = Path('~', '.ssh', 'ca-bundle.crt').expanduser()

            if os.access(default_x509_certs, os.R_OK):
                x509_trusted_certs = str(default_x509_certs)

        if x509_trusted_cert_paths == ():
            default_x509_cert_path = Path('~', '.ssh', 'crt').expanduser()

            if default_x509_cert_path.is_dir():
                x509_trusted_cert_paths = [str(default_x509_cert_path)]

        if login_timeout == ():
            login_timeout = config.get('ConnectTimeout',
                                       _DEFAULT_LOGIN_TIMEOUT)

        if keepalive_interval == ():
            keepalive_interval = config.get('ServerAliveInterval',
                                            _DEFAULT_KEEPALIVE_INTERVAL)

        if keepalive_count_max == ():
            keepalive_count_max = config.get('ServerAliveCountMax',
                                             _DEFAULT_KEEPALIVE_COUNT_MAX)

        super().prepare(config, client_factory or SSHClient, client_version,
                        host, port, tunnel, proxy_command, family, local_addr,
                        tcp_keepalive, kex_algs, encryption_algs, mac_algs,
                        compression_algs, signature_algs, host_based_auth,
                        public_key_auth, kbdint_auth, password_auth,
                        x509_trusted_certs, x509_trusted_cert_paths,
                        x509_purposes, rekey_bytes, rekey_seconds,
                        login_timeout, keepalive_interval, keepalive_count_max)

        if known_hosts == ():
            known_hosts = (config.get('UserKnownHostsFile', []) + \
                           config.get('GlobalKnownHostsFile', [])) or ()

        self.known_hosts = known_hosts
        self.host_key_alias = host_key_alias or config.get('HostKeyAlias')

        self.server_host_key_algs = server_host_key_algs

        # Just validate the input here -- the actual server host key
        # selection is done later, after the known_hosts lookup is done.
        _select_host_key_algs(server_host_key_algs,
                              config.get('HostKeyAlgorithms', ()))

        if username == ():
            username = config.get('User', local_username)

        self.username = saslprep(username)
        self.password = password

        if client_host_keysign == ():
            client_host_keysign = config.get('EnableSSHKeySign', False)

        if client_host_keysign:
            client_host_keysign = find_keysign(client_host_keysign)

            if client_host_keys:
                client_host_keys = load_public_keys(client_host_keys)
            else:
                client_host_keys = load_default_host_public_keys()
        else:
            client_host_keys = load_keypairs(client_host_keys, passphrase,
                                             client_host_certs)

        if client_username == ():
            client_username = local_username

        self.client_host_keysign = client_host_keysign
        self.client_host_keys = client_host_keys
        self.client_host = client_host
        self.client_username = saslprep(client_username)

        if gss_kex == ():
            gss_kex = config.get('GSSAPIKeyExchange', True)

        if gss_auth == ():
            gss_auth = config.get('GSSAPIAuthentication', True)

        if gss_delegate_creds == ():
            gss_delegate_creds = config.get('GSSAPIDelegateCredentials', False)

        self.gss_host = gss_host
        self.gss_kex = gss_kex
        self.gss_auth = gss_auth
        self.gss_delegate_creds = gss_delegate_creds

        if preferred_auth == ():
            preferred_auth = config.get('PreferredAuthentications', ())

        if isinstance(preferred_auth, str):
            preferred_auth = preferred_auth.split(',')

        self.preferred_auth = preferred_auth

        self.disable_trivial_auth = disable_trivial_auth

        if agent_path == ():
            agent_path = config.get('IdentityAgent', ())

        if agent_path == ():
            agent_path = os.environ.get('SSH_AUTH_SOCK', ())

        if agent_path:
            agent_path = str(Path(agent_path).expanduser())

        if pkcs11_provider == ():
            pkcs11_provider = config.get('PKCS11Provider')

        self.agent_path = None
        self.pkcs11_provider = None
        self.pkcs11_pin = None

        if client_keys == ():
            client_keys = config.get('IdentityFile', ())

        if client_certs == ():
            client_certs = config.get('CertificateFile', ())

        identities_only = config.get('IdentitiesOnly')

        if agent_identities == ():
            if identities_only:
                agent_identities = client_keys
            else:
                agent_identities = None

        if agent_identities:
            self.agent_identities = load_identities(agent_identities,
                                                    identities_only)
        elif agent_identities == ():
            self.agent_identities = load_default_identities()
        else:
            self.agent_identities = None

        if client_keys:
            self.client_keys = load_keypairs(client_keys, passphrase,
                                             client_certs, identities_only,
                                             ignore_encrypted)
        else:
            if client_keys == ():
                client_keys = load_default_keypairs(passphrase, client_certs)

            self.client_keys = client_keys

        if client_keys is not None:
            self.agent_path = agent_path
            self.pkcs11_provider = pkcs11_provider
            self.pkcs11_pin = pkcs11_pin

        if agent_forwarding == ():
            agent_forwarding = config.get('ForwardAgent', False)

        self.agent_forward_path = agent_path if agent_forwarding else None

        if command == ():
            command = config.get('RemoteCommand')

        if env == ():
            env = config.get('SetEnv')

        if send_env == ():
            send_env = config.get('SendEnv')

        if request_pty == ():
            request_pty = config.get('RequestTTY', True)

        if x11_forwarding == ():
            x11_forwarding = config.get('ForwardX11Trusted') and \
                'ignore_failure'

        self.command = command
        self.subsystem = subsystem
        self.env = env
        self.send_env = send_env
        self.request_pty = request_pty
        self.term_type = term_type
        self.term_size = term_size
        self.term_modes = term_modes
        self.x11_forwarding = x11_forwarding
        self.x11_display = x11_display
        self.x11_auth_path = x11_auth_path
        self.x11_single_connection = x11_single_connection
        self.encoding = encoding
        self.errors = errors
        self.window = window
        self.max_pktsize = max_pktsize


class SSHServerConnectionOptions(SSHConnectionOptions):
    """SSH server connection options

       The following options are available to control the acceptance
       of SSH server connections:

       :param server_factory:
           A `callable` which returns an :class:`SSHServer` object that will
           be created for each new connection.
       :param proxy_command: (optional)
           A string or list of strings specifying a command and arguments
           to run when using :func:`connect_reverse` to make a reverse
           direction connection to an SSH client. Data will be forwarded
           to this process over stdin/stdout instead of opening a TCP
           connection. If specified as a string, standard shell quoting
           will be applied when splitting the command and its arguments.
       :param server_host_keys: (optional)
           A list of private keys and optional certificates which can be
           used by the server as a host key. Either this argument or
           `gss_host` must be specified. If this is not specified,
           only GSS-based key exchange will be supported.
       :param server_host_certs: (optional)
           A list of optional certificates which can be paired with the
           provided server host keys.
       :param passphrase: (optional)
           The passphrase to use to decrypt server host keys when loading
           them, if they are encrypted. If this is not specified, only
           unencrypted server host keys can be loaded. If the keys passed
           into server_host_keys are already loaded, this argument is
           ignored.
       :param known_client_hosts: (optional)
           A list of client hosts which should be trusted to perform
           host-based client authentication. If this is not specified,
           host-based client authentication will be not be performed.
       :param trust_client_host: (optional)
           Whether or not to use the hostname provided by the client
           when performing host-based authentication. By default, the
           client-provided hostname is not trusted and is instead
           determined by doing a reverse lookup of the IP address the
           client connected from.
       :param authorized_client_keys: (optional)
           A list of authorized user and CA public keys which should be
           trusted for certifcate-based client public key authentication.
       :param x509_trusted_certs: (optional)
           A list of certificates which should be trusted for X.509 client
           certificate authentication. If this argument is explicitly set
           to `None`, X.509 client certificate authentication will not
           be performed.

               .. note:: X.509 certificates to trust can also be provided
                         through an :ref:`authorized_keys <AuthorizedKeys>`
                         file if they are converted into OpenSSH format.
                         This allows their trust to be limited to only
                         specific client IPs or user names and allows
                         SSH functions to be restricted when these
                         certificates are used.
       :param x509_trusted_cert_paths: (optional)
           A list of path names to "hash directories" containing certificates
           which should be trusted for X.509 client certificate authentication.
           Each certificate should be in a separate file with a name of the
           form *hash.number*, where *hash* is the OpenSSL hash value of the
           certificate subject name and *number* is an integer counting up
           from zero if multiple certificates have the same hash.
       :param x509_purposes: (optional)
           A list of purposes allowed in the ExtendedKeyUsage of a
           certificate used for X.509 client certificate authentication,
           defulting to 'secureShellClient'. If this argument is explicitly
           set to `None`, the client certificate's ExtendedKeyUsage will
           not be checked.
       :param host_based_auth: (optional)
           Whether or not to allow host-based authentication. By default,
           host-based authentication is enabled if known client host keys
           are specified or if callbacks to validate client host keys
           are made available.
       :param public_key_auth: (optional)
           Whether or not to allow public key authentication. By default,
           public key authentication is enabled if authorized client keys
           are specified or if callbacks to validate client keys are made
           available.
       :param kbdint_auth: (optional)
           Whether or not to allow keyboard-interactive authentication. By
           default, keyboard-interactive authentication is enabled if the
           callbacks to generate challenges are made available.
       :param password_auth: (optional)
           Whether or not to allow password authentication. By default,
           password authentication is enabled if callbacks to validate a
           password are made available.
       :param gss_host: (optional)
           The principal name to use for the host in GSS key exchange and
           authentication. If not specified, the value returned by
           :func:`socket.gethostname` will be used if it is a fully qualified
           name. Otherwise, the value used by :func:`socket.getfqdn` will be
           used. If this argument is explicitly set to `None`, GSS
           key exchange and authentication will not be performed.
       :param gss_kex: (optional)
           Whether or not to allow GSS key exchange. By default, GSS
           key exchange is enabled.
       :param gss_auth: (optional)
           Whether or not to allow GSS authentication. By default, GSS
           authentication is enabled.
       :param allow_pty: (optional)
           Whether or not to allow allocation of a pseudo-tty in sessions,
           defaulting to `True`
       :param line_editor: (optional)
           Whether or not to enable input line editing on sessions which
           have a pseudo-tty allocated, defaulting to `True`
       :param line_history: (int)
           The number of lines of input line history to store in the
           line editor when it is enabled, defaulting to 1000
       :param max_line_length: (int)
           The maximum number of characters allowed in an input line when
           the line editor is enabled, defaulting to 1024
       :param rdns_lookup: (optional)
           Whether or not to perform reverse DNS lookups on the client's
           IP address to enable hostname-based matches in authorized key
           file "from" options and "Match Host" config options, defaulting
           to `False`.
       :param x11_forwarding: (optional)
           Whether or not to allow forwarding of X11 connections back
           to the client when the client supports it, defaulting to `False`
       :param x11_auth_path: (optional)
           The path to the Xauthority file to write X11 authentication
           data to, defaulting to the value in the environment variable
           `XAUTHORITY` or the file :file:`.Xauthority` in the user's
           home directory if that's not set
       :param agent_forwarding: (optional)
           Whether or not to allow forwarding of ssh-agent requests back
           to the client when the client supports it, defaulting to `True`
       :param process_factory: (optional)
           A `callable` or coroutine handler function which takes an AsyncSSH
           :class:`SSHServerProcess` argument that will be called each time a
           new shell, exec, or subsystem other than SFTP is requested by the
           client. If set, this takes precedence over the `session_factory`
           argument.
       :param session_factory: (optional)
           A `callable` or coroutine handler function which takes AsyncSSH
           stream objects for stdin, stdout, and stderr that will be called
           each time a new shell, exec, or subsystem other than SFTP is
           requested by the client. If not specified, sessions are rejected
           by default unless the :meth:`session_requested()
           <SSHServer.session_requested>` method is overridden on the
           :class:`SSHServer` object returned by `server_factory` to make
           this decision.
       :param encoding: (optional)
           The Unicode encoding to use for data exchanged on sessions on
           this server, defaulting to UTF-8 (ISO 10646) format. If `None`
           is passed in, the application can send and receive raw bytes.
       :param errors: (optional)
           The error handling strategy to apply on Unicode encode/decode
           errors of data exchanged on sessions on this server, defaulting
           to 'strict'.
       :param sftp_factory: (optional)
           A `callable` which returns an :class:`SFTPServer` object that
           will be created each time an SFTP session is requested by the
           client, or `True` to use the base :class:`SFTPServer` class
           to handle SFTP requests. If not specified, SFTP sessions are
           rejected by default.
       :param allow_scp: (optional)
           Whether or not to allow incoming scp requests to be accepted.
           This option can only be used in conjunction with `sftp_factory`.
           If not specified, scp requests will be passed as regular
           commands to the `process_factory` or `session_factory`.
           to the client when the client supports it, defaulting to `True`
       :param window: (optional)
           The receive window size for sessions on this server
       :param max_pktsize: (optional)
           The maximum packet size for sessions on this server
       :param server_version: (optional)
           An ASCII string to advertise to SSH clients as the version of
           this server, defaulting to `'AsyncSSH'` and its version number.
       :param kex_algs: (optional)
           A list of allowed key exchange algorithms in the SSH handshake,
           taken from :ref:`key exchange algorithms <KexAlgs>`
       :param encryption_algs: (optional)
           A list of encryption algorithms to use during the SSH handshake,
           taken from :ref:`encryption algorithms <EncryptionAlgs>`
       :param mac_algs: (optional)
           A list of MAC algorithms to use during the SSH handshake, taken
           from :ref:`MAC algorithms <MACAlgs>`
       :param compression_algs: (optional)
           A list of compression algorithms to use during the SSH handshake,
           taken from :ref:`compression algorithms <CompressionAlgs>`, or
           `None` to disable compression
       :param signature_algs: (optional)
           A list of public key signature algorithms to use during the SSH
           handshake, taken from :ref:`signature algorithms <SignatureAlgs>`
       :param rekey_bytes: (optional)
           The number of bytes which can be sent before the SSH session
           key is renegotiated, defaulting to 1 GB
       :param rekey_seconds: (optional)
           The maximum time in seconds before the SSH session key is
           renegotiated, defaulting to 1 hour
       :param login_timeout: (optional)
           The maximum time in seconds allowed for authentication to
           complete, defaulting to 2 minutes. Setting this to 0
           will disable the login timeout.
       :param keepalive_interval: (optional)
           The time in seconds to wait before sending a keepalive message
           if no data has been received from the client. This defaults to
           0, which disables sending these messages.
       :param keepalive_count_max: (optional)
           The maximum number of keepalive messages which will be sent
           without getting a response before disconnecting a client.
           This defaults to 3, but only applies when keepalive_interval is
           non-zero.
       :param tcp_keepalive: (optional)
           Whether or not to enable keepalive probes at the TCP level to
           detect broken connections, defaulting to `True`
       :param config: (optional)
           Paths to OpenSSH server configuration files to load. This
           configuration will be used as a fallback to override the
           defaults for settings which are not explcitly specified using
           AsyncSSH's configuration options.

               .. note:: Specifying configuration files when creating an
                         :class:`SSHServerConnectionOptions` object will
                         cause the config file to be read and parsed at
                         the time of creation of the object, including
                         evaluation of any conditional blocks. If you want
                         the config to be parsed for every new connection,
                         this argument should be added to the connect or
                         listen calls instead. However, if you want to
                         save the parsing overhead and your configuration
                         doesn't depend on conditions that would change
                         between calls, this argument may be an option.
       :param options: (optional)
           A previous set of options to use as the base to incrementally
           build up a configuration. When an option is not explicitly
           specified, its value will be pulled from this options object
           (if present) before falling back to the default value.
       :type server_factory: `callable`
       :type proxy_command: `str` or `list` of `str`
       :type family: `socket.AF_UNSPEC`, `socket.AF_INET`, or `socket.AF_INET6`
       :type server_host_keys: *see* :ref:`SpecifyingPrivateKeys`
       :type server_host_certs: *see* :ref:`SpecifyingCertificates`
       :type passphrase: `str`
       :type known_client_hosts: *see* :ref:`SpecifyingKnownHosts`
       :type trust_client_host: `bool`
       :type authorized_client_keys: *see* :ref:`SpecifyingAuthorizedKeys`
       :type x509_trusted_certs: *see* :ref:`SpecifyingCertificates`
       :type x509_trusted_cert_paths: `list` of `str`
       :type x509_purposes: *see* :ref:`SpecifyingX509Purposes`
       :type host_based_auth: `bool`
       :type public_key_auth: `bool`
       :type kbdint_auth: `bool`
       :type password_auth: `bool`
       :type gss_host: `str`
       :type gss_kex: `bool`
       :type gss_auth: `bool`
       :type allow_pty: `bool`
       :type line_editor: `bool`
       :type line_history: `int`
       :type max_line_length: `int`
       :type rdns_lookup: `bool`
       :type x11_forwarding: `bool`
       :type x11_auth_path: `str`
       :type agent_forwarding: `bool`
       :type process_factory: `callable`
       :type session_factory: `callable`
       :type encoding: `str`
       :type errors: `str`
       :type sftp_factory: `callable`
       :type allow_scp: `bool`
       :type window: `int`
       :type max_pktsize: `int`
       :type server_version: `str`
       :type kex_algs: `str` or `list` of `str`
       :type encryption_algs: `str` or `list` of `str`
       :type mac_algs: `str` or `list` of `str`
       :type compression_algs: `str` or `list` of `str`
       :type signature_algs: `str` or `list` of `str`
       :type rekey_bytes: *see* :ref:`SpecifyingByteCounts`
       :type rekey_seconds: *see* :ref:`SpecifyingTimeIntervals`
       :type login_timeout: *see* :ref:`SpecifyingTimeIntervals`
       :type keepalive_interval: *see* :ref:`SpecifyingTimeIntervals`
       :type keepalive_count_max: `int`
       :type config: `list` of `str`
       :type options: :class:`SSHServerConnectionOptions`

    """

    # pylint: disable=arguments-differ
    def prepare(self, last_config=None, config=(), reload=False,
                accept_addr='', accept_port=0, username='', client_host=None,
                client_addr='', server_factory=None, server_version=(),
                host='', port=(), tunnel=(), proxy_command=(), family=(),
                local_addr=(), tcp_keepalive=(), kex_algs=(),
                encryption_algs=(), mac_algs=(), compression_algs=(),
                signature_algs=(), host_based_auth=(), public_key_auth=(),
                kbdint_auth=(), password_auth=(), x509_trusted_certs=(),
                x509_trusted_cert_paths=(), x509_purposes='secureShellClient',
                rekey_bytes=(), rekey_seconds=(), login_timeout=(),
                keepalive_interval=(), keepalive_count_max=(),
                server_host_keys=(), server_host_certs=(), passphrase=None,
                known_client_hosts=None, trust_client_host=False,
                authorized_client_keys=(), gss_host=(), gss_kex=(),
                gss_auth=(), allow_pty=(), line_editor=True,
                line_history=_DEFAULT_LINE_HISTORY,
                max_line_length=_DEFAULT_MAX_LINE_LENGTH, rdns_lookup=(),
                x11_forwarding=False, x11_auth_path=None, agent_forwarding=(),
                process_factory=None, session_factory=None, encoding='utf-8',
                errors='strict', sftp_factory=None, allow_scp=False,
                window=_DEFAULT_WINDOW, max_pktsize=_DEFAULT_MAX_PKTSIZE):
        """Prepare server connection configuration options"""

        config = SSHServerConfig.load(last_config, config, reload,
                                      accept_addr, accept_port, username,
                                      client_host, client_addr)

        if login_timeout == ():
            login_timeout = config.get('LoginGraceTime',
                                       _DEFAULT_LOGIN_TIMEOUT)

        if keepalive_interval == ():
            keepalive_interval = config.get('ClientAliveInterval',
                                            _DEFAULT_KEEPALIVE_INTERVAL)

        if keepalive_count_max == ():
            keepalive_count_max = config.get('ClientAliveCountMax',
                                             _DEFAULT_KEEPALIVE_COUNT_MAX)

        super().prepare(config, server_factory or SSHServer, server_version,
                        host, port, tunnel, proxy_command, family, local_addr,
                        tcp_keepalive, kex_algs, encryption_algs, mac_algs,
                        compression_algs, signature_algs, host_based_auth,
                        public_key_auth, kbdint_auth, password_auth,
                        x509_trusted_certs, x509_trusted_cert_paths,
                        x509_purposes, rekey_bytes, rekey_seconds,
                        login_timeout, keepalive_interval, keepalive_count_max)

        if server_host_keys == ():
            server_host_keys = config.get('HostKey')

        if server_host_certs == ():
            server_host_certs = config.get('HostCertificate', ())

        server_keys = load_keypairs(server_host_keys, passphrase,
                                    server_host_certs)

        self.server_host_keys = OrderedDict()

        for keypair in server_keys:
            for alg in keypair.host_key_algorithms:
                if alg in self.server_host_keys:
                    raise ValueError('Multiple keys of type %s found' %
                                     alg.decode('ascii'))

                self.server_host_keys[alg] = keypair

        self.known_client_hosts = known_client_hosts
        self.trust_client_host = trust_client_host

        if authorized_client_keys == () and reload:
            authorized_client_keys = config.get('AuthorizedKeysFile')

        if isinstance(authorized_client_keys, (str, list)):
            self.authorized_client_keys = \
                read_authorized_keys(authorized_client_keys)
        else:
            self.authorized_client_keys = authorized_client_keys

        if gss_host == ():
            gss_host = socket.gethostname()

            if '.' not in gss_host:
                gss_host = socket.getfqdn()

        if gss_kex == ():
            gss_kex = config.get('GSSAPIKeyExchange', True)

        if gss_auth == ():
            gss_auth = config.get('GSSAPIAuthentication', True)

        self.gss_host = gss_host
        self.gss_kex = gss_kex
        self.gss_auth = gss_auth

        if not server_keys and not gss_host:
            raise ValueError('No server host keys provided')

        if allow_pty == ():
            allow_pty = config.get('PermitTTY', True)

        if agent_forwarding == ():
            agent_forwarding = config.get('AllowAgentForwarding', True)

        if rdns_lookup == ():
            rdns_lookup = config.get('UseDNS', False)

        self.allow_pty = allow_pty
        self.line_editor = line_editor
        self.line_history = line_history
        self.max_line_length = max_line_length
        self.rdns_lookup = rdns_lookup
        self.x11_forwarding = x11_forwarding
        self.x11_auth_path = x11_auth_path
        self.agent_forwarding = agent_forwarding
        self.process_factory = process_factory
        self.session_factory = session_factory
        self.encoding = encoding
        self.errors = errors
        self.sftp_factory = SFTPServer if sftp_factory is True else sftp_factory
        self.allow_scp = allow_scp
        self.window = window
        self.max_pktsize = max_pktsize


@async_context_manager
async def connect(host, port=(), *, tunnel=(), family=(), flags=0,
                  local_addr=None, config=(), options=None, **kwargs):
    """Make an SSH client connection

       This function is a coroutine which can be run to create an outbound SSH
       client connection to the specified host and port.

       When successful, the following steps occur:

           1. The connection is established and an instance of
              :class:`SSHClientConnection` is created to represent it.
           2. The `client_factory` is called without arguments and should
              return an instance of :class:`SSHClient` or a subclass.
           3. The client object is tied to the connection and its
              :meth:`connection_made() <SSHClient.connection_made>` method
              is called.
           4. The SSH handshake and authentication process is initiated,
              calling methods on the client object if needed.
           5. When authentication completes successfully, the client's
              :meth:`auth_completed() <SSHClient.auth_completed>` method is
              called.
           6. The coroutine returns the :class:`SSHClientConnection`. At
              this point, the connection is ready for sessions to be opened
              or port forwarding to be set up.

       If an error occurs, it will be raised as an exception and the partially
       open connection and client objects will be cleaned up.

       :param host:
           The hostname or address to connect to.
       :param port: (optional)
           The port number to connect to. If not specified, the default
           SSH port is used.
       :param tunnel: (optional)
           An existing SSH client connection that this new connection should
           be tunneled over. If set, a direct TCP/IP tunnel will be opened
           over this connection to the requested host and port rather than
           connecting directly via TCP. A string of the form
           [user@]host[:port] may also be specified, in which case a
           connection will first be made to that host and it will then be
           used as a tunnel.
       :param family: (optional)
           The address family to use when creating the socket. By default,
           the address family is automatically selected based on the host.
       :param flags: (optional)
           The flags to pass to getaddrinfo() when looking up the host address
       :param local_addr: (optional)
           The host and port to bind the socket to before connecting
       :param config: (optional)
           Paths to OpenSSH client configuration files to load. This
           configuration will be used as a fallback to override the
           defaults for settings which are not explcitly specified using
           AsyncSSH's configuration options. If no paths are specified,
           an attempt will be made to load the configuration from the file
           :file:`.ssh/config`. If this argument is explicitly set to
           `None`, no OpenSSH configuration files will be loaded. See
           :ref:`SupportedClientConfigOptions` for details on what
           configuration options are currently supported.
       :param options: (optional)
           Options to use when establishing the SSH client connection. These
           options can be specified either through this parameter or as direct
           keyword arguments to this function.
       :type host: `str`
       :type port: `int`
       :type tunnel: :class:`SSHClientConnection` or `str`
       :type family: `socket.AF_UNSPEC`, `socket.AF_INET`, or `socket.AF_INET6`
       :type flags: flags to pass to :meth:`getaddrinfo() <socket.getaddrinfo>`
       :type local_addr: tuple of `str` and `int`
       :type config: `list` of `str`
       :type options: :class:`SSHClientConnectionOptions`

       :returns: :class:`SSHClientConnection`

    """

    def conn_factory():
        """Return an SSH client connection factory"""

        return SSHClientConnection(loop, options, wait='auth')

    loop = asyncio.get_event_loop()

    options = SSHClientConnectionOptions(options, config=config, host=host,
                                         port=port, tunnel=tunnel,
                                         family=family, local_addr=local_addr,
                                         **kwargs)

    return await _connect(options, loop, flags, conn_factory,
                          'Opening SSH connection to')


@async_context_manager
async def connect_reverse(host, port=(), *, tunnel=(), family=(), flags=0,
                          local_addr=None, config=(), options=None, **kwargs):
    """Create a reverse direction SSH connection

       This function is a coroutine which behaves similar to :func:`connect`,
       making an outbound TCP connection to a remote server. However, instead
       of starting up an SSH client which runs on that outbound connection,
       this function starts up an SSH server, expecting the remote system to
       start up a reverse-direction SSH client.

       Arguments to this function are the same as :func:`connect`, except
       that the `options` are of type :class:`SSHServerConnectionOptions`
       instead of :class:`SSHClientConnectionOptions`.

       :param host:
           The hostname or address to connect to.
       :param port: (optional)
           The port number to connect to. If not specified, the default
           SSH port is used.
       :param tunnel: (optional)
           An existing SSH client connection that this new connection should
           be tunneled over. If set, a direct TCP/IP tunnel will be opened
           over this connection to the requested host and port rather than
           connecting directly via TCP. A string of the form
           [user@]host[:port] may also be specified, in which case a
           connection will first be made to that host and it will then be
           used as a tunnel.
       :param family: (optional)
           The address family to use when creating the socket. By default,
           the address family is automatically selected based on the host.
       :param flags: (optional)
           The flags to pass to getaddrinfo() when looking up the host address
       :param local_addr: (optional)
           The host and port to bind the socket to before connecting
       :param config: (optional)
           Paths to OpenSSH server configuration files to load. This
           configuration will be used as a fallback to override the
           defaults for settings which are not explcitly specified using
           AsyncSSH's configuration options. By default, no OpenSSH
           configuration files will be loaded. See
           :ref:`SupportedServerConfigOptions` for details on what
           configuration options are currently supported.
       :param options: (optional)
           Options to use when starting the reverse-direction SSH server.
           These options can be specified either through this parameter
           or as direct keyword arguments to this function.
       :type host: `str`
       :type port: `int`
       :type tunnel: :class:`SSHClientConnection` or `str`
       :type family: `socket.AF_UNSPEC`, `socket.AF_INET`, or `socket.AF_INET6`
       :type flags: flags to pass to :meth:`getaddrinfo() <socket.getaddrinfo>`
       :type local_addr: tuple of `str` and `int`
       :type config: `list` of `str`
       :type options: :class:`SSHServerConnectionOptions`

       :returns: :class:`SSHServerConnection`

    """

    def conn_factory():
        """Return an SSH client connection factory"""

        return SSHServerConnection(loop, options, wait='auth')

    loop = asyncio.get_event_loop()

    options = SSHServerConnectionOptions(options, config=config, host=host,
                                         port=port, tunnel=tunnel,
                                         family=family, local_addr=local_addr,
                                         **kwargs)

    return await _connect(options, loop, flags, conn_factory,
                          'Opening reverse SSH connection to')


@async_context_manager
async def listen(host='', port=(), tunnel=(), family=(),
                 flags=socket.AI_PASSIVE, backlog=100, reuse_address=None,
                 reuse_port=None, acceptor=None, error_handler=None,
                 config=(), options=None, **kwargs):
    """Start an SSH server

       This function is a coroutine which can be run to create an SSH server
       listening on the specified host and port. The return value is an
       :class:`SSHAcceptor` which can be used to shut down the listener.

       :param host: (optional)
           The hostname or address to listen on. If not specified, listeners
           are created for all addresses.
       :param port: (optional)
           The port number to listen on. If not specified, the default
           SSH port is used.
       :param tunnel: (optional)
           An existing SSH client connection that this new listener should
           be forwarded over. If set, a remote TCP/IP listener will be
           opened on this connection on the requested host and port rather
           than listening directly via TCP. A string of the form
           [user@]host[:port] may also be specified, in which case a
           connection will first be made to that host and it will then be
           used as a tunnel.
       :param family: (optional)
           The address family to use when creating the server. By default,
           the address families are automatically selected based on the host.
       :param flags: (optional)
           The flags to pass to getaddrinfo() when looking up the host
       :param backlog: (optional)
           The maximum number of queued connections allowed on listeners
       :param reuse_address: (optional)
           Whether or not to reuse a local socket in the TIME_WAIT state
           without waiting for its natural timeout to expire. If not
           specified, this will be automatically set to `True` on UNIX.
       :param reuse_port: (optional)
           Whether or not to allow this socket to be bound to the same
           port other existing sockets are bound to, so long as they all
           set this flag when being created. If not specified, the
           default is to not allow this. This option is not supported
           on Windows or Python versions prior to 3.4.4.
       :param acceptor: (optional)
           A `callable` or coroutine which will be called when the
           SSH handshake completes on an accepted connection, taking
           the :class:`SSHServerConnection` as an argument.
       :param error_handler: (optional)
           A `callable` which will be called whenever the SSH handshake
           fails on an accepted connection. It is called with the failed
           :class:`SSHServerConnection` and an exception object describing
           the failure. If not specified, failed handshakes result in the
           connection object being silently cleaned up.
       :param config: (optional)
           Paths to OpenSSH server configuration files to load. This
           configuration will be used as a fallback to override the
           defaults for settings which are not explcitly specified using
           AsyncSSH's configuration options. By default, no OpenSSH
           configuration files will be loaded. See
           :ref:`SupportedServerConfigOptions` for details on what
           configuration options are currently supported.
       :param options: (optional)
           Options to use when accepting SSH server connections. These
           options can be specified either through this parameter or
           as direct keyword arguments to this function.
       :type protocol_factory: `callable`
       :type host: `str`
       :type port: `int`
       :type tunnel: :class:`SSHClientConnection` or `str`
       :type family: `socket.AF_UNSPEC`, `socket.AF_INET`, or `socket.AF_INET6`
       :type flags: flags to pass to :meth:`getaddrinfo() <socket.getaddrinfo>`
       :type backlog: `int`
       :type reuse_address: `bool`
       :type reuse_port: `bool`
       :type config: `list` of `str`
       :type options: :class:`SSHServerConnectionOptions`

       :returns: :class:`SSHAcceptor`

    """

    def conn_factory():
        """Return an SSH client connection factory"""

        return SSHServerConnection(loop, options, acceptor, error_handler)

    loop = asyncio.get_event_loop()

    options = SSHServerConnectionOptions(options, config=config, host=host,
                                         port=port, tunnel=tunnel,
                                         family=family, **kwargs)

    # pylint: disable=attribute-defined-outside-init
    options.proxy_command = None

    return await _listen(options, loop, flags, backlog, reuse_address,
                         reuse_port, conn_factory, 'Creating SSH listener on')


@async_context_manager
async def listen_reverse(host='', port=(), *, tunnel=(), family=(),
                         flags=socket.AI_PASSIVE, backlog=100,
                         reuse_address=None, reuse_port=None,
                         acceptor=None, error_handler=None, config=(),
                         options=None, **kwargs):
    """Create a reverse-direction SSH listener

       This function is a coroutine which behaves similar to :func:`listen`,
       creating a listener which accepts inbound connections on the specified
       host and port. However, instead of starting up an SSH server on each
       inbound connection, it starts up a reverse-direction SSH client,
       expecting the remote system making the connection to start up a
       reverse-direction SSH server.

       Arguments to this function are the same as :func:`listen`, except
       that the `options` are of type :class:`SSHClientConnectionOptions`
       instead of :class:`SSHServerConnectionOptions`.

       The return value is an :class:`SSHAcceptor` which can be used to
       shut down the reverse listener.

       :param host: (optional)
           The hostname or address to listen on. If not specified, listeners
           are created for all addresses.
       :param port: (optional)
           The port number to listen on. If not specified, the default
           SSH port is used.
       :param tunnel: (optional)
           An existing SSH client connection that this new listener should
           be forwarded over. If set, a remote TCP/IP listener will be
           opened on this connection on the requested host and port rather
           than listening directly via TCP. A string of the form
           [user@]host[:port] may also be specified, in which case a
           connection will first be made to that host and it will then be
           used as a tunnel.
       :param family: (optional)
           The address family to use when creating the server. By default,
           the address families are automatically selected based on the host.
       :param flags: (optional)
           The flags to pass to getaddrinfo() when looking up the host
       :param backlog: (optional)
           The maximum number of queued connections allowed on listeners
       :param reuse_address: (optional)
           Whether or not to reuse a local socket in the TIME_WAIT state
           without waiting for its natural timeout to expire. If not
           specified, this will be automatically set to `True` on UNIX.
       :param reuse_port: (optional)
           Whether or not to allow this socket to be bound to the same
           port other existing sockets are bound to, so long as they all
           set this flag when being created. If not specified, the
           default is to not allow this. This option is not supported
           on Windows or Python versions prior to 3.4.4.
       :param acceptor: (optional)
           A `callable` or coroutine which will be called when the
           SSH handshake completes on an accepted connection, taking
           the :class:`SSHClientConnection` as an argument.
       :param error_handler: (optional)
           A `callable` which will be called whenever the SSH handshake
           fails on an accepted connection. It is called with the failed
           :class:`SSHClientConnection` and an exception object describing
           the failure. If not specified, failed handshakes result in the
           connection object being silently cleaned up.
       :param config: (optional)
           Paths to OpenSSH client configuration files to load. This
           configuration will be used as a fallback to override the
           defaults for settings which are not explcitly specified using
           AsyncSSH's configuration options. If no paths are specified,
           an attempt will be made to load the configuration from the file
           :file:`.ssh/config`. If this argument is explicitly set to
           `None`, no OpenSSH configuration files will be loaded. See
           :ref:`SupportedClientConfigOptions` for details on what
           configuration options are currently supported.
       :param options: (optional)
           Options to use when starting reverse-direction SSH clients.
           These options can be specified either through this parameter
           or as direct keyword arguments to this function.
       :type client_factory: `callable`
       :type host: `str`
       :type port: `int`
       :type tunnel: :class:`SSHClientConnection` or `str`
       :type family: `socket.AF_UNSPEC`, `socket.AF_INET`, or `socket.AF_INET6`
       :type flags: flags to pass to :meth:`getaddrinfo() <socket.getaddrinfo>`
       :type backlog: `int`
       :type reuse_address: `bool`
       :type reuse_port: `bool`
       :type config: `list` of `str`
       :type options: :class:`SSHClientConnectionOptions`

       :returns: :class:`SSHAcceptor`

    """

    def conn_factory():
        """Return an SSH client connection factory"""

        return SSHClientConnection(loop, options, acceptor, error_handler)

    loop = asyncio.get_event_loop()

    options = SSHClientConnectionOptions(options, config=config, host=host,
                                         port=port, tunnel=tunnel,
                                         family=family, **kwargs)

    # pylint: disable=attribute-defined-outside-init
    options.proxy_command = None

    return await _listen(options, loop, flags, backlog, reuse_address,
                         reuse_port, conn_factory,
                         'Creating reverse direction SSH listener on')


async def create_connection(client_factory, host, port=(), **kwargs):
    """Create an SSH client connection

       This is a coroutine which wraps around :func:`connect`, providing
       backward compatibility with older AsyncSSH releases. The only
       differences are that the `client_factory` argument is the first
       positional argument in this call rather than being a keyword argument
       or specified via an :class:`SSHClientConnectionOptions` object and
       the return value is a tuple of an :class:`SSHClientConnection` and
       :class:`SSHClient` rather than just the connection, mirroring
       :meth:`asyncio.BaseEventLoop.create_connection`.

       :returns: An :class:`SSHClientConnection` and :class:`SSHClient`

    """

    conn = await connect(host, port, client_factory=client_factory, **kwargs)

    return conn, conn.get_owner()


@async_context_manager
async def create_server(server_factory, host='', port=(), **kwargs):
    """Create an SSH server

       This is a coroutine which wraps around :func:`listen`, providing
       backward compatibility with older AsyncSSH releases. The only
       difference is that the `server_factory` argument is the first
       positional argument in this call rather than being a keyword argument
       or specified via an :class:`SSHServerConnectionOptions` object,
       mirroring :meth:`asyncio.BaseEventLoop.create_server`.

    """

    return await listen(host, port, server_factory=server_factory, **kwargs)


async def get_server_host_key(host, port=(), *, tunnel=(), proxy_command=(),
                              family=(), flags=0, local_addr=None,
                              client_version=(), kex_algs=(),
                              server_host_key_algs=(), config=(),
                              options=None):
    """Retrieve an SSH server's host key

       This is a coroutine which can be run to connect to an SSH server and
       return the server host key presented during the SSH handshake.

       A list of server host key algorithms can be provided to specify
       which host key types the server is allowed to choose from. If the
       key exchange is successful, the server host key sent during the
       handshake is returned.

           .. note:: Not all key exchange methods involve the server
                     presenting a host key. If something like GSS key
                     exchange is used without a server host key, this
                     method may return `None` even when the handshake
                     completes.

       :param host:
           The hostname or address to connect to
       :param port: (optional)
           The port number to connect to. If not specified, the default
           SSH port is used.
       :param tunnel: (optional)
           An existing SSH client connection that this new connection should
           be tunneled over. If set, a direct TCP/IP tunnel will be opened
           over this connection to the requested host and port rather than
           connecting directly via TCP. A string of the form
           [user@]host[:port] may also be specified, in which case a
           connection will first be made to that host and it will then be
           used as a tunnel.
       :param proxy_command: (optional)
           A string or list of strings specifying a command and arguments
           to run to make a connection to the SSH server. Data will be
           forwarded to this process over stdin/stdout instead of opening a
           TCP connection. If specified as a string, standard shell quoting
           will be applied when splitting the command and its arguments.
       :param family: (optional)
           The address family to use when creating the socket. By default,
           the address family is automatically selected based on the host.
       :param flags: (optional)
           The flags to pass to getaddrinfo() when looking up the host address
       :param local_addr: (optional)
           The host and port to bind the socket to before connecting
       :param client_version: (optional)
           An ASCII string to advertise to the SSH server as the version of
           this client, defaulting to `'AsyncSSH'` and its version number.
       :param kex_algs: (optional)
           A list of allowed key exchange algorithms in the SSH handshake,
           taken from :ref:`key exchange algorithms <KexAlgs>`
       :param server_host_key_algs: (optional)
           A list of server host key algorithms to allow during the SSH
           handshake, taken from :ref:`server host key algorithms
           <PublicKeyAlgs>`.
       :param config: (optional)
           Paths to OpenSSH client configuration files to load. This
           configuration will be used as a fallback to override the
           defaults for settings which are not explcitly specified using
           AsyncSSH's configuration options. If no paths are specified,
           an attempt will be made to load the configuration from the file
           :file:`.ssh/config`. If this argument is explicitly set to
           `None`, no OpenSSH configuration files will be loaded. See
           :ref:`SupportedClientConfigOptions` for details on what
           configuration options are currently supported.
       :param options: (optional)
           Options to use when establishing the SSH client connection used
           to retrieve the server host key. These options can be specified
           either through this parameter or as direct keyword arguments to
           this function.
       :type host: `str`
       :type port: `int`
       :type tunnel: :class:`SSHClientConnection` or `str`
       :type proxy_command: `str` or `list` of `str`
       :type family: `socket.AF_UNSPEC`, `socket.AF_INET`, or `socket.AF_INET6`
       :type flags: flags to pass to :meth:`getaddrinfo() <socket.getaddrinfo>`
       :type local_addr: tuple of `str` and `int`
       :type client_version: `str`
       :type kex_algs: `str` or `list` of `str`
       :type server_host_key_algs: `str` or `list` of `str`
       :type config: `list` of `str`
       :type options: :class:`SSHClientConnectionOptions`

       :returns: An :class:`SSHKey` public key or `None`

    """

    def conn_factory():
        """Return an SSH client connection factory"""

        return SSHClientConnection(loop, options, wait='kex')

    loop = asyncio.get_event_loop()

    options = SSHClientConnectionOptions(
        options, config=config, host=host, port=port, tunnel=tunnel,
        proxy_command=proxy_command, family=family, local_addr=local_addr,
        known_hosts=None, server_host_key_algs=server_host_key_algs,
        x509_trusted_certs=None, x509_trusted_cert_paths=None,
        x509_purposes='any', gss_host=None, kex_algs=kex_algs,
        client_version=client_version)

    conn = await _connect(options, loop, flags, conn_factory,
                          'Fetching server host key from')

    server_host_key = conn.get_server_host_key()

    conn.abort()

    await conn.wait_closed()

    return server_host_key
