# Copyright (c) 2013-2025 by Ron Frederick <ronf@timeheart.net> and others.
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

"""SSH port forwarding handlers"""

import asyncio
import socket
from types import TracebackType
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, Optional
from typing import Type, cast
from typing_extensions import Self

from .misc import ChannelOpenError, SockAddr


if TYPE_CHECKING:
    # pylint: disable=cyclic-import
    from .connection import SSHConnection


SSHForwarderCoro = Callable[..., Awaitable]


class SSHForwardTracker:
    """Base class for observing the lifecycle of a forwarded connection

       A tracker observes a single forwarded connection on a local
       listener. A `tracker_factory` passed to one of the
       :meth:`forward_local_port() <SSHClientConnection.forward_local_port>`
       family of methods is called once per accepted connection and must
       return a new tracker instance, on which asyncssh then calls the
       hooks below for the life of that connection.

       All hooks run inside the asyncio event loop and **must not block**
       (no I/O, no sleeps). They are pure observers: return values are
       ignored and the forwarded data is never altered. Each hook has a
       no-op default, so a subclass need only override the ones it cares
       about. Exceptions raised by a hook are caught and discarded, so a
       buggy tracker can never break forwarding.

       This base class defines the hooks shared by all forward types.
       Use :class:`SSHPortForwardTracker` for TCP local forwards and
       :class:`SSHPathForwardTracker` for UNIX domain socket local
       forwards; they differ only in the signature of `connection_made`.

    """

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Called when the forwarded connection has closed

           :param exc:
               The exception which caused the connection to close, or
               `None` if the connection closed cleanly.
           :type exc: :class:`Exception` or `None`

        """

    def forward_local_bytes(self, data: bytes) -> None:
        """Called for data forwarded from the local side into the tunnel

           :param data:
               A block of bytes received on the local connection and
               about to be sent over the SSH connection. This is called
               once per received block, not once per byte.
           :type data: `bytes`

        """

    def forward_remote_bytes(self, data: bytes) -> None:
        """Called for data forwarded from the tunnel to the local side

           :param data:
               A block of bytes received over the SSH connection and
               about to be written to the local connection. This is
               called once per received block, not once per byte.
           :type data: `bytes`

        """


class SSHPortForwardTracker(SSHForwardTracker):
    """Tracker for local TCP port forwards

       Used with
       :meth:`forward_local_port() <SSHClientConnection.forward_local_port>`
       and :meth:`forward_local_port_to_path()
       <SSHClientConnection.forward_local_port_to_path>`.

    """

    def connection_made(self, forwarder: 'SSHForwarder',
                        orig_host: str, orig_port: int) -> None:
        """Called when a new TCP connection is accepted on the listener

           :param forwarder:
               The forwarder handling this connection.
           :param orig_host:
               The originating client host.
           :param orig_port:
               The originating client port.
           :type forwarder: :class:`SSHForwarder`
           :type orig_host: `str`
           :type orig_port: `int`

        """


class SSHPathForwardTracker(SSHForwardTracker):
    """Tracker for local UNIX domain socket forwards

       Used with
       :meth:`forward_local_path() <SSHClientConnection.forward_local_path>`
       and :meth:`forward_local_path_to_port()
       <SSHClientConnection.forward_local_path_to_port>`.

    """

    def connection_made(self, forwarder: 'SSHForwarder') -> None:
        """Called when a new UNIX domain connection is accepted

           :param forwarder:
               The forwarder handling this connection.
           :type forwarder: :class:`SSHForwarder`

        """


SSHForwardTrackerFactory = Callable[[], SSHForwardTracker]


class SSHForwarder(asyncio.BaseProtocol):
    """SSH port forwarding connection handler"""

    def __init__(self, peer: Optional['SSHForwarder'] = None,
                 extra: Optional[Dict[str, Any]] = None):
        self._peer = peer
        self._transport: Optional[asyncio.Transport] = None
        self._inpbuf = b''
        self._eof_received = False

        if peer:
            peer.set_peer(self)

        if extra is None:
            extra = {}

        self._extra = extra

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, _exc_type: Optional[Type[BaseException]],
                        _exc_value: Optional[BaseException],
                        _traceback: Optional[TracebackType]) -> bool:
        self.close()
        return False

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        """Get additional information about the forwarder

           This method returns extra information about the forwarder.
           Currently, the only information available is the value
           ``interface`` for TUN/TAP forwarders, returning the name of the
           local TUN/TAP network interface created for this forwarder.

        """

        return self._extra.get(name, default)

    def set_peer(self, peer: 'SSHForwarder') -> None:
        """Set the peer forwarder to exchange data with"""

        self._peer = peer

    def write(self, data: bytes) -> None:
        """Write data to the transport"""

        if not self._transport:
            return # pragma: no cover

        try:
            self._transport.write(data)
        except OSError: # pragma: no cover
            pass

    def write_eof(self) -> None:
        """Write end of file to the transport"""

        if not self._transport:
            return # pragma: no cover

        try:
            self._transport.write_eof()
        except OSError: # pragma: no cover
            pass

    def was_eof_received(self) -> bool:
        """Return whether end of file has been received or not"""

        return self._eof_received

    def pause_reading(self) -> None:
        """Pause reading from the transport"""

        assert self._transport is not None
        self._transport.pause_reading()

    def resume_reading(self) -> None:
        """Resume reading on the transport"""

        assert self._transport is not None
        self._transport.resume_reading()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Handle a newly opened connection"""

        self._transport = cast(Optional['asyncio.Transport'], transport)

        sock = cast(socket.socket, transport.get_extra_info('socket'))

        if sock and sock.family in {socket.AF_INET, socket.AF_INET6}:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Handle an incoming connection close"""

        # pylint: disable=unused-argument

        self.close()

    def session_started(self) -> None:
        """Handle session start"""

    def data_received(self, data: bytes,
                      datatype: Optional[int] = None) -> None:
        """Handle incoming data from the transport"""

        # pylint: disable=unused-argument

        if self._peer:
            self._peer.write(data)
        else:
            self._inpbuf += data

    def eof_received(self) -> bool:
        """Handle an incoming end of file from the transport"""

        self._eof_received = True

        if self._peer:
            self._peer.write_eof()

            return not self._peer.was_eof_received()
        else:
            return True

    def pause_writing(self) -> None:
        """Pause writing by asking peer to pause reading"""

        if self._peer: # pragma: no branch
            self._peer.pause_reading()

    def resume_writing(self) -> None:
        """Resume writing by asking peer to resume reading"""

        if self._peer: # pragma: no branch
            self._peer.resume_reading()

    def close(self) -> None:
        """Close this port forwarder"""

        if self._transport:
            self._transport.close()
            self._transport = None

        if self._peer:
            peer = self._peer
            self._peer = None
            peer.close()


class SSHLocalForwarder(SSHForwarder):
    """Local forwarding connection handler"""

    def __init__(self, conn: 'SSHConnection', coro: SSHForwarderCoro,
                 tracker_factory: Optional[SSHForwardTrackerFactory] = None):
        super().__init__()
        self._conn = conn
        self._coro = coro
        self._tracker_factory = tracker_factory
        self._tracker: Optional[SSHForwardTracker] = None

    def _create_tracker(self) -> None:
        """Instantiate this connection's tracker from the factory, if any"""

        if self._tracker_factory is None:
            return

        try:
            self._tracker = self._tracker_factory()
        except Exception: # pylint: disable=broad-exception-caught
            # A buggy factory must not break forwarding.
            self._tracker = None

    def data_received(self, data: bytes,
                      datatype: Optional[int] = None) -> None:
        """Handle incoming data from the local transport"""

        if self._tracker is not None:
            try:
                self._tracker.forward_local_bytes(data)
            except Exception: # pylint: disable=broad-exception-caught
                pass

        super().data_received(data, datatype)

    def write(self, data: bytes) -> None:
        """Write tunnel data out to the local transport"""

        if self._tracker is not None:
            try:
                self._tracker.forward_remote_bytes(data)
            except Exception: # pylint: disable=broad-exception-caught
                pass

        super().write(data)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Handle a closed local connection"""

        if self._tracker is not None:
            try:
                self._tracker.connection_lost(exc)
            except Exception: # pylint: disable=broad-exception-caught
                pass

        super().connection_lost(exc)

    async def _forward(self, *args: object) -> None:
        """Begin local forwarding"""

        def session_factory() -> SSHForwarder:
            """Return an SSH forwarder"""

            return SSHForwarder(self)

        try:
            await self._coro(session_factory, *args)
        except ChannelOpenError as exc:
            self.connection_lost(exc)
            return

        assert self._peer is not None

        if self._inpbuf:
            self._peer.write(self._inpbuf)
            self._inpbuf = b''

        if self._eof_received:
            self._peer.write_eof()

    def forward(self, *args: object) -> None:
        """Start a task to begin local forwarding"""

        self._conn.create_task(self._forward(*args))


class SSHLocalPortForwarder(SSHLocalForwarder):
    """Local TCP port forwarding connection handler"""

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Handle a newly opened connection"""

        super().connection_made(transport)

        orig_host, orig_port = '', 0
        peername = cast(SockAddr, transport.get_extra_info('peername'))

        if peername: # pragma: no branch
            orig_host, orig_port = peername[:2]

        self._create_tracker()

        if self._tracker is not None:
            try:
                cast(SSHPortForwardTracker, self._tracker).connection_made(
                    self, orig_host, orig_port)
            except Exception: # pylint: disable=broad-exception-caught
                pass

        self.forward(orig_host, orig_port)


class SSHLocalPathForwarder(SSHLocalForwarder):
    """Local UNIX domain socket forwarding connection handler"""

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Handle a newly opened connection"""

        super().connection_made(transport)

        self._create_tracker()

        if self._tracker is not None:
            try:
                cast(SSHPathForwardTracker, self._tracker).connection_made(self)
            except Exception: # pylint: disable=broad-exception-caught
                pass

        self.forward()
