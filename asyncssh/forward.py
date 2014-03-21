# Copyright (c) 2013-2014 by Ron Frederick <ronf@timeheart.net>.
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

"""SSH port forwarding handlers"""

import asyncore, socket, sys, traceback

from .asyncfunc import *
from .connection import *
from .constants import *
from .listen import *


class _ForwardDispatcher(asyncore.dispatcher):
    """Asynchronous port forwarder"""

    def __init__(self, connection, sock=None, dest=None):
        super().__init__(sock)

        self._addrinfo = ()
        self._connection = connection
        self._outbuf = b''
        self._send_blocked = False
        self._eof_pending = False
        self._eof_sent = False
        self._eof_received = False

        if dest:
            host, port = dest
            try:
                self._addrinfo = getaddrinfo(host, port, socket.AF_UNSPEC,
                                             socket.SOCK_STREAM,
                                             callback=self._try_connect)
            except socket.gaierror as exc:
                self._connection.report_open_error(OPEN_CONNECT_FAILED,
                                                   exc.args[1])

    def _try_connect(self, rtype, result):
        if rtype == 'result':
            self._addrinfo = result
            self._connect_next()
        else:
            self._connection.report_open_error(OPEN_CONNECT_FAILED,
                                               result.args[1])

    def _connect_next(self):
        family, socktype, proto, canonname, sockaddr = self._addrinfo.pop(0)
        self.create_socket(family, socktype)
        self.connect(sockaddr)

    def handle_connect(self):
        self._connection.report_open()

    def readable(self):
        return self.connected and not (self._connection._send_blocked or
                                       self._eof_received)

    def handle_read(self):
        data = self.socket.recv(self._connection._send_pktsize)
        if data:
            self._connection.send(data)
        else:
            self._eof_received = True
            self._connection.send_eof()
            if self._eof_sent:
                self.handle_close()

    def writable(self):
        return not self.connected or self._outbuf or \
               self._send_blocked or self._eof_pending

    def handle_write(self):
        if self._outbuf:
            sent = self.socket.send(self._outbuf)
            self._outbuf = self._outbuf[sent:]

        if self._outbuf:
            self._send_blocked = True
            self._connection.block_recv()
        elif self._send_blocked:
            self._send_blocked = False
            self._connection.unblock_recv()
        elif self._eof_pending:
            self.socket.shutdown(socket.SHUT_WR)
            self._eof_pending = False
            self._eof_sent = True
            if self._eof_received:
                self.handle_close()

    def handle_error(self):
        exc = sys.exc_info()[1]
        if isinstance(exc, socket.error):
            connected = self.connected
            self.close()

            if connected:
                self._connection.close()
            elif self._addrinfo:
                self._connect_next()
            else:
                self._connection.report_open_error(OPEN_CONNECT_FAILED,
                                                   exc.args[1])
        else:
            traceback.print_exc()
            sys.exit(1)

    def handle_close(self):
        self._connection.close()
        self.close()

    def send(self, data):
        self._outbuf += data

    def send_eof(self):
        self._eof_pending = True


class SSHForwardedConnection(SSHTCPConnection):
    """SSH TCP connection which implements port forwarding"""

    def __init__(self, conn, sock=None, dest=None):
        super().__init__(conn)

        self._sock = sock
        self._dest = dest
        self._dispatcher = None

    def handle_open_request(self):
        self._dispatcher = _ForwardDispatcher(self, dest=self._dest)

    def handle_open(self):
        if not self._dispatcher:
            self._dispatcher = _ForwardDispatcher(self, sock=self._sock)
            self._sock = None

    def handle_open_error(self, code, reason, lang):
        self.handle_close()

    def handle_data(self, data, datatype):
        self._dispatcher.send(data)

    def handle_eof(self):
        self._dispatcher.send_eof()

    def handle_close(self):
        if self._dispatcher:
            self._dispatcher.close()

        if self._sock:
            self._sock.close()

        self.close()


class SSHClientLocalPortForwarder(Listener):
    """SSH client local port forwarder

       Applications should subclass this when implementing local port
       forwarding on an SSH client. If port forwarding was successfully
       set up on the requested listening host and port, the method
       :meth:`handle_open` is. If an error occurs, the method
       :meth:`handle_open_error` is called with exception information.

       Once the listener is set up, the method :meth:`accept_connection`
       is called on each new incoming connection to determine whether or
       not to forward the connection over SSH. It should return ``True`` to
       accept and forward the connection or ``False`` to reject and close
       it.

       By default, :meth:`accept_connection` returns ``True``, causing
       all connections to be forwarded.

       :param conn:
           The SSH connection to forward connections on
       :param string listen_host:
           The local host address to listen on
       :param integer listen_port:
           The local port to listen on, or ``0`` to listen on a dynamic port
       :param string dest_host:
           The remote destination host to forward the connection to
       :param integer dest_port:
           The remote destination port to forward the connection to
       :type conn: :class:`SSHClient`

    """

    def __init__(self, conn, listen_host, listen_port, dest_host, dest_port):
        listen_host = listen_host.lower()
        super().__init__(listen_host, listen_port)

        self.conn = conn
        self._dest_host = dest_host
        self._dest_port = dest_port

        conn._local_listeners[(listen_host, listen_port)] = self

    def handle_accepted(self, sock, client_addr):
        orig_host, orig_port = client_addr[:2]

        if self.accept_connection(orig_host, orig_port):
            connection = SSHForwardedConnection(self.conn, sock=sock)
            connection.connect(self._dest_host, self._dest_port,
                               orig_host, orig_port)
        else:
            sock.close()

    def close(self):
        """Close the port forwarder
        
           This method can be called to stop forwarding connections on
           the originally requested local listening host and port over
           SSH.

        """

        del self.conn._local_listeners[(self.listen_host, self.listen_port)]
        super().close()

    def accept_connection(self, orig_host, orig_port):
        """Return whether or not to accept a connection

           This method is called when a new connection arrives on the
           requested local listening host and port. It should return
           ``True`` if the connection should be accepted and forwarded
           over the SSH connection to the requested destination host
           and port or ``False`` if the connection should be rejected.

           By default, this method returns ``True``, accepting and
           forwarding all incoming connections.

           :param string orig_host:
               The address the connection was originated from
           :param integer orig_port:
               The port the connection was originated from

           :returns: ``True`` to accept the connection or ``False`` to
                     reject it

        """

        return True


class SSHClientRemotePortForwarder(SSHClientListener):
    """SSH client remote port forwarder

       Applications should subclass this when implementing remote port
       forwarding on an SSH client. If port forwarding was successfully
       set up on the requested listening host and port, the method
       :meth:`handle_open` is called. If an error occurs, the method
       :meth:`handle_open_error` is called.

       Once the listener is set up, the method :meth:`accept_connection`
       is called on each forwarded connection arriving over SSH to
       determine whether or not to forward it. It should return ``True``
       to accept and forward the connection, ``False`` to reject the
       connection with an error of "Connection refused", or raise
       :exc:`ChannelOpenError` to reject it with some other error.

       By default, :meth:`accept_connection` returns ``True``, causing
       all connections to be forwarded.

       :param conn:
           The SSH connection to forward connections on
       :param string listen_host:
           The remote host address to listen on
       :param integer listen_port:
           The remote port to listen on, or ``0`` to listen on a dynamic port
       :param string dest_host:
           The local destination host to forward the connection to
       :param integer dest_port:
           The local destination port to forward the connection to
       :type conn: :class:`SSHClient`

    """

    def __init__(self, conn, listen_host, listen_port, dest_host, dest_port):
        super().__init__(conn, listen_host, listen_port)

        self._dest_host = dest_host
        self._dest_port = dest_port

    def handle_connection(self, orig_host, orig_port):
        if self.accept_connection(orig_host, orig_port):
            return SSHForwardedConnection(self.conn, dest=(self._dest_host,
                                                           self._dest_port))
        else:
            raise ChannelOpenError(OPEN_CONNECT_FAILED, 'Connection refused')

    def accept_connection(self, orig_host, orig_port):
        """Return whether or not to accept a connection

           This method is called when a forwarded connection arrives
           on the SSH connection and should return whether or not to
           accept the connection and forward it to the requested
           destination host and port.

           By default, this method returns ``True``, accepting and
           forwarding all incoming connections.

           :param string orig_host:
               The address the connection was originated from
           :param integer orig_port:
               The port the connection was originated from

           :returns: ``True`` to accept the connection or ``False`` to
                     reject it with a "Connection refused" error

           :raises:
               :exc:`ChannelOpenError` to reject the connection with some
               other error

        """

        return True


class _SSHServerForwardListener(Listener):
    """SSH server port forwarding listener"""

    def __init__(self, forwarder, listen_host, listen_port):
        super().__init__(listen_host, listen_port)

        self._forwarder = forwarder

    def handle_open(self):
        self._forwarder.report_open(self.listen_port)

    def handle_open_error(self, exc):
        self._forwarder.report_open_error()

    def handle_accepted(self, sock, client_addr):
        self._forwarder.handle_accepted(sock, client_addr)


class SSHServerPortForwarder(SSHServerListener):
    """SSH server port forwarder

       Server applications should subclass this when implementing port
       forwarding.

       Once the listener is set up, the method :meth:`accept_connection`
       is called on each new incoming connection to determine whether or
       not to forward the connection over SSH. It should return ``True`` to
       accept and forward the connection or ``False`` to reject and close
       it.

       By default, :meth:`accept_connection` returns ``True``, causing
       all connections to be forwarded.

       :param conn:
           The SSH connection to forward connections on
       :param string listen_host:
           The local host address to listen on
       :param integer listen_port:
           The local port to listen on, or ``0`` to listen on a dynamic port
       :type conn: :class:`SSHServer`

    """

    def handle_open_request(self):
        self._listener = _SSHServerForwardListener(self, self.listen_host,
                                                   self.listen_port)

    def handle_accepted(self, sock, client_addr):
        orig_host, orig_port = client_addr[:2]

        if self.accept_connection(orig_host, orig_port):
            connection = SSHForwardedConnection(self.conn, sock=sock)
            connection.accept(self.listen_host, self.listen_port,
                              orig_host, orig_port)
        else:
            sock.close()

    def handle_close(self):
        self._listener.close()

    def accept_connection(self, orig_host, orig_port):
        """Return whether or not to accept a connection

           This method is called when a new connection arrives on the
           requested local listening host and port. It should return
           ``True`` if the connection should be accepted and forwarded
           to over the SSH connection to the requested destination host
           and port or ``False`` if the connection should be rejected.

           By default, this method returns ``True``, accepting and
           forwarding all incoming connections.

           :param string orig_host:
               The address the connection was originated from
           :param integer orig_port:
               The port the connection was originated from

           :returns: ``True`` to accept the connection or ``False`` to
                     reject it

        """

        return True
