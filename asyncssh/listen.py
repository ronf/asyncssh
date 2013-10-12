# Copyright (c) 2013 by Ron Frederick <ronf@timeheart.net>.
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

"""SSH TCP/IP listening handlers"""

from .constants import *
from .misc import *


class SSHClientListener:
    """SSH client listener parent class

       Client applications should subclass this when implementing a handler
       for forwarded SSH TCP/IP connections. Creating an instance of this
       class will send a request to the server to listen on the specified
       remote address and port for incoming TCP connections. If the
       listener is opened successfully, the method :meth:`handle_open`
       is called. If the attempt to open the listener fails, the method
       :meth:`handle_open_error` is called.

       When new connections are forwarded from the server, the method
       :meth:`handle_connection` is called, and it should return an
       instance of a class derived from :class:`SSHTCPConnection` to
       accept the connection or raise :exc:`ChannelOpenError` to reject it.

       Passing in a port value of ``0`` indicates that the server should
       allocate a dynamic port to listen on. The application can determine
       what listening port was selected by reading the ``listen_port``
       member variable when :meth:`handle_open` is called.

       :param conn:
           The connection this listener should be opened on
       :param string listen_host:
           The requested hostname or address to listen on
       :param integer listen_port:
           The requested port to listen on, or ``0`` to request a dynamic port
       :type conn: :class:`SSHClient`

    """

    @staticmethod
    def _find(conn, host, port):
        """Find a listener by host and port

           Some buggy servers send back a port of ``0`` instead of the
           actual listening port they selected when reporting connections
           which arrive on a listener set up on a dynamic port. This
           method does its best to work around that.

        """

        host = host.lower()

        return conn._remote_listeners.get((host, port)) or \
               conn._remote_dynamic_listeners.get(host)

    def __init__(self, conn, listen_host, listen_port):
        self.conn = conn
        self.listen_host = listen_host.lower()
        self.listen_port = listen_port

        self._state = 'opening'

        conn._open_remote_listener(self)

    def _process_listen_confirmation(self, packet):
        """Process a listener open confirmation"""

        if self.listen_port == 0:
            self.listen_port = packet.get_uint32()

            self.conn._remote_dynaamic_listeners[self.listen_host] = self

        packet.check_end()

        self.conn._remote_listeners[(self.listen_host, self.listen_port)] = self

        if self._state == 'opening':
            self._state = 'open'
            self.handle_open()
        elif self._state == 'open_aborted':
            self._state = 'closing'
            self.conn._close_remote_listener(self)
        else:
            raise IOError('Listener already open')

    def _process_listen_failure(self):
        """Process a listener open failure"""

        if self._state == 'opening':
            self.handle_open_error()
        elif self._state != 'open_aborted':
            raise IOError('Listener already open')

        self._state = 'closed'

    def _process_connection(self, orig_host, orig_port):
        """Process a forwarded connection"""

        return self.handle_connection(orig_host, orig_port)

    def _process_close(self):
        if self._state == 'closing':
            if self.conn._remote_dynamic_listeners[self.listen_host] == self:
                del self.conn._remote_dynamic_listeners[self.listen_host]

            del self.conn._remote_listeners[(self.listen_host,
                                             self.listen_port)]

            self._state = 'closed'
        else:
            raise IOError('Listener not closing')

    def close(self):
        """Close the listener

           This method can be called to request that the server stop
           forwarding connections on the originally requested host
           and port over SSH. After this call is made, there may be
           some additional connections forwarded which arrived before
           the server finished processing the close request.

        """

        if self._state == 'opening':
            self._state = 'open_aborted'
        elif self._state == 'open':
            self._state = 'closing'
            self.conn._close_remote_listener(self)
        else:
            # We've already begun to close
            pass

    def handle_open(self):
        """Handle a successfully opened listener

           This method is called when the remote listener is opened
           successfully. The host and port that the listener was opened
           on are available in the ``listen_host`` and ``listen_port``
           member variables.

           By default, this method does nothing.

        """

        pass

    def handle_open_error(self):
        """Handle a failure opening a listener

           This method is called when an attempt to open the remote
           listener fails.

           By default, this method does nothing.

        """

        pass

    def handle_connection(self, orig_host, orig_port):
        """Handle a forwarded TCP/IP connection request

           This method is called when a forwarded TCP/IP connection
           request is received. Applications wishing to accept such
           connections must override this method and have it return
           a class derived from :class:`SSHTCPConnection` which can
           process the data received on the channel. Otherwise, they
           should raise :exc:`ChannelOpenError` with the reason they
           are rejecting the connection.

           By default, all connections are rejected with an error code
           of ``OPEN_CONNECT_FAILED`` and a reason of "Connection
           refused".

           :param string orig_host:
               The address the connection was originated from
           :param integer orig_port:
               The port the connection was originated from

           :returns:
               A subclass of :class:`SSHTCPConnection` which should be
               used to process the data on the forwarded connection

           :raises:
               :exc:`ChannelOpenError` if the connection shouldn't be
               accepted

        """

        raise ChannelOpenError(OPEN_CONNECT_FAILED, 'Connection refused')


class SSHServerListener:
    """SSH server listener parent class

       Server applications should subclass this when implementing a
       handler to forward TCP/IP connections back to the client over
       SSH. An instance of the subclass should be returned when the
       :meth:`handle_listen() <SSHServer.handle_listen>` method is
       called on an :class:`SSHServer` object.

       When new connections arrive, this class should create instances
       of a subclass of :class:`SSHTCPConnection` and call :meth:`accept()
       <SSHTCPConnection.accept>` to forward the incoming connections
       over SSH.

       :param conn:
           The connection this listener should be opened on
       :param string listen_host:
           The requested hostname or address to listen on
       :param integer listen_port:
           The requested port to listen on, or ``0`` to request a dynamic port
       :type conn: :class:`SSHServer`

    """

    def __init__(self, conn, listen_host, listen_port):
        self.conn = conn
        self.listen_host = listen_host.lower()
        self.listen_port = listen_port

        self._state = 'opening'

        self.handle_open_request()

    def close(self):
        self.handle_close()

    def report_open(self, listen_port=None):
        """Report that the listener has been opened successfully
        
           This method can be called to report that the listener has
           been opened successfully. If the requested listening port
           was ``0`` indicating that a dynamic port should be allocated,
           this method should be called with the port number which was
           selected.

           :param integer listen_port: (optional)
               The selected port number if a dynamic port was requested

        """

        if self.listen_port == 0:
            self.listen_port = listen_port
            result = UInt32(listen_port)
        else:
            result = True

        self.conn._report_global_response(result)

    def report_open_error(self):
        """Report that the attempt to open the listener failed

           This method can be called to report that the listener could
           not be opened.

        """

        self.conn._report_global_response(False)

    def handle_open_request(self):
        """Handle when a request is made to open the listener

           This method is called when a request is made to open a
           server-side TCP/IP listener. If a server application wishes
           to forward connections back to the client, it must override
           this method to initiate whatever processing is needed to
           set up its listener. When this processing is complete, a call
           must be made to :meth:`report_open` to indicate that the
           listener was opened successfully. If an error occurs while
           trying to open the listener, a call must be made to
           :meth:`report_open_error`.

           Applications can find the requested listening host and port
           in the ``listen_host`` and ``listen_port`` member variables.
           If ``listen_port`` is set to ``0``, this indicates that the
           client is requesting the server allocate a dynamic port. In
           such cases, the selected port number should be provided in
           the call to :meth:`report_open`.

           By default, this calls :meth:`report_open_error` to
           indicate that the listener could not be opened.

        """

        self.report_open_error()

    def handle_close(self):
        """Handle when the listener is closed

           This method is called when the client requests that the
           server stop forwarding connections on the originally
           requested host and port over SSH, or when the SSH
           connection is closed.

           By default, this method does nothing, but it should be
           overridden to clean up any listeners set up as a result
           of the call to :meth:`handle_open_request`.

        """

        pass
