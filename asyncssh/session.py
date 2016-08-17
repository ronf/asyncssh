# Copyright (c) 2013-2015 by Ron Frederick <ronf@timeheart.net>.
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

"""SSH session handlers"""


class SSHSession:
    """SSH session handler"""

    def connection_made(self, chan):
        """Called when a channel is opened successfully

           This method is called when a channel is opened successfully. The
           channel parameter should be stored if needed for later use.

           :param chan:
               The channel which was successfully opened.
           :type chan: :class:`SSHClientChannel`

        """
        pass # pragma: no cover

    def connection_lost(self, exc):
        """Called when a channel is closed

           This method is called when a channel is closed. If the channel
           is shut down cleanly, *exc* will be ``None``. Otherwise, it
           will be an exception explaining the reason for the channel close.

           :param exc:
               The exception which caused the channel to close, or
               ``None`` if the channel closed cleanly.
           :type exc: :class:`Exception`

        """

        pass # pragma: no cover

    def session_started(self):
        """Called when the session is started

           This method is called when a session has started up. For
           client and server sessions, this will be called once a
           shell, exec, or subsystem request has been successfully
           completed. For TCP and UNIX domain socket sessions, it will
           be called immediately after the connection is opened.

        """

        pass # pragma: no cover

    def data_received(self, data, datatype):
        """Called when data is received on the channel

           This method is called when data is received on the channel.
           If an encoding was specified when the channel was created,
           the data will be delivered as a string after decoding with
           the requested encoding. Otherwise, the data will be delivered
           as bytes.

           :param data:
               The data received on the channel
           :param datatype:
               The extended data type of the data, from :ref:`extended
               data types <ExtendedDataTypes>`
           :type data: str or bytes

        """

        pass # pragma: no cover

    def eof_received(self):
        """Called when EOF is received on the channel

           This method is called when an end-of-file indication is received
           on the channel, after which no more data will be received. If this
           method returns ``True``, the channel remains half open and data
           may still be sent. Otherwise, the channel is automatically closed
           after this method returns. This is the default behavior for
           classes derived directly from :class:`SSHSession`, but not when
           using the higher-level streams API. Because input is buffered
           in that case, streaming sessions enable half-open channels to
           allow applications to respond to input read after an end-of-file
           indication is received.

        """

        # pylint: disable=no-self-use

        return False # pragma: no cover

    def pause_writing(self):
        """Called when the write buffer becomes full

           This method is called when the channel's write buffer becomes
           full and no more data can be sent until the remote system
           adjusts its window. While data can still be buffered locally,
           applications may wish to stop producing new data until the
           write buffer has drained.

        """

        pass # pragma: no cover

    def resume_writing(self):
        """Called when the write buffer has sufficiently drained

           This method is called when the channel's send window reopens
           and enough data has drained from the write buffer to allow the
           application to produce more data.

        """

        pass # pragma: no cover


class SSHClientSession(SSHSession):
    """SSH client session handler

       Applications should subclass this when implementing an SSH client
       session handler. The functions listed below should be implemented
       to define application-specific behavior. In particular, the standard
       ``asyncio`` protocol methods such as :meth:`connection_made`,
       :meth:`connection_lost`, :meth:`data_received`, :meth:`eof_received`,
       :meth:`pause_writing`, and :meth:`resume_writing` are all supported.
       In addition, :meth:`session_started` is called as soon as the SSH
       session is fully started, :meth:`xon_xoff_requested` can be used to
       determine if the server wants the client to support XON/XOFF flow
       control, and :meth:`exit_status_received` and
       :meth:`exit_signal_received` can be used to receive session exit
       information.

    """

    def xon_xoff_requested(self, client_can_do):
        """XON/XOFF flow control has been enabled or disabled

           This method is called to notify the client whether or not
           to enable XON/XOFF flow control. If client_can_do is
           ``True`` and output is being sent to an interactive
           terminal the application should allow input of Control-S
           and Control-Q to pause and resume output, respectively.
           If client_can_do is ``False``, Control-S and Control-Q
           should be treated as normal input and passed through to
           the server. Non-interactive applications can ignore this
           request.

           By default, this message is ignored.

           :param bool client_can_do:
               Whether or not to enable XON/XOFF flow control

        """

        pass # pragma: no cover

    def exit_status_received(self, status):
        """A remote exit status has been received for this session

           This method is called when the shell, command, or subsystem
           running on the server terminates and returns an exit status.
           A zero exit status generally means that the operation was
           successful. This call will generally be followed by a call
           to :meth:`connection_lost`.

           By default, the exit status is ignored.

           :param int status:
               The exit status returned by the remote process

        """

        pass # pragma: no cover

    def exit_signal_received(self, signal, core_dumped, msg, lang):
        """A remote exit signal has been received for this session

           This method is called when the shell, command, or subsystem
           running on the server terminates abnormally with a signal.
           A more detailed error may also be provided, along with an
           indication of whether the remote process dumped core. This call
           will generally be followed by a call to :meth:`connection_lost`.

           By default, exit signals are ignored.

           :param str signal:
               The signal which caused the remote process to exit
           :param bool core_dumped:
               Whether or not the remote process dumped core
           :param msg:
               Details about what error occurred
           :param lang:
               The language the error message is in

        """

        pass # pragma: no cover


class SSHServerSession(SSHSession):
    """SSH server session handler

       Applications should subclass this when implementing an SSH server
       session handler. The functions listed below should be implemented
       to define application-specific behavior. In particular, the
       standard ``asyncio`` protocol methods such as :meth:`connection_made`,
       :meth:`connection_lost`, :meth:`data_received`, :meth:`eof_received`,
       :meth:`pause_writing`, and :meth:`resume_writing` are all supported.
       In addition, :meth:`pty_requested` is called when the client requests a
       pseudo-terminal, one of :meth:`shell_requested`, :meth:`exec_requested`,
       or :meth:`subsystem_requested` is called depending on what type of
       session the client wants to start, :meth:`session_started` is called
       once the SSH session is fully started, :meth:`terminal_size_changed` is
       called when the client's terminal size changes, :meth:`signal_received`
       is called when the client sends a signal, and :meth:`break_received`
       is called when the client sends a break.

    """

    def pty_requested(self, term_type, term_size, term_modes):
        """A psuedo-terminal has been requested

           This method is called when the client sends a request to allocate
           a pseudo-terminal with the requested terminal type, size, and
           POSIX terminal modes. This method should return ``True`` if the
           request for the pseudo-terminal is accepted. Otherwise, it should
           return ``False`` to reject the request.

           By default, requests to allocate a pseudo-terminal are accepted
           but nothing is done with the associated terminal information.
           Applications wishing to use this information should implement
           this method and have it return ``True``, or call
           :meth:`get_terminal_type() <SSHServerChannel.get_terminal_type>`,
           :meth:`get_terminal_size() <SSHServerChannel.get_terminal_size>`,
           or :meth:`get_terminal_mode() <SSHServerChannel.get_terminal_mode>`
           on the :class:`SSHServerChannel` to get the information they need
           after a shell, command, or subsystem is started.

           :param str term_type:
               Terminal type to set for this session
           :param tuple term_size:
               Terminal size to set for this session provided as a
               tuple of four integers: the width and height of the
               terminal in characters followed by the width and height
               of the terminal in pixels
           :param dictionary term_modes:
               POSIX terminal modes to set for this session, where keys
               are taken from :ref:`POSIX terminal modes <PTYModes>` with
               values defined in section 8 of :rfc:`4254#section-8`.

           :returns: A bool indicating if the request for a
                     pseudo-terminal was allowed or not

        """

        # pylint: disable=no-self-use,unused-argument

        return True # pragma: no cover

    def terminal_size_changed(self, width, height, pixwidth, pixheight):
        """The terminal size has changed

           This method is called when a client requests a
           pseudo-terminal and again whenever the the size of
           he client's terminal window changes.

           By default, this information is ignored, but applications
           wishing to use the terminal size can implement this method
           to get notified whenever it changes.

           :param int width:
               The width of the terminal in characters
           :param int height:
               The height of the terminal in characters
           :param int pixwidth: (optional)
               The width of the terminal in pixels
           :param int pixheight: (optional)
               The height of the terminal in pixels

        """

        # pylint: disable=no-self-use,unused-argument

        pass # pragma: no cover

    def shell_requested(self):
        """The client has requested a shell

           This method should be implemented by the application to
           perform whatever processing is required when a client makes
           a request to open an interactive shell. It should return
           ``True`` to accept the request, or ``False`` to reject it.

           If the application returns ``True``, the :meth:`session_started`
           method will be called once the channel is fully open. No output
           should be sent until this method is called.

           By default this method returns ``False`` to reject all requests.

           :returns: A bool indicating if the shell request was
                     allowed or not

        """

        # pylint: disable=no-self-use,unused-argument

        return False # pragma: no cover

    def exec_requested(self, command):
        """The client has requested to execute a command

           This method should be implemented by the application to
           perform whatever processing is required when a client makes
           a request to execute a command. It should return ``True`` to
           accept the request, or ``False`` to reject it.

           If the application returns ``True``, the :meth:`session_started`
           method will be called once the channel is fully open. No output
           should be sent until this method is called.

           By default this method returns ``False`` to reject all requests.

           :param str command:
               The command the client has requested to execute

           :returns: A bool indicating if the exec request was
                     allowed or not

        """

        # pylint: disable=no-self-use,unused-argument

        return False # pragma: no cover

    def subsystem_requested(self, subsystem):
        """The client has requested to start a subsystem

           This method should be implemented by the application to
           perform whatever processing is required when a client makes
           a request to start a subsystem. It should return ``True`` to
           accept the request, or ``False`` to reject it.

           If the application returns ``True``, the :meth:`session_started`
           method will be called once the channel is fully open. No output
           should be sent until this method is called.

           By default this method returns ``False`` to reject all requests.

           :param str subsystem:
               The subsystem to start

           :returns: A bool indicating if the request to open the
                     subsystem was allowed or not

        """

        # pylint: disable=no-self-use,unused-argument

        return False # pragma: no cover

    def break_received(self, msec):
        """The client has sent a break

           This method is called when the client requests that the
           server perform a break operation on the terminal. If the
           break is performed, this method should return ``True``.
           Otherwise, it should return ``False``.

           By default, this method returns ``False`` indicating that
           no break was performed.

           :param int msec:
               The duration of the break in milliseconds

           :returns: A bool to indicate if the break operation was
                     performed or not

        """

        # pylint: disable=no-self-use,unused-argument

        return False # pragma: no cover

    def signal_received(self, signal):
        """The client has sent a signal

           This method is called when the client delivers a signal
           on the channel.

           By default, signals from the client are ignored.

        """

        # pylint: disable=no-self-use,unused-argument

        pass # pragma: no cover


class SSHTCPSession(SSHSession):
    """SSH TCP session handler

       Applications should subclass this when implementing a handler for
       SSH direct or forwarded TCP connections.

       SSH client applications wishing to open a direct connection should call
       :meth:`create_connection() <SSHClientConnection.create_connection>`
       on their :class:`SSHClientConnection`, passing in a factory which
       returns instances of this class.

       Server applications wishing to allow direct connections should
       implement the coroutine :meth:`connection_requested()
       <SSHServer.connection_requested>` on their :class:`SSHServer`
       object and have it return instances of this class.

       Server applications wishing to allow connection forwarding back
       to the client should implement the coroutine :meth:`server_requested()
       <SSHServer.server_requested>` on their :class:`SSHServer` object
       and call :meth:`create_connection()
       <SSHServerConnection.create_connection>` on their
       :class:`SSHServerConnection` for each new connection, passing it a
       factory which returns instances of this class.

       When a connection is successfully opened, :meth:`session_started`
       will be called, after which the application can begin sending data.
       Received data will be passed to the :meth:`data_received` method.

    """


class SSHUNIXSession(SSHSession):
    """SSH UNIX domain socket session handler

       Applications should subclass this when implementing a handler for
       SSH direct or forwarded UNIX domain socket connections.

       SSH client applications wishing to open a direct connection should call
       :meth:`create_unix_connection()
       <SSHClientConnection.create_unix_connection>` on their
       :class:`SSHClientConnection`, passing in a factory which returns
       instances of this class.

       Server applications wishing to allow direct connections should
       implement the coroutine :meth:`unix_connection_requested()
       <SSHServer.unix_connection_requested>` on their :class:`SSHServer`
       object and have it return instances of this class.

       Server applications wishing to allow connection forwarding back
       to the client should implement the coroutine
       :meth:`unix_server_requested() <SSHServer.unix_server_requested>`
       on their :class:`SSHServer` object and call
       :meth:`create_unix_connection()
       <SSHServerConnection.create_unix_connection>` on their
       :class:`SSHServerConnection` for each new connection, passing it a
       factory which returns instances of this class.

       When a connection is successfully opened, :meth:`session_started`
       will be called, after which the application can begin sending data.
       Received data will be passed to the :meth:`data_received` method.

    """
