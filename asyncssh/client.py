# Copyright (c) 2013-2016 by Ron Frederick <ronf@timeheart.net>.
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

"""SSH client protocol handler"""


class SSHClient:
    """SSH client protocol handler

       Applications should subclass this when implementing an SSH client.
       The functions listed below should be overridden to define
       application-specific behavior. In particular, the method
       :meth:`auth_completed` should be defined to open the desired
       SSH channels on this connection once authentication has been
       completed.

       For simple password or public key based authentication, nothing
       needs to be defined here if the password or client keys are passed
       in when the connection is created. However, to prompt interactively
       or otherwise dynamically select these values, the methods
       :meth:`password_auth_requested` and/or :meth:`public_key_auth_requested`
       can be defined. Keyboard-interactive authentication is also supported
       via :meth:`kbdint_auth_requested` and :meth:`kbdint_challenge_received`.

       If the server sends an authentication banner, the method
       :meth:`auth_banner_received` will be called.

       If the server requires a password change, the method
       :meth:`password_change_requested` will be called, followed by either
       :meth:`password_changed` or :meth:`password_change_failed` depending
       on whether the password change is successful.

    """

    # pylint: disable=no-self-use,unused-argument

    def connection_made(self, connection):
        """Called when a connection is made

           This method is called as soon as the TCP connection completes. The
           connection parameter should be stored if needed for later use.

           :param connection:
               The connection which was successfully opened
           :type connection: :class:`SSHClientConnection`

        """

        pass # pragma: no cover

    def connection_lost(self, exc):
        """Called when a connection is lost or closed

           This method is called when a connection is closed. If the
           connection is shut down cleanly, *exc* will be ``None``.
           Otherwise, it will be an exception explaining the reason for
           the disconnect.

           :param exc:
               The exception which caused the connection to close, or
               ``None`` if the connection closed cleanly
           :type exc: :class:`Exception`

        """

        pass # pragma: no cover

    def debug_msg_received(self, msg, lang, always_display):
        """A debug message was received on this connection

           This method is called when the other end of the connection sends
           a debug message. Applications should implement this method if
           they wish to process these debug messages.

           :param str msg:
               The debug message sent
           :param str lang:
               The language the message is in
           :param bool always_display:
               Whether or not to display the message

        """

        pass # pragma: no cover

    def auth_banner_received(self, msg, lang):
        """An incoming authentication banner was received

           This method is called when the server sends a banner to display
           during authentication. Applications should implement this method
           if they wish to do something with the banner.

           :param str msg:
               The message the server wanted to display
           :param str lang:
               The language the message is in

        """

        pass # pragma: no cover

    def auth_completed(self):
        """Authentication was completed successfully

           This method is called when authentication has completed
           succesfully. Applications may use this method to create
           whatever client sessions and direct TCP/IP or UNIX domain
           connections are needed and/or set up listeners for incoming
           TCP/IP or UNIX domain connections coming from the server.

        """

        pass # pragma: no cover

    def public_key_auth_requested(self):
        """Public key authentication has been requested

           This method should return a private key corresponding to
           the user that authentication is being attempted for.

           This method may be called multiple times and can return a
           different key to try each time it is called. When there are
           no keys left to try, it should return ``None`` to indicate
           that some other authentication method should be tried.

           If client keys were provided when the connection was opened,
           they will be tried before this method is called.

           If blocking operations need to be performed to determine the
           key to authenticate with, this method may be defined as a
           coroutine.

           :returns: A key as described in :ref:`SpecifyingPrivateKeys`
                     or ``None`` to move on to another authentication
                     method

        """

        return None # pragma: no cover

    def password_auth_requested(self):
        """Password authentication has been requested

           This method should return a string containing the password
           corresponding to the user that authentication is being
           attempted for. It may be called multiple times and can
           return a different password to try each time, but most
           servers have a limit on the number of attempts allowed.
           When there's no password left to try, this method should
           return ``None`` to indicate that some other authentication
           method should be tried.

           If a password was provided when the connection was opened,
           it will be tried before this method is called.

           If blocking operations need to be performed to determine the
           password to authenticate with, this method may be defined as
           a coroutine.

           :returns: A string containing the password to authenticate
                     with or ``None`` to move on to another authentication
                     method

        """

        return None # pragma: no cover

    def password_change_requested(self, prompt, lang):
        """A password change has been requested

           This method is called when password authentication was
           attempted and the user's password was expired on the
           server. To request a password change, this method should
           return a tuple or two strings containing the old and new
           passwords. Otherwise, it should return ``NotImplemented``.

           If blocking operations need to be performed to determine the
           passwords to authenticate with, this method may be defined
           as a coroutine.

           By default, this method returns ``NotImplemented``.

           :param str prompt:
               The prompt requesting that the user enter a new password
           :param str lang:
               The language that the prompt is in

           :returns: A tuple of two strings containing the old and new
                     passwords or ``NotImplemented`` if password changes
                     aren't supported

        """

        return NotImplemented # pragma: no cover

    def password_changed(self):
        """The requested password change was successful

           This method is called to indicate that a requested password
           change was successful. It is generally followed by a call to
           :meth:`auth_completed` since this means authentication was
           also successful.

        """

        pass # pragma: no cover

    def password_change_failed(self):
        """The requested password change has failed

           This method is called to indicate that a requested password
           change failed, generally because the requested new password
           doesn't meet the password criteria on the remote system.
           After this method is called, other forms of authentication
           will automatically be attempted.

        """

        pass # pragma: no cover

    def kbdint_auth_requested(self):
        """Keyboard-interactive authentication has been requested

           This method should return a string containing a comma-separated
           list of submethods that the server should use for
           keyboard-interactive authentication. An empty string can be
           returned to let the server pick the type of keyboard-interactive
           authentication to perform. If keyboard-interactive authentication
           is not supported, ``None`` should be returned.

           By default, keyboard-interactive authentication is supported
           if a password was provided when the :class:`SSHClient` was
           created and it hasn't been sent yet. If the challenge is not
           a password challenge, this authentication will fail. This
           method and the :meth:`kbdint_challenge_received` method can be
           overridden if other forms of challenge should be supported.

           If blocking operations need to be performed to determine the
           submethods to request, this method may be defined as a
           coroutine.

           :returns: A string containing the submethods the server should
                     use for authentication or ``None`` to move on to
                     another authentication method

        """

        return NotImplemented # pragma: no cover

    def kbdint_challenge_received(self, name, instruction, lang, prompts):
        """A keyboard-interactive auth challenge has been received

           This method is called when the server sends a keyboard-interactive
           authentication challenge.

           The return value should be a list of strings of the same length
           as the number of prompts provided if the challenge can be
           answered, or ``None`` to indicate that some other form of
           authentication should be attempted.

           If blocking operations need to be performed to determine the
           responses to authenticate with, this method may be defined
           as a coroutine.

           By default, this method will look for a challenge consisting
           of a single 'Password:' prompt, and call the method
           :meth:`password_auth_requested` to provide the response.
           It will also ignore challenges with no prompts (generally used
           to provide instructions). Any other form of challenge will
           cause this method to return ``None`` to move on to another
           authentication method.

           :param str name:
               The name of the challenge
           :param str instruction:
               Instructions to the user about how to respond to the challenge
           :param str lang:
               The language the challenge is in
           :param prompts:
               The challenges the user should respond to and whether or
               not the responses should be echoed when they are entered
           :type prompts: list of tuples of str and bool

           :returns: List of string responses to the challenge or ``None``
                     to move on to another authentication method

        """

        return None # pragma: no cover
