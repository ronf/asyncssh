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

"""Miscellaneous utility classes and functions"""

import codecs
import functools
import ipaddress
import re
import socket

from collections import OrderedDict
from pathlib import Path
from random import SystemRandom

from .constants import DEFAULT_LANG
from .constants import DISC_COMPRESSION_ERROR, DISC_CONNECTION_LOST
from .constants import DISC_HOST_KEY_NOT_VERIFIABLE, DISC_ILLEGAL_USER_NAME
from .constants import DISC_KEY_EXCHANGE_FAILED, DISC_MAC_ERROR
from .constants import DISC_NO_MORE_AUTH_METHODS_AVAILABLE
from .constants import DISC_PROTOCOL_ERROR, DISC_PROTOCOL_VERSION_NOT_SUPPORTED
from .constants import DISC_SERVICE_NOT_AVAILABLE


# Define a version of randrange which is based on SystemRandom(), so that
# we get back numbers suitable for cryptographic use.
_random = SystemRandom()
randrange = _random.randrange

_unit_pattern = re.compile(r'([A-Za-z])')
_byte_units = {'': 1, 'k': 1024, 'm': 1024*1024, 'g': 1024*1024*1024}
_time_units = {'': 1, 's': 1, 'm': 60, 'h': 60*60,
               'd': 24*60*60, 'w': 7*24*60*60}


def hide_empty(value, prefix=', '):
    """Return a string with optional prefix if value is non-empty"""

    value = str(value)
    return prefix + value if value else ''


def plural(length, label, suffix='s'):
    """Return a label with an optional plural suffix"""

    return '%d %s%s' % (length, label, suffix if length != 1 else '')


def to_hex(data):
    """Convert binary data to a hex string"""

    return codecs.encode(data, 'hex')


def all_ints(seq):
    """Return if a sequence contains all integers"""

    return all(isinstance(i, int) for i in seq)


def get_symbol_names(symbols, prefix, strip_leading=0):
    """Return a mapping from values to symbol names for logging"""

    return {value: name[strip_leading:] for name, value in symbols.items()
            if name.startswith(prefix)}


# Punctuation to map when creating handler names
_HANDLER_PUNCTUATION = (('@', '_at_'), ('.', '_dot_'), ('-', '_'))

def map_handler_name(name):
    """Map punctuation so a string can be used as a handler name"""

    for old, new in _HANDLER_PUNCTUATION:
        name = name.replace(old, new)

    return name


def _normalize_scoped_ip(addr):
    """Normalize scoped IP address

       The ipaddress module doesn't handle scoped addresses properly,
       so we normalize scoped IP addresses using socket.getaddrinfo
       before we pass them into ip_address/ip_network.

    """

    try:
        addrinfo = socket.getaddrinfo(addr, None, family=socket.AF_UNSPEC,
                                      type=socket.SOCK_STREAM,
                                      flags=socket.AI_NUMERICHOST)[0]
    except socket.gaierror:
        return addr

    if addrinfo[0] == socket.AF_INET6:
        sa = addrinfo[4]
        addr = sa[0]

        idx = addr.find('%')
        if idx >= 0: # pragma: no cover
            addr = addr[:idx]

        ip = ipaddress.ip_address(addr)

        if ip.is_link_local:
            addr = str(ipaddress.ip_address(int(ip) | (sa[3] << 96)))

    return addr


def ip_address(addr):
    """Wrapper for ipaddress.ip_address which supports scoped addresses"""

    return ipaddress.ip_address(_normalize_scoped_ip(addr))


def ip_network(addr):
    """Wrapper for ipaddress.ip_network which supports scoped addresses"""

    idx = addr.find('/')
    if idx >= 0:
        addr, mask = addr[:idx], addr[idx:]
    else:
        mask = ''

    return ipaddress.ip_network(_normalize_scoped_ip(addr) + mask)


def open_file(filename, *args, **kwargs):
    """Open a file with home directory expansion"""

    return open(Path(filename).expanduser(), *args, **kwargs)


def read_file(filename, mode='rb'):
    """Read from a file with home directory expansion"""

    with open_file(filename, mode) as f:
        return f.read()


def write_file(filename, data, mode='wb'):
    """Write or append to a file with home directory expansion"""

    with open_file(filename, mode) as f:
        return f.write(data)


def _parse_units(value, suffixes, label):
    """Parse a series of integers followed by unit suffixes"""

    matches = _unit_pattern.split(value)

    if matches[-1]:
        matches.append('')
    else:
        matches.pop()

    try:
        return sum(float(matches[i]) * suffixes[matches[i+1].lower()]
                   for i in range(0, len(matches), 2))
    except KeyError:
        raise ValueError('Invalid ' + label) from None


def parse_byte_count(value):
    """Parse a byte count with optional k, m, or g suffixes"""

    return _parse_units(value, _byte_units, 'byte count')


def parse_time_interval(value):
    """Parse a time interval with optional s, m, h, d, or w suffixes"""

    return _parse_units(value, _time_units, 'time interval')


def async_context_manager(coro):
    """Decorator for functions returning asynchronous context managers

       This decorator can be used on functions which return objects
       intended to be async context managers. The object returned by
       the function should implement __aenter__ and __aexit__ methods
       to run when the async context is entered and exited.

       This wrapper also allows the use of "await" on the function being
       decorated, to return the context manager without entering it.

    """

    class AsyncContextManager:
        """Async context manager wrapper"""

        def __init__(self, coro):
            self._coro = coro
            self._result = None

        def __await__(self):
            return self._coro.__await__()

        async def __aenter__(self):
            self._result = await self._coro
            return await self._result.__aenter__()

        async def __aexit__(self, *exc_info):
            await self._result.__aexit__(*exc_info)
            self._result = None

    @functools.wraps(coro)
    def context_wrapper(*args, **kwargs):
        """Return an async context manager wrapper for this coroutine"""

        return AsyncContextManager(coro(*args, **kwargs))

    return context_wrapper


async def maybe_wait_closed(writer):
    """Wait for a StreamWriter to close, if Python version supports it

       Python 3.8 triggers a false error report about garbage collecting
       an open stream if a close is in progress when a StreamWriter is
       garbage collected. This can be avoided by calling wait_closed(),
       but that method is not available in Python releases prior to 3.7.
       This function wraps this call, ignoring the error if the method
       is not available.

    """

    try:
        await writer.wait_closed()
    except AttributeError: # pragma: no cover
        pass


class Options:
    """Container for configuration options"""

    def __init__(self, options=None, **kwargs):
        if options:
            if not isinstance(options, type(self)):
                raise TypeError('Invalid %s, got %s' %
                                (type(self).__name__, type(options).__name__))

            self.kwargs = options.kwargs.copy()
        else:
            self.kwargs = {}

        self.kwargs.update(kwargs)
        self.prepare(**self.kwargs)

    def prepare(self):
        """Pre-process configuration options"""

    def update(self, kwargs):
        """Update options based on keyword parameters passed in"""

        self.kwargs.update(kwargs)
        self.prepare(**self.kwargs)


class Record:
    """General-purpose record type with fixed set of fields"""

    __slots__ = OrderedDict()

    def __init__(self, *args, **kwargs):
        for k, v in self.__slots__.items():
            setattr(self, k, v)

        for k, v in zip(self.__slots__, args):
            setattr(self, k, v)

        for k, v in kwargs.items():
            setattr(self, k, v)

    def __repr__(self):
        return '%s(%s)' % (type(self).__name__,
                           ', '.join('%s=%r' % (k, getattr(self, k))
                                     for k in self.__slots__))

    def __str__(self):
        values = ((k, self._format(k, getattr(self, k)))
                  for k in self.__slots__)

        return ', '.join('%s: %s' % (k, v) for k, v in values if v is not None)

    def _format(self, k, v):
        """Format a field as a string"""

        # pylint: disable=no-self-use,unused-argument

        return str(v)


class Error(Exception):
    """General SSH error"""

    def __init__(self, code, reason, lang=DEFAULT_LANG):

        super().__init__(reason)
        self.code = code
        self.reason = reason
        self.lang = lang


class DisconnectError(Error):
    """SSH disconnect error

       This exception is raised when a serious error occurs which causes
       the SSH connection to be disconnected. Exception codes should be
       taken from :ref:`disconnect reason codes <DisconnectReasons>`.
       See below for exception subclasses tied to specific disconnect
       reasons if you want to customize your handling by reason.

       :param code:
           Disconnect reason, taken from :ref:`disconnect reason
           codes <DisconnectReasons>`
       :param reason:
           A human-readable reason for the disconnect
       :param lang: (optional)
           The language the reason is in
       :type code: `int`
       :type reason: `str`
       :type lang: `str`

    """


class CompressionError(DisconnectError):
    """SSH compression error

       This exception is raised when an error occurs while compressing
       or decompressing data sent on the SSH connection.

       :param reason:
           Details about the compression error
       :param lang: (optional)
           The language the reason is in
       :type reason: `str`
       :type lang: `str`

    """

    def __init__(self, reason, lang=DEFAULT_LANG):
        super().__init__(DISC_COMPRESSION_ERROR, reason, lang)


class ConnectionLost(DisconnectError):
    """SSH connection lost

       This exception is raised when the SSH connection to the remote
       system is unexpectedly lost. It can also occur as a result of
       the remote system failing to respond to keepalive messages or
       as a result of a login timeout, when those features are enabled.

       :param reason:
           Details about the connection failure
       :param lang: (optional)
           The language the reason is in
       :type reason: `str`
       :type lang: `str`

    """

    def __init__(self, reason, lang=DEFAULT_LANG):
        super().__init__(DISC_CONNECTION_LOST, reason, lang)


class HostKeyNotVerifiable(DisconnectError):
    """SSH host key not verifiable

       This exception is raised when the SSH server's host key or
       certificate is not verifiable.

       :param reason:
           Details about the host key verification failure
       :param lang: (optional)
           The language the reason is in
       :type reason: `str`
       :type lang: `str`

    """

    def __init__(self, reason, lang=DEFAULT_LANG):
        super().__init__(DISC_HOST_KEY_NOT_VERIFIABLE, reason, lang)


class IllegalUserName(DisconnectError):
    """SSH illegal user name

       This exception is raised when an error occurs while processing
       the username sent during the SSL handshake.

       :param reason:
           Details about the illegal username
       :param lang: (optional)
           The language the reason is in
       :type reason: `str`
       :type lang: `str`

    """

    def __init__(self, reason, lang=DEFAULT_LANG):
        super().__init__(DISC_ILLEGAL_USER_NAME, reason, lang)


class KeyExchangeFailed(DisconnectError):
    """SSH key exchange failed

       This exception is raised when the SSH key exchange fails.

       :param reason:
           Details about the connection failure
       :param lang: (optional)
           The language the reason is in
       :type reason: `str`
       :type lang: `str`

    """

    def __init__(self, reason, lang=DEFAULT_LANG):
        super().__init__(DISC_KEY_EXCHANGE_FAILED, reason, lang)


class MACError(DisconnectError):
    """SSH MAC error

       This exception is raised when an error occurs while processing
       the message authentication code (MAC) of a message on the SSH
       connection.

       :param reason:
           Details about the MAC error
       :param lang: (optional)
           The language the reason is in
       :type reason: `str`
       :type lang: `str`

    """

    def __init__(self, reason, lang=DEFAULT_LANG):
        super().__init__(DISC_MAC_ERROR, reason, lang)


class PermissionDenied(DisconnectError):
    """SSH permission denied

       This exception is raised when there are no authentication methods
       remaining to complete SSH client authentication.

       :param reason:
           Details about the SSH protocol error detected
       :param lang: (optional)
           The language the reason is in
       :type reason: `str`
       :type lang: `str`

    """

    def __init__(self, reason, lang=DEFAULT_LANG):
        super().__init__(DISC_NO_MORE_AUTH_METHODS_AVAILABLE, reason, lang)


class ProtocolError(DisconnectError):
    """SSH protocol error

       This exception is raised when the SSH connection is disconnected
       due to an SSH protocol error being detected.

       :param reason:
           Details about the SSH protocol error detected
       :param lang: (optional)
           The language the reason is in
       :type reason: `str`
       :type lang: `str`

    """

    def __init__(self, reason, lang=DEFAULT_LANG):
        super().__init__(DISC_PROTOCOL_ERROR, reason, lang)


class ProtocolNotSupported(DisconnectError):
    """SSH protocol not supported

       This exception is raised when the remote system sends an SSH
       protocol version which is not supported.

       :param reason:
           Details about the unsupported SSH protocol version
       :param lang: (optional)
           The language the reason is in
       :type reason: `str`
       :type lang: `str`

    """

    def __init__(self, reason, lang=DEFAULT_LANG):
        super().__init__(DISC_PROTOCOL_ERROR, reason, lang)


class ServiceNotAvailable(DisconnectError):
    """SSH service not available

       This exception is raised when an unexpected service name is
       received during the SSH handshake.

       :param reason:
           Details about the unexpected SSH service
       :param lang: (optional)
           The language the reason is in
       :type reason: `str`
       :type lang: `str`

    """

    def __init__(self, reason, lang=DEFAULT_LANG):
        super().__init__(DISC_SERVICE_NOT_AVAILABLE, reason, lang)


class ChannelOpenError(Error):
    """SSH channel open error

       This exception is raised by connection handlers to report
       channel open failures.

       :param code:
           Channel open failure reason, taken from :ref:`channel open
           failure reason codes <ChannelOpenFailureReasons>`
       :param reason:
           A human-readable reason for the channel open failure
       :param lang:
           The language the reason is in
       :type code: `int`
       :type reason: `str`
       :type lang: `str`

    """


class ChannelListenError(Exception):
    """SSH channel listen error

       This exception is raised to report failures in setting up
       remote SSH connection listeners.

       :param details:
           Details of the listen failure
       :type details: `str`

    """


class PasswordChangeRequired(Exception):
    """SSH password change required

       This exception is raised during password validation on the
       server to indicate that a password change is required. It
       should be raised when the password provided is valid but
       expired, to trigger the client to provide a new password.

       :param prompt:
           The prompt requesting that the user enter a new password
       :param lang:
           The language that the prompt is in
       :type prompt: `str`
       :type lang: `str`

    """

    def __init__(self, prompt, lang=DEFAULT_LANG):
        super().__init__('Password change required: %s' % prompt)
        self.prompt = prompt
        self.lang = lang


class BreakReceived(Exception):
    """SSH break request received

       This exception is raised on an SSH server stdin stream when the
       client sends a break on the channel.

       :param msec:
           The duration of the break in milliseconds
       :type msec: `int`

    """

    def __init__(self, msec):
        super().__init__('Break for %s msec' % msec)
        self.msec = msec


class SignalReceived(Exception):
    """SSH signal request received

       This exception is raised on an SSH server stdin stream when the
       client sends a signal on the channel.

       :param signal:
           The name of the signal sent by the client
       :type signal: `str`

    """

    def __init__(self, signal):
        super().__init__('Signal: %s' % signal)
        self.signal = signal


class SoftEOFReceived(Exception):
    """SSH soft EOF request received

       This exception is raised on an SSH server stdin stream when the
       client sends an EOF from within the line editor on the channel.

    """

    def __init__(self):
        super().__init__('Soft EOF')


class TerminalSizeChanged(Exception):
    """SSH terminal size change notification received

       This exception is raised on an SSH server stdin stream when the
       client sends a terminal size change on the channel.

       :param width:
           The new terminal width
       :param height:
           The new terminal height
       :param pixwidth:
           The new terminal width in pixels
       :param pixheight:
           The new terminal height in pixels
       :type width: `int`
       :type height: `int`
       :type pixwidth: `int`
       :type pixheight: `int`

    """

    def __init__(self, width, height, pixwidth, pixheight):
        super().__init__('Terminal size change: (%s, %s, %s, %s)' %
                         (width, height, pixwidth, pixheight))
        self.width = width
        self.height = height
        self.pixwidth = pixwidth
        self.pixheight = pixheight


_disc_error_map = {
    DISC_PROTOCOL_ERROR: ProtocolError,
    DISC_KEY_EXCHANGE_FAILED: KeyExchangeFailed,
    DISC_MAC_ERROR: MACError,
    DISC_COMPRESSION_ERROR: CompressionError,
    DISC_SERVICE_NOT_AVAILABLE: ServiceNotAvailable,
    DISC_PROTOCOL_VERSION_NOT_SUPPORTED: ProtocolNotSupported,
    DISC_HOST_KEY_NOT_VERIFIABLE: HostKeyNotVerifiable,
    DISC_CONNECTION_LOST: ConnectionLost,
    DISC_NO_MORE_AUTH_METHODS_AVAILABLE: PermissionDenied,
    DISC_ILLEGAL_USER_NAME: IllegalUserName
}


def construct_disc_error(code, reason, lang):
    """Map disconnect error code to appropriate DisconnectError exception"""

    try:
        return _disc_error_map[code](reason, lang)
    except KeyError:
        return DisconnectError(code, '%s (error %d)' % (reason, code), lang)
