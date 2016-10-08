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

"""Miscellaneous utility classes and functions"""

import asyncio
import functools
import ipaddress
import os
import platform
import socket

from collections import OrderedDict
from random import SystemRandom

import asyncssh

from .constants import DEFAULT_LANG


# Provide globals to test if we're on various Python versions
python344 = platform.python_version_tuple() >= ('3', '4', '4')
python35 = platform.python_version_tuple() >= ('3', '5', '0')
python352 = platform.python_version_tuple() >= ('3', '5', '2')


# Define a version of randrange which is based on SystemRandom(), so that
# we get back numbers suitable for cryptographic use.
_random = SystemRandom()
randrange = _random.randrange


# Avoid deprecation warning for asyncio.async()
if python344:
    ensure_future = asyncio.ensure_future
else: # pragma: no cover
    ensure_future = asyncio.async    # pylint: disable=deprecated-method


def all_ints(seq):
    """Return if a sequence contains all integers"""

    return all(isinstance(i, int) for i in seq)


# Default file names in .ssh directory to read private keys from
_DEFAULT_KEY_FILES = ('id_ed25519', 'id_ecdsa', 'id_rsa', 'id_dsa')

def load_default_keypairs(passphrase=None):
    """Return a list of default keys from the user's home directory"""

    result = []

    for file in _DEFAULT_KEY_FILES:
        try:
            file = os.path.join(os.path.expanduser('~'), '.ssh', file)
            result.extend(asyncssh.load_keypairs(file, passphrase))
        except OSError:
            pass

    return result


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
       so we strip off the CIDR suffix here and normalize scoped IP
       addresses using socket.inet_pton before we pass them into
       ipaddress.

    """

    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            return socket.inet_ntop(family, socket.inet_pton(family, addr))
        except (ValueError, socket.error):
            pass

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


if python352:
    async_iterator = lambda iter: iter
else:
    async_iterator = asyncio.coroutine


def async_context_manager(coro):
    """Decorator for methods returning asynchronous context managers

       This function can be used as a decorator for coroutines which
       return objects intended to be used as Python 3.5 asynchronous
       context managers. The object returned should implement __aenter__
       and __aexit__ methods to run when the async context is entered
       and exited.

       This wrapper also allows non-async context managers to be defined
       on the returned object, as well as the use of "await" or "yield
       from" on the function being decorated for backward compatibility
       with the API defined by older versions of AsyncSSH.

    """

    class AsyncContextManager:
        """Async context manager wrapper for Python 3.5 and later"""

        def __init__(self, coro):
            self._coro = coro
            self._result = None

        def __iter__(self):
            return (yield from self._coro)

        def __await__(self):
            return (yield from self._coro)

        @asyncio.coroutine
        def __aenter__(self):
            self._result = yield from self._coro
            return (yield from self._result.__aenter__())

        @asyncio.coroutine
        def __aexit__(self, *exc_info):
            yield from self._result.__aexit__(*exc_info)
            self._result = None

    @functools.wraps(coro)
    def coro_wrapper(*args, **kwargs):
        """Return an async context manager wrapper for this coroutine"""

        return AsyncContextManager(asyncio.coroutine(coro)(*args, **kwargs))

    if python35:
        return coro_wrapper
    else:
        return coro


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


class Error(Exception):
    """General SSH error"""

    def __init__(self, errtype, code, reason, lang):
        super().__init__('%s Error: %s' % (errtype, reason))
        self.code = code
        self.reason = reason
        self.lang = lang


class DisconnectError(Error):
    """SSH disconnect error

       This exception is raised when a serious error occurs which causes
       the SSH connection to be disconnected. Exception codes should be
       taken from :ref:`disconnect reason codes <DisconnectReasons>`.

       :param int code:
           Disconnect reason, taken from :ref:`disconnect reason
           codes <DisconnectReasons>`
       :param str reason:
           A human-readable reason for the disconnect
       :param str lang:
           The language the reason is in

    """

    def __init__(self, code, reason, lang=DEFAULT_LANG):
        super().__init__('Disconnect', code, reason, lang)


class ChannelOpenError(Error):
    """SSH channel open error

       This exception is raised by connection handlers to report
       channel open failures.

       :param int code:
           Channel open failure  reason, taken from :ref:`channel open
           failure reason codes <ChannelOpenFailureReasons>`
       :param str reason:
           A human-readable reason for the channel open failure
       :param str lang:
           The language the reason is in

    """

    def __init__(self, code, reason, lang=DEFAULT_LANG):
        super().__init__('Channel Open', code, reason, lang)


class PasswordChangeRequired(Exception):
    """SSH password change required

       This exception is raised during password validation on the
       server to indicate that a password change is required. It
       shouuld be raised when the password provided is valid but
       expired, to trigger the client to provide a new password.

       :param str prompt:
           The prompt requesting that the user enter a new password
       :param str lang:
           The language that the prompt is in

    """

    def __init__(self, prompt, lang=DEFAULT_LANG):
        super().__init__('Password change required: %s' % prompt)
        self.prompt = prompt
        self.lang = lang


class BreakReceived(Exception):
    """SSH break request received

       This exception is raised on an SSH server stdin stream when the
       client sends a break on the channel.

       :param int msec:
           The duration of the break in milliseconds

    """

    def __init__(self, msec):
        super().__init__('Break for %s msec' % msec)
        self.msec = msec


class SignalReceived(Exception):
    """SSH signal request received

       This exception is raised on an SSH server stdin stream when the
       client sends a signal on the channel.

       :param str signal:
           The name of the signal sent by the client

    """

    def __init__(self, signal):
        super().__init__('Signal: %s' % signal)
        self.signal = signal


class TerminalSizeChanged(Exception):
    """SSH terminal size change notification received

       This exception is raised on an SSH server stdin stream when the
       client sends a terminal size change on the channel.

       :param int width:
           The new terminal width
       :param int height:
           The new terminal height
       :param int pixwidth:
           The new terminal width in pixels
       :param int pixheight:
           The new terminal height in pixels

    """

    def __init__(self, width, height, pixwidth, pixheight):
        super().__init__('Terminal size change: (%s, %s, %s, %s)' %
                         (width, height, pixwidth, pixheight))
        self.width = width
        self.height = height
        self.pixwidth = pixwidth
        self.pixheight = pixheight
