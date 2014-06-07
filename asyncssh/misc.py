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

"""Miscellaneous utility classes and functions"""

from .constants import *

def all_ints(seq):
    """Return if a sequence contains all integers"""

    return all(isinstance(i, int) for i in seq)

def mod_inverse(x, m):
    """Compute the modular inverse (x^-1) modulo m"""

    a, b, c, d = m, x % m, 0, 1

    while b:
        q, r = divmod(a, b)
        a, b, c, d = b, r, d, c - q*d

    if a == 1:
        return c if c >= 0 else c + m
    else:
        raise ValueError('%d has no inverse mod %d' % (x, m))


class Error(Exception):
    """General SSH error"""

    def __init__(self, code, reason, lang=DEFAULT_LANG):
        self.code = code
        self.reason = reason
        self.lang = lang

    def __str__(self):
        return 'SSH Error: %s' % self.reason


class DisconnectError(Error):
    """SSH disconnect error

       This exception is raised when a serious error occurs which causes
       the SSH connection to be disconnected. Exception codes should be
       taken from :ref:`disconnect reason codes <DisconnectReasons>`.

       :param integer code:
           Disconnect reason, taken from :ref:`disconnect reason
           codes <DisconnectReasons>`
       :param string reason:
           A human-readable reason for the disconnect
       :param string lang:
           The language the reason is in

    """

    def __str__(self):
        return 'Disconnect Error: %s' % self.reason


class ChannelOpenError(Error):
    """SSH channel open error

       This exception is raised by connection handlers to report
       channel open failures.

       :param integer code:
           Channel open failure  reason, taken from :ref:`channel open
           failure reason codes <ChannelOpenFailureReasons>`
       :param string reason:
           A human-readable reason for the channel open failure
       :param string lang:
           The language the reason is in

    """

    def __str__(self):
        return 'Channel Open Error: %s' % self.reason


class BreakReceived(Exception):
    """SSH break request received

       This exception is raised on an SSH server stdin stream when the
       client sends a break on the channel.

       :param integer msec:
           The duration of the break in milliseconds

    """

    def __init__(self, msec):
        self.msec = msec

    def __str__(self):
        return 'Break for %s msec' % self.msec


class SignalReceived(Exception):
    """SSH signal request received

       This exception is raised on an SSH server stdin stream when the
       client sends a signal on the channel.

       :param string signal:
           The name of the signal sent by the client

    """

    def __init__(self, signal):
        self.signal = signal

    def __str__(self):
        return 'Signal: %s' % self.signal


class TerminalSizeChanged(Exception):
    """SSH terminal size change notification received

       This exception is raised on an SSH server stdin stream when the
       client sends a terminal size change on the channel.

       :param integer width:
           The new terminal width
       :param integer height:
           The new terminal height
       :param integer pixwidth:
           The new terminal width in pixels
       :param integer pixheight:
           The new terminal height in pixels

    """

    def __init__(self, width, height, pixwidth, pixheight):
        self.width = width
        self.height = height
        self.pixwidth = pixwidth
        self.pixheight = pixheight

    def __str__(self):
        return 'Terminal size change: (%s, %s, %s, %s)' % \
                   (self.width, self.height, self.pixwidth, self.pixheight)
