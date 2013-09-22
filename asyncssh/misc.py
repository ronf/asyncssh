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


class SSHError(Exception):
    """General SSH error
    
       This exception is returned when a general SSH error occurs,
       causing the SSH connection to be disconnected. Exception codes
       should be taken from :ref:`disconnect reason codes <DisconnectReasons>`.
       
       :param integer code:
           Disconnect reason, taken from :ref:`disconnect reason
           codes <DisconnectReasons>`.
       :param string reason:
           A human-readable reason for the disconnect.
       :param string lang:
           The language the reason is in.

    """

    def __init__(self, code, reason, lang=DEFAULT_LANG):
        self.code = code
        self.reason = reason
        self.lang = lang

    def __str__(self):
        return 'SSH Error: %s' % self.reason

class ChannelOpenError(SSHError):
    """SSH channel open error

       This exception is returned by connection handlers to report
       channel open failures.

       :param integer code:
           Channel open failure  reason, taken from :ref:`channel open
           failure reason codes <ChannelOpenFailureReasons>`.
       :param string reason:
           A human-readable reason for the channel open failure.
       :param string lang:
           The language the reason is in.

    """

    def __str__(self):
        return 'Channel Open Error: %s' % self.reason
