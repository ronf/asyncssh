# Copyright (c) 2015-2019 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Pattern matching for principal and host names"""

from fnmatch import fnmatch

from .misc import ip_network


class WildcardPattern:
    """A pattern matcher for '*' and '?' wildcards"""

    def __init__(self, pattern):
        # We need to escape square brackets in host patterns if we
        # want to use Python's fnmatch.
        self._pattern = ''.join('[[]' if ch == '[' else
                                '[]]' if ch == ']' else
                                ch for ch in pattern)

    def matches(self, value):
        """Return whether a wild card pattern matches a value"""

        return fnmatch(value, self._pattern)


class WildcardHostPattern(WildcardPattern):
    """Match a host name or address against a wildcard pattern"""

    def matches(self, host, addr, _ip):
        """Return whether a host or address matches a wild card host pattern"""

        # Arguments vary by class, but inheritance is still needed here
        # pylint: disable=arguments-differ

        return (host and super().matches(host)) or \
               (addr and super().matches(addr))


class CIDRHostPattern:
    """Match IPv4/v6 address against CIDR-style subnet pattern"""

    def __init__(self, pattern):
        self._network = ip_network(pattern)

    def matches(self, _host, _addr, ip):
        """Return whether an IP address matches a CIDR address pattern"""

        return ip and ip in self._network


class _PatternList:
    """Match against a list of comma-separated positive and negative patterns

       This class is a base class for building a pattern matcher that
       takes a set of comma-separated positive and negative patterns,
       returning `True` if one or more positive patterns match and
       no negative ones do.

       The pattern matching is done by objects returned by the
       build_pattern method. The arguments passed in when a match
       is performed will vary depending on what class build_pattern
       returns.

    """

    def __init__(self, patterns):
        self._pos_patterns = []
        self._neg_patterns = []

        for pattern in patterns.split(','):
            if pattern.startswith('!'):
                negate = True
                pattern = pattern[1:]
            else:
                negate = False

            matcher = self.build_pattern(pattern)

            if negate:
                self._neg_patterns.append(matcher)
            else:
                self._pos_patterns.append(matcher)

    def build_pattern(self, pattern):
        """Abstract method to build a pattern object"""

        raise NotImplementedError

    def matches(self, *args):
        """Match a set of values against positive & negative pattern lists"""

        pos_match = any(p.matches(*args) for p in self._pos_patterns)
        neg_match = any(p.matches(*args) for p in self._neg_patterns)

        return pos_match and not neg_match


class WildcardPatternList(_PatternList):
    """Match names against wildcard patterns"""

    def build_pattern(self, pattern):
        """Build a wild card pattern"""

        return WildcardPattern(pattern)


class HostPatternList(_PatternList):
    """Match host names & addresses against wildcard and CIDR patterns"""

    def build_pattern(self, pattern):
        """Build a CIDR address or wild card host pattern"""

        try:
            return CIDRHostPattern(pattern)
        except ValueError:
            return WildcardHostPattern(pattern)
