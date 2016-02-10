# Copyright (c) 2015 by Ron Frederick <ronf@timeheart.net>.
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
#     Alexander Travov - proposed changes to add negated patterns, hashed
#                        entries, and support for the revoked marker
#     Josh Yudaken - proposed change to split parsing and matching to avoid
#                    parsing large known_hosts lists multiple times

"""Parser for SSH known_hosts files"""

import binascii
import hmac
from hashlib import sha1

from .misc import ip_address
from .pattern import HostPatternList
from .public_key import KeyImportError, import_public_key


class _PlainHost:
    """A plain host entry in a known_hosts file"""

    def __init__(self, pattern):
        self._pattern = HostPatternList(pattern)

    def matches(self, host, addr, ip):
        """Return whether a host or address matches this host pattern list"""

        return self._pattern.matches(host, addr, ip)


class _HashedHost:
    """A hashed host entry in a known_hosts file"""

    _HMAC_SHA1_MAGIC = '1'

    def __init__(self, pattern):
        try:
            magic, salt, hosthash = pattern[1:].split('|')
            self._salt = binascii.a2b_base64(salt)
            self._hosthash = binascii.a2b_base64(hosthash)
        except (ValueError, binascii.Error):
            raise ValueError('Invalid known hosts hash entry: %s' %
                             pattern) from None

        if magic != self._HMAC_SHA1_MAGIC:
            # Only support HMAC SHA-1 for now
            raise ValueError('Invalid known hosts hash type: %s' %
                             magic) from None

    def _match(self, value):
        """Return whether this host hash matches a value"""

        hosthash = hmac.new(self._salt, value.encode(), sha1).digest()
        return hosthash == self._hosthash

    def matches(self, host, addr, ip):
        """Return whether a host or address matches this host hash"""

        # pylint: disable=unused-argument

        return (host and self._match(host)) or (addr and self._match(addr))


class SSHKnownHosts:
    """An SSH known hosts list"""

    def __init__(self, known_hosts):
        self._exact_entries = {}
        self._pattern_entries = []

        for line in known_hosts.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            try:
                if line.startswith('@'):
                    marker, pattern, key = line[1:].split(None, 2)
                else:
                    marker = None
                    pattern, key = line.split(None, 1)
            except ValueError:
                raise ValueError('Invalid known hosts entry: %s' %
                                 line) from None

            if marker not in (None, 'cert-authority', 'revoked'):
                raise ValueError('Invalid known hosts marker: %s' %
                                 marker) from None

            try:
                key = import_public_key(key)
            except KeyImportError:
                # Ignore keys in the file that we're unable to parse
                continue

            if any(c in pattern for c in '*?|/!'):
                self._add_pattern(marker, pattern, key)
            else:
                self._add_exact(marker, pattern, key)

    def _add_exact(self, marker, pattern, key):
        """Add an exact match entry"""

        for entry in pattern.split(','):
            if entry not in self._exact_entries:
                self._exact_entries[entry] = []

            self._exact_entries[entry].append((marker, key))

    def _add_pattern(self, marker, pattern, key):
        """Add a pattern match entry"""

        if pattern.startswith('|'):
            entry = _HashedHost(pattern)
        else:
            entry = _PlainHost(pattern)

        self._pattern_entries.append((entry, (marker, key)))

    def _match(self, host, addr, port=None):
        """Find host keys matching specified host, address, and port"""

        ip = ip_address(addr) if addr else None

        if port:
            host = '[{}]:{}'.format(host, port) if host else None
            addr = '[{}]:{}'.format(addr, port) if addr else None

        matches = []
        matches += self._exact_entries.get(host, [])
        matches += self._exact_entries.get(addr, [])
        matches += (match for (entry, match) in self._pattern_entries
                    if entry.matches(host, addr, ip))

        host_keys = []
        ca_keys = []
        revoked_keys = []

        for marker, key in matches:
            if marker == 'revoked':
                revoked_keys.append(key)
            elif marker == 'cert-authority':
                ca_keys.append(key)
            else:
                host_keys.append(key)

        return host_keys, ca_keys, revoked_keys

    def match(self, host, addr, port):
        """Match a host, IP address, and port against known_hosts patterns

           If the port is not the default port and no match is found
           for it, the lookup is attempted again without a port number.

           :param str host:
               The hostname of the target host
           :param str addr:
               The IP address of the target host
           :param int port:
               The port number on the target host, or ``None`` for the default


           :returns: A tuple of matching host keys, CA keys, and revoked keys

        """

        host_keys, ca_keys, revoked_keys = self._match(host, addr, port)

        if port and not (host_keys or ca_keys):
            host_keys, ca_keys, revoked_keys = self._match(host, addr)

        return host_keys, ca_keys, revoked_keys


def import_known_hosts(data):
    """Import SSH known hosts

       This function imports known host patterns and keys in
       OpenSSH known hosts format.

       :param str data:
           The known hosts data to import

       :returns: An :class:`SSHKnownHosts` object

    """

    return SSHKnownHosts(data)

def read_known_hosts(filename):
    """Read SSH known hosts from a file

       This function reads known host patterns and keys in
       OpenSSH known hosts format from a file.

       :param str filename:
           The file to read the known hosts from

       :returns: An :class:`SSHKnownHosts` object

    """

    with open(filename, 'r') as f:
        return import_known_hosts(f.read())


def match_known_hosts(known_hosts, host, addr, port):
    """Match a host, IP address, and port against a known_hosts list

       This function looks up a host, IP address, and port in a list of
       host patterns in OpenSSH ``known_hosts`` format and returns the
       host keys, CA keys, and revoked keys which match.

       The ``known_hosts`` argument can be a string containing the
       filename to load the host patterns from, a byte string containing
       host pattern data, or an already loaded :class:`SSHKnownHosts`
       object.

       If the port is not the default port and no match is found
       for it, the lookup is attempted again without a port number.

       :param known_hosts:
           The host patterns to match against
       :param str host:
           The hostname of the target host
       :param str addr:
           The IP address of the target host
       :param int port:
           The port number on the target host, or ``None`` for the default
       :type known_hosts: str or bytes or :class:`SSHKnownHosts`


       :returns: A tuple of matching host keys, CA keys, and revoked keys

    """

    if isinstance(known_hosts, str):
        known_hosts = read_known_hosts(known_hosts)
    elif isinstance(known_hosts, bytes):
        known_hosts = import_known_hosts(known_hosts.decode())

    return known_hosts.match(host, addr, port)
