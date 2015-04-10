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

"""Parser for SSH known_hosts files"""

import binascii, hmac
from hashlib import sha1

from .misc import *
from .pattern import *
from .public_key import *


class PlainHost:
    """A plain host entry in a known_hosts file"""

    def __init__(self, pattern):
        self._pattern = HostPatternList(pattern)

    def matches(self, host, addr, ip):
        return self._pattern.matches(host, addr, ip)

class HashedHost:
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
        return hmac.new(self._salt, value, sha1).digest() == self._hosthash

    def matches(self, host, addr):
        return (host and self._match(host)) or (addr and self._match(addr))


def _parse_entries(known_hosts):
    entries = []

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
        except ValueError as exc:
            raise ValueError('Invalid known hosts entry: %s' %
                                 line) from None

        if marker not in (None, 'cert-authority', 'revoked'):
            raise ValueError('Invalid known hosts marker: %s' %
                                 marker) from None

        if pattern.startswith('|'):
            entry = HashedHost(pattern)
        else:
            entry = PlainHost(pattern)

        entry.marker = marker

        try:
            entry.key = import_public_key(key)
        except KeyImportError:
            """Ignore keys in the file that we're unable to parse"""
            continue

        entries.append(entry)

    return entries

def _match_entries(entries, host, addr, port=None):
    ip = ip_address(addr) if addr else None

    if port:
        host = '[{}]:{}'.format(host, port) if host else None

        if addr:
            addr = '[{}]:{}'.format(addr, port) if addr else None

    host_keys = []
    ca_keys = []
    revoked_keys = []

    for entry in entries:
        if entry.matches(host, addr, ip):
            if entry.marker == 'revoked':
                revoked_keys.append(entry.key)
            elif entry.marker == 'cert-authority':
                ca_keys.append(entry.key)
            else:
                host_keys.append(entry.key)

    return host_keys, ca_keys, revoked_keys

def match_known_hosts(known_hosts, host, addr, port):
    """Match a host, IP address, and port against a known_hosts file

       This function looks up a host, IP address, and port in a file
       in OpenSSH ``known_hosts`` format and returns the host keys,
       CA keys, and revoked keys which match.

       If the port is not the default port and no match is found
       for it, the lookup is attempted again without a port number.

    """

    if isinstance(known_hosts, str):
        known_hosts = open(known_hosts, 'r').read()
    else:
        known_hosts = known_hosts.decode()

    entries = _parse_entries(known_hosts)

    host_keys, ca_keys, revoked_keys = _match_entries(entries, host, addr, port)

    if port and not (host_keys or ca_keys):
        host_keys, ca_keys, revoked_keys = _match_entries(entries, host, addr)

    return host_keys, ca_keys, revoked_keys
