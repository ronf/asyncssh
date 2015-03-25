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

import binascii, hmac, os
from fnmatch import fnmatch
from hashlib import sha1

from .constants import *
from .public_key import *


class _PlainEntry:
    """A plaintext entry in a known_hosts file"""

    def __init__(self, pattern):
        self._patterns = []
        self._negated_patterns = []

        for p in pattern.split(b','):
            # We need to escape square brackets in host patterns if we
            # want to use Python's fnmatch.
            p = b''.join(b'[[]' if b == ord('[') else
                         b'[]]' if b == ord(']') else
                         bytes((b,)) for b in p)

            if p.startswith(b'!'):
                self._negated_patterns.append(p[1:])
            else:
                self._patterns.append(p)

    def matches(self, host):
        return (any(fnmatch(host, p) for p in self._patterns) and
                not any(fnmatch(host, p) for p in self._negated_patterns))


class _HashedEntry:
    """A hashed entry in a known_hosts file"""

    _HMAC_SHA1_MAGIC = b'1'

    def __init__(self, pattern):
        try:
            magic, salt, hosthash = pattern[1:].split(b'|')
            self._salt = binascii.a2b_base64(salt)
            self._hosthash = binascii.a2b_base64(hosthash)
        except (ValueError, binascii.Error):
            raise ValueError('Invalid known hosts hash entry: %s' %
                                 pattern.decode('ascii', errors='replace')) \
                      from None

        if magic != self._HMAC_SHA1_MAGIC:
            # Only support HMAC SHA-1 for now
            raise ValueError('Invalid known hosts hash type: %s' %
                                 magic.decode('ascii', errors='replace')) \
                      from None

    def matches(self, host):
        return hmac.new(self._salt, host, sha1).digest() == self._hosthash


def _parse_entries(known_hosts=None):
    if not known_hosts:
        known_hosts = os.path.join(os.environ['HOME'], '.ssh', 'known_hosts')

    try:
        lines = open(known_hosts, 'rb').readlines()
    except OSError:
        return []

    entries = []

    for line in lines:
        line = line.strip()
        if not line or line.startswith(b'#'):
            continue

        try:
            if line.startswith(b'@'):
                marker, pattern, key = line[1:].split(None, 2)
            else:
                marker = None
                pattern, key = line.split(None, 1)
        except ValueError as exc:
            raise ValueError('Invalid known hosts entry: %s' %
                                 line.decode('ascii', errors='replace')) \
                      from None

        if marker not in (None, b'cert-authority', b'revoked'):
            raise ValueError('Invalid known hosts marker: %s' %
                                 marker.decode('ascii', errors='replace')) \
                      from None

        if pattern.startswith(b'|'):
            entry = _HashedEntry(pattern)
        else:
            entry = _PlainEntry(pattern)

        entry.marker = marker

        try:
            entry.key = import_public_key(key)
        except KeyImportError:
            """Ignore keys in the file that we're unable to parse"""
            continue

        entries.append(entry)

    return entries

def _match_entries(entries, host, port=DEFAULT_PORT):
    if port != DEFAULT_PORT:
        host = '[' + host + ']:' + str(port)

    host_keys = []
    ca_keys = []
    revoked_keys = []

    for entry in entries:
        if entry.matches(host.encode()):
            if entry.marker == b'revoked':
                revoked_keys.append(entry.key)
            elif entry.marker == b'cert-authority':
                ca_keys.append(entry.key)
            else:
                host_keys.append(entry.key)

    return host_keys, ca_keys, revoked_keys

def match_known_hosts(host, port=DEFAULT_PORT, known_hosts_file=None):
    """Match a host and port against a known_hosts file

       This function looks up a host and port in a file in OpenSSH
       ``known_hosts`` format and returns the host keys, CA keys,
       and revoked keys which match.

       If the port is not the default port and no match is found
       for it, the lookup is attempted again without a port number.

    """

    entries = _parse_entries(known_hosts_file)

    host_keys, ca_keys, revoked_keys = _match_entries(entries, host, port)

    if port != DEFAULT_PORT and not (host_keys or ca_keys):
        host_keys, ca_keys, revoked_keys = _match_entries(entries, host)

    return host_keys, ca_keys, revoked_keys
