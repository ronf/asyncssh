"""
Helper classes and functions for parsing openssh known_hosts file.
"""

import os.path
from binascii import a2b_base64
from fnmatch import fnmatch
from hashlib import sha1
from hmac import HMAC

from .public_key import import_public_key


class HostnamePattern:
    """
    HostnamePattern is a pattern to match against a given hostname.
    It can have two forms:

    - a glob-like pattern that can contain '*' and '?' that act as wildcards
      ex. b'node*'

    - a hostname or address that is enclosed in '[' and ']' then followed
    by ':' and a nonstandart port number
        b'[192.168.3.1]:3022'
    """

    def __init__(self, pattern):
        self._pattern = pattern

    def matches(self, hostname):
        if hostname.startswith(b'['):
            return self._pattern == hostname
        else:
            return fnmatch(hostname, self._pattern)


class PlainEntry:
    """
    A PlainEntry is a representation of a plain-text entry in a
    known_hosts file.
    param: patterns is a comma-separated list of patterns.
    A pattern may also be preceded by '!' to indicate negation:
    if the hostname matches a negated pattern, it is not accepted
    (by that line) even if it matched another pattern on the line.
    """

    def __init__(self, patterns):
        self._patterns = []
        self._negated_patterns = []
        for p in patterns.split(b','):
            if p.startswith(b'!'):
                self._negated_patterns.append(HostnamePattern(p[1:]))
            else:
                self._patterns.append(HostnamePattern(p))

    def matches(self, hostname):
        matches_negated = any(
            p.matches(hostname) for p in self._negated_patterns
        )
        matches_regular = any(
            p.matches(hostname) for p in self._patterns
        )
        return not matches_negated and matches_regular


class HashedEntry:
    """
    A HashedEntry represents a hashed form of entry,
    which hides host names and addresses.
    Hashed hostnames start with a '|' character. Only one
    hashed hostname may appear on a single line and none of the above
    negation or wildcards operators may be applied.

    HashedEntry format:

    |1|b64_salt|b64_hosthash|

    |1| - is a HASH_MAGIC
    b64_salt - is base64 encoded salt for sha1 hmac
    b64_hosthash - is base64 hosthash
    """

    MAGIC = b'|1|'

    def __init__(self, data):
        salt_and_hosthash = data[len(self.MAGIC):].split(b'|')
        if len(salt_and_hosthash) != 2:
            raise ValueError("Can't parse hashed entry: %s" % data)
        b64_salt, b64_hosthash = salt_and_hosthash
        self._salt = a2b_base64(b64_salt)
        self._hosthash = a2b_base64(b64_hosthash)

    def matches(self, hostname):
        hash = HMAC(self._salt, digestmod=sha1)
        hash.update(hostname)
        return hash.digest() == self._hosthash


def _extract_hostname_entry_and_key(line):
    """
    Extract hostname entry and key from a line in a known_hosts file.
    param line: A known hosts file entry (a single line).
    type line: bytes
    return: a 2-tuple of hostname entry (PlainEntry or HashedEntry),
    key (SSHKey).
    Also sets appropirate flags on hostname entry if
    meets known_hosts markers: @cert-authority and @revoked
    """
    ca_marker = b'@cert-authority'
    revoked_marker = b'@revoked'
    
    marker = None

    if line.startswith(ca_marker):
        marker = ca_marker
    elif line.startswith(revoked_marker):
        marker = revoked_marker

    num_splits = 2 if marker else 1
    elements = line.split(None, num_splits)
    if len(elements) != num_splits + 1:
        raise ValueError("Can't process known_hosts entry: %s" % line)
    hostnames, key = elements[1 if marker else 0:]
    if hostnames.startswith(b'|'):
        entry = HashedEntry(hostnames)
    else:
        entry = PlainEntry(hostnames)
        
    if marker == ca_marker:
        entry.is_ca = True
    elif marker == revoked_marker:
        entry.revoked = True

    key = import_public_key(key)
    return entry, key


def parse_known_hosts(host, port, *, known_hosts_file=None):
    """
    Parses known_hosts file and returns keys and certificates of
    all entries that given host and port match against.
    By default looks at standart location: ~/.ssh/known_hosts
    """
    if not known_hosts_file:
        known_hosts_file = os.path.join(
            os.environ['HOME'], '.ssh', 'known_hosts')

    try:
        lines = open(known_hosts_file, 'rb').readlines()
    except OSError:
        return [], []

    DEFAULT_PORT = 22
    hostname = host.encode()
    # If port is non-standart creates hostname [host]:port
    if port != DEFAULT_PORT:
        hostname = b'[' + hostname + b']:' + str(port).encode()

    server_host_keys = []
    server_ca_keys = []

    # Skip comments
    entries_and_keys = [_extract_hostname_entry_and_key(l) for l in lines
                        if l.strip() and not l.startswith(b'#')]

    for entry, key in entries_and_keys:
        if entry.matches(hostname) and not hasattr(entry, 'revoked'):
            if hasattr(entry, 'is_ca'):
                server_ca_keys.append(key)
            else:
                server_host_keys.append(key)

    return server_host_keys, server_ca_keys
