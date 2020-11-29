# Copyright (c) 2015-2020 by Ron Frederick <ronf@timeheart.net> and others.
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
#     Alexander Travov - proposed changes to add negated patterns, hashed
#                        entries, and support for the revoked marker
#     Josh Yudaken - proposed change to split parsing and matching to avoid
#                    parsing large known_hosts lists multiple times

"""Parser for SSH known_hosts files"""

import binascii
import hmac

from hashlib import sha1

try:
    from .crypto import X509NamePattern
    _x509_available = True
except ImportError: # pragma: no cover
    _x509_available = False

from .misc import ip_address, read_file
from .pattern import HostPatternList
from .public_key import KeyImportError, import_public_key
from .public_key import import_certificate, import_certificate_subject
from .public_key import load_public_keys, load_certificates


def _load_subject_names(names):
    """Load a list of X.509 subject name patterns"""

    if not _x509_available: # pragma: no cover
        return []

    return list(map(X509NamePattern, names))


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

    def matches(self, host, addr, _ip):
        """Return whether a host or address matches this host hash"""

        return (host and self._match(host)) or (addr and self._match(addr))


class SSHKnownHosts:
    """An SSH known hosts list"""

    def __init__(self, known_hosts=None):
        self._exact_entries = {}
        self._pattern_entries = []

        if known_hosts:
            self.load(known_hosts)

    def load(self, known_hosts):
        """Load known hosts data into this object"""

        for line in known_hosts.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            try:
                if line.startswith('@'):
                    marker, pattern, data = line[1:].split(None, 2)
                else:
                    marker = None
                    pattern, data = line.split(None, 1)
            except ValueError:
                raise ValueError('Invalid known hosts entry: %s' %
                                 line) from None

            if marker not in (None, 'cert-authority', 'revoked'):
                raise ValueError('Invalid known hosts marker: %s' %
                                 marker) from None

            key = None
            cert = None
            subject = None

            try:
                key = import_public_key(data)
            except KeyImportError:
                try:
                    cert = import_certificate(data)
                except KeyImportError:
                    if not _x509_available: # pragma: no cover
                        continue

                    try:
                        subject = import_certificate_subject(data)
                    except KeyImportError:
                        # Ignore keys in the file that we're unable to parse
                        continue

                    subject = X509NamePattern(subject)

            if any(c in pattern for c in '*?|/!'):
                self._add_pattern(marker, pattern, key, cert, subject)
            else:
                self._add_exact(marker, pattern, key, cert, subject)

    def _add_exact(self, marker, pattern, key, cert, subject):
        """Add an exact match entry"""

        for entry in pattern.split(','):
            if entry not in self._exact_entries:
                self._exact_entries[entry] = []

            self._exact_entries[entry].append((marker, key, cert, subject))

    def _add_pattern(self, marker, pattern, key, cert, subject):
        """Add a pattern match entry"""

        if pattern.startswith('|'):
            entry = _HashedHost(pattern)
        else:
            entry = _PlainHost(pattern)

        self._pattern_entries.append((entry, (marker, key, cert, subject)))

    def _match(self, host, addr, port=None):
        """Find host keys matching specified host, address, and port"""

        if addr:
            ip = ip_address(addr)
        else:
            try:
                ip = ip_address(host)
            except ValueError:
                ip = None

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
        x509_certs = []
        revoked_certs = []
        x509_subjects = []
        revoked_subjects = []

        for marker, key, cert, subject in matches:
            if key:
                if marker == 'revoked':
                    revoked_keys.append(key)
                elif marker == 'cert-authority':
                    ca_keys.append(key)
                else:
                    host_keys.append(key)
            elif cert:
                if marker == 'revoked':
                    revoked_certs.append(cert)
                else:
                    x509_certs.append(cert)
            else:
                if marker == 'revoked':
                    revoked_subjects.append(subject)
                else:
                    x509_subjects.append(subject)

        return (host_keys, ca_keys, revoked_keys, x509_certs, revoked_certs,
                x509_subjects, revoked_subjects)

    def match(self, host, addr, port):
        """Match a host, IP address, and port against known_hosts patterns

           If the port is not the default port and no match is found
           for it, the lookup is attempted again without a port number.

           :param host:
               The hostname of the target host
           :param addr:
               The IP address of the target host
           :param port:
               The port number on the target host, or `None` for the default
           :type host: `str`
           :type addr: `str`
           :type port: `int`


           :returns: A tuple of matching host keys, CA keys, and revoked keys

        """

        host_keys, ca_keys, revoked_keys, x509_certs, revoked_certs, \
            x509_subjects, revoked_subjects = self._match(host, addr, port)

        if port and not (host_keys or ca_keys or x509_certs or x509_subjects):
            host_keys, ca_keys, revoked_keys, x509_certs, revoked_certs, \
                x509_subjects, revoked_subjects = self._match(host, addr)

        return (host_keys, ca_keys, revoked_keys, x509_certs, revoked_certs,
                x509_subjects, revoked_subjects)


def import_known_hosts(data):
    """Import SSH known hosts

       This function imports known host patterns and keys in
       OpenSSH known hosts format.

       :param data:
           The known hosts data to import
       :type data: `str`

       :returns: An :class:`SSHKnownHosts` object

    """

    return SSHKnownHosts(data)


def read_known_hosts(filelist):
    """Read SSH known hosts from a file or list of files

       This function reads known host patterns and keys in
       OpenSSH known hosts format from a file or list of files.

       :param filelist:
           The file or list of files to read the known hosts from
       :type filelist: `str` or `list` of `str`

       :returns: An :class:`SSHKnownHosts` object

    """

    known_hosts = SSHKnownHosts()

    if isinstance(filelist, str):
        filelist = [filelist]

    for filename in filelist:
        known_hosts.load(read_file(filename, 'r'))

    return known_hosts


def match_known_hosts(known_hosts, host, addr, port):
    """Match a host, IP address, and port against a known_hosts list

       This function looks up a host, IP address, and port in a list of
       host patterns in OpenSSH `known_hosts` format and returns the
       host keys, CA keys, and revoked keys which match.

       The `known_hosts` argument can be any of the following:

           * a string containing the filename to load host patterns from
           * a byte string containing host pattern data to load
           * an already loaded :class:`SSHKnownHosts` object containing
             host patterns to match against
           * an alternate matching function which accepts a host, address,
             and port and returns lists of trusted host keys, trusted CA
             keys, and revoked keys to load
           * lists of trusted host keys, trusted CA keys, and revoked keys
             to load without doing any matching

       If the port is not the default port and no match is found
       for it, the lookup is attempted again without a port number.

       :param known_hosts:
           The host patterns to match against
       :param host:
           The hostname of the target host
       :param addr:
           The IP address of the target host
       :param port:
           The port number on the target host, or `None` for the default
       :type host: `str`
       :type addr: `str`
       :type port: `int`

       :returns: A tuple of matching host keys, CA keys, and revoked keys

    """

    if isinstance(known_hosts, str) or \
            (known_hosts and isinstance(known_hosts, list) and
             isinstance(known_hosts[0], str)):
        known_hosts = read_known_hosts(known_hosts)
    elif isinstance(known_hosts, bytes):
        known_hosts = import_known_hosts(known_hosts.decode())

    if isinstance(known_hosts, SSHKnownHosts):
        known_hosts = known_hosts.match(host, addr, port)
    else:
        if callable(known_hosts):
            known_hosts = known_hosts(host, addr, port)

        known_hosts = (tuple(map(load_public_keys, known_hosts[:3])) +
                       tuple(map(load_certificates, known_hosts[3:5])) +
                       tuple(map(_load_subject_names, known_hosts[5:])))

        if len(known_hosts) == 3:
            # Provide backward compatibility for pre-X.509 releases
            known_hosts = tuple(known_hosts) + ((), (), (), ())

    return known_hosts
