# Copyright (c) 2015-2017 by Ron Frederick <ronf@timeheart.net>.
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

"""Parser for SSH known_hosts files"""

import socket

try:
    from .crypto import X509NamePattern
    _x509_available = True
except ImportError: # pragma: no cover
    _x509_available = False

from .misc import ip_address
from .pattern import HostPatternList, WildcardPatternList
from .public_key import KeyImportError, import_public_key
from .public_key import import_certificate, import_certificate_subject


class _SSHAuthorizedKeyEntry:
    """An entry in an SSH authorized_keys list"""

    def __init__(self, line):
        self.key = None
        self.cert = None
        self.options = {}

        try:
            self._import_key_or_cert(line)
            return
        except KeyImportError:
            pass

        line = self._parse_options(line)
        self._import_key_or_cert(line)

    def _import_key_or_cert(self, line):
        """Import key or certificate in this entry"""

        try:
            self.key = import_public_key(line)
            return
        except KeyImportError:
            pass

        try:
            self.cert = import_certificate(line)

            if ('cert-authority' in self.options and
                    self.cert.subject != self.cert.issuer):
                raise ValueError('X.509 cert-authority entries must '
                                 'contain a root CA certificate')

            return
        except KeyImportError:
            pass

        if 'cert-authority' not in self.options:
            try:
                self.key = None
                self.cert = None
                self._add_subject('subject', import_certificate_subject(line))
                return
            except KeyImportError:
                pass

        raise KeyImportError('Unrecognized key, certificate, or subject')

    def _set_string(self, option, value):
        """Set an option with a string value"""

        self.options[option] = value

    def _add_environment(self, option, value):
        """Add an environment key/value pair"""

        if value.startswith('=') or '=' not in value:
            raise ValueError('Invalid environment entry in authorized_keys')

        name, value = value.split('=', 1)
        self.options.setdefault(option, {})[name] = value

    def _add_from(self, option, value):
        """Add a from host pattern"""

        self.options.setdefault(option, []).append(HostPatternList(value))

    def _add_permitopen(self, option, value):
        """Add a permitopen host/port pair"""

        try:
            host, port = value.rsplit(':', 1)

            if host.startswith('[') and host.endswith(']'):
                host = host[1:-1]

            port = None if port == '*' else int(port)
        except:
            raise ValueError('Illegal permitopen value: %s' % value) from None

        self.options.setdefault(option, set()).add((host, port))

    def _add_principals(self, option, value):
        """Add a principals wildcard pattern list"""

        self.options.setdefault(option, []).append(WildcardPatternList(value))

    def _add_subject(self, option, value):
        """Add an X.509 subject pattern"""

        if _x509_available: # pragma: no branch
            self.options.setdefault(option, []).append(X509NamePattern(value))

    _handlers = {
        'command':     _set_string,
        'environment': _add_environment,
        'from':        _add_from,
        'permitopen':  _add_permitopen,
        'principals':  _add_principals,
        'subject':     _add_subject
    }

    def _add_option(self):
        """Add an option value"""

        if self._option.startswith('='):
            raise ValueError('Missing option name in authorized_keys')

        if '=' in self._option:
            option, value = self._option.split('=', 1)

            handler = self._handlers.get(option)
            if handler:
                handler(self, option, value)
            else:
                self.options.setdefault(option, []).append(value)
        else:
            self.options[self._option] = True

    def _parse_options(self, line):
        """Parse options in this entry"""

        self._option = ''

        idx = 0
        quoted = False
        escaped = False

        for idx, ch in enumerate(line):
            if escaped:
                self._option += ch
                escaped = False
            elif ch == '\\':
                escaped = True
            elif ch == '"':
                quoted = not quoted
            elif quoted:
                self._option += ch
            elif ch in ' \t':
                break
            elif ch == ',':
                self._add_option()
                self._option = ''
            else:
                self._option += ch

        self._add_option()

        if quoted:
            raise ValueError('Unbalanced quote in authorized_keys')
        elif escaped:
            raise ValueError('Unbalanced backslash in authorized_keys')

        return line[idx:].strip()

    def match_options(self, client_addr, cert_principals, cert_subject=None):
        """Match "from", "principals" and "subject" options in entry"""

        from_patterns = self.options.get('from')

        if from_patterns:
            client_host, _ = socket.getnameinfo((client_addr, 0),
                                                socket.NI_NUMERICSERV)
            client_ip = ip_address(client_addr)

            if not all(pattern.matches(client_host, client_addr, client_ip)
                       for pattern in from_patterns):
                return False

        principal_patterns = self.options.get('principals')

        if cert_principals is not None and principal_patterns is not None:
            if not all(any(pattern.matches(principal)
                           for principal in cert_principals)
                       for pattern in principal_patterns):
                return False

        subject_patterns = self.options.get('subject')

        if cert_subject is not None and subject_patterns is not None:
            if not all(pattern.matches(cert_subject)
                       for pattern in subject_patterns):
                return False

        return True


class SSHAuthorizedKeys:
    """An SSH authorized keys list"""

    def __init__(self, data):
        self._user_entries = []
        self._ca_entries = []
        self._x509_entries = []

        for line in data.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            try:
                entry = _SSHAuthorizedKeyEntry(line)
            except KeyImportError:
                continue

            if entry.key:
                if 'cert-authority' in entry.options:
                    self._ca_entries.append(entry)
                else:
                    self._user_entries.append(entry)
            else:
                self._x509_entries.append(entry)

        if (not self._user_entries and not self._ca_entries and
                not self._x509_entries):
            raise ValueError('No valid entries found')

    def validate(self, key, client_addr, cert_principals=None, ca=False):
        """Return whether a public key or CA is valid for authentication"""

        for entry in self._ca_entries if ca else self._user_entries:
            if (entry.key == key and
                    entry.match_options(client_addr, cert_principals)):
                return entry.options

        return None

    def validate_x509(self, cert, client_addr):
        """Return whether an X.509 certificate is valid for authentication"""

        for entry in self._x509_entries:
            if (entry.cert and 'cert-authority' not in entry.options and
                    (cert.key != entry.cert.key or
                     cert.subject != entry.cert.subject)):
                continue # pragma: no cover (work around bug in coverage tool)

            if entry.match_options(client_addr, cert.user_principals,
                                   cert.subject):
                return entry.options, entry.cert

        return None, None

def import_authorized_keys(data):
    """Import SSH authorized keys

       This function imports public keys and associated options in
       OpenSSH authorized keys format.

       :param data:
           The key data to import.
       :type data: `str`

       :returns: An :class:`SSHAuthorizedKeys` object

    """

    return SSHAuthorizedKeys(data)


def read_authorized_keys(filename):
    """Read SSH authorized keys from a file

       This function reads public keys and associated options in
       OpenSSH authorized_keys format from a file.

       :param filename:
           The file to read the keys from.
       :type filename: `str`

       :returns: An :class:`SSHAuthorizedKeys` object

    """

    with open(filename, 'r') as f:
        return import_authorized_keys(f.read())
