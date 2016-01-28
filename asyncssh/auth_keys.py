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

"""Parser for SSH known_hosts files"""

import socket

from .misc import ip_address
from .pattern import HostPatternList, WildcardPatternList
from .public_key import import_public_key, KeyImportError


class _SSHAuthorizedKeyEntry:
    """An entry in an SSH authorized_keys list"""

    def __init__(self, line):
        self.options = {}

        try:
            self.key = import_public_key(line)
            return
        except KeyImportError:
            pass

        line = self._parse_options(line)
        self.key = import_public_key(line)

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

    _handlers = {
        'command':     _set_string,
        'environment': _add_environment,
        'from':        _add_from,
        'permitopen':  _add_permitopen,
        'principals':  _add_principals
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


class SSHAuthorizedKeys:
    """An SSH authorized keys list"""

    def __init__(self, data):
        self._user_entries = []
        self._ca_entries = []

        for line in data.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            try:
                entry = _SSHAuthorizedKeyEntry(line)
            except KeyImportError:
                continue

            if 'cert-authority' in entry.options:
                self._ca_entries.append(entry)
            else:
                self._user_entries.append(entry)

        if not self._user_entries and not self._ca_entries:
            raise ValueError('No valid keys found')

    def validate(self, key, client_addr, cert_principals=None, ca=False):
        """Return whether a public key or CA is valid for authentication"""

        for entry in self._ca_entries if ca else self._user_entries:
            if entry.key != key:
                continue

            from_patterns = entry.options.get('from')
            if from_patterns is not None:
                client_host, _ = socket.getnameinfo((client_addr, 0),
                                                    socket.NI_NUMERICSERV)
                client_ip = ip_address(client_addr)

                if not all(pattern.matches(client_host, client_addr, client_ip)
                           for pattern in from_patterns):
                    continue

            principal_patterns = entry.options.get('principals')
            if cert_principals is not None and principal_patterns is not None:
                if not all(any(pattern.matches(principal)
                               for principal in cert_principals)
                           for pattern in principal_patterns):
                    continue

            return entry.options

        return None


def import_authorized_keys(data):
    """Import SSH authorized keys

       This function imports public keys and associated options in
       OpenSSH authorized keys format.

       :param str data:
           The key data to import.

       :returns: An :class:`SSHAuthorizedKeys` object

    """

    return SSHAuthorizedKeys(data)


def read_authorized_keys(filename):
    """Read SSH authorized keys from a file

       This function reads public keys and associated options in
       OpenSSH authorized_keys format from a file.

       :param str filename:
           The file to read the keys from.

       :returns: An :class:`SSHAuthorizedKeys` object

    """

    with open(filename, 'r') as f:
        return import_authorized_keys(f.read())
