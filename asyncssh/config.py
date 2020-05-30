# Copyright (c) 2020 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Parser for OpenSSH config files"""

import os
import shlex
import socket

from pathlib import Path, PurePath

from .pattern import WildcardPatternList


class ConfigParseError(ValueError):
    """Configuration parsing exception"""


class SSHConfig:
    """Settings from an OpenSSH config file"""

    _conditionals = {'match'}
    _no_split = set()
    _handlers = {}

    def __init__(self):
        self._path = ''
        self._line_no = 0
        self._matching = True
        self._options = {}

    def _error(self, reason, *args):
        """Raise a configuration parsing error"""

        raise ConfigParseError('%s line %s: %s' % (self._path, self._line_no,
                                                   reason % args))

    def _match_val(self, match):
        """Return the value to match against in a match condition"""

        raise NotImplementedError

    def _include(self, option, args):
        """Read config from a list of other config files"""

        # pylint: disable=unused-argument

        for pattern in args:
            path = Path(pattern)

            if path.anchor:
                pattern = str(Path(*path.parts[1:]))
                path = Path(path.anchor)
            else:
                path = Path(self._path).parent

            for path in path.glob(pattern):
                self.parse(path)
                self._matching = True

        args.clear()

    def _match(self, option, args):
        """Begin a conditional block"""

        # pylint: disable=unused-argument

        while args:
            match = args.pop(0).lower()

            if match == 'all':
                continue

            match_val = self._match_val(match)

            if match_val is None:
                self._error('Invalid match condition')

            try:
                pattern = WildcardPatternList(args.pop(0))
            except IndexError:
                self._error('Missing %s match pattern', match)

            self._matching = pattern.matches(match_val)

            if not self._matching:
                args.clear()
                break

    def _set_bool(self, option, args):
        """Set a boolean config option"""

        value = args.pop(0).lower()

        if value in ('yes', 'true'):
            value = True
        elif value in ('no', 'false'):
            value = False
        else:
            self._error('Invalid %s boolean value: %s', option, value)

        if option not in self._options:
            self._options[option] = value

    def _set_int(self, option, args):
        """Set an integer config option"""

        value = args.pop(0)

        try:
            value = int(value)
        except ValueError:
            self._error('Invalid %s integer value: %s', option, value)

        if option not in self._options:
            self._options[option] = value

    def _set_string(self, option, args):
        """Set a string config option"""

        value = args.pop(0)

        if value.lower() == 'none':
            value = None

        if option not in self._options:
            self._options[option] = value

    def _append_string(self, option, args):
        """Append a string config option to a list"""

        value = args.pop(0)

        if value.lower() != 'none':
            if option in self._options:
                self._options[option].append(value)
            else:
                self._options[option] = [value]
        else:
            if option not in self._options:
                self._options[option] = []

    def _append_string_list(self, option, args):
        """Append whitespace-separated string config options to a list"""

        if option in self._options:
            self._options[option].extend(args)
        else:
            self._options[option] = args[:]

        args.clear()

    def _set_address_family(self, option, args):
        """Set an address family config option"""

        value = args.pop(0).lower()

        if value == 'any':
            value = socket.AF_UNSPEC
        elif value == 'inet':
            value = socket.AF_INET
        elif value == 'inet6':
            value = socket.AF_INET6
        else:
            self._error('Invalid %s value: %s', option, value)

        if option not in self._options:
            self._options[option] = value

    def _set_rekey_limits(self, option, args):
        """Set rekey limits config option"""

        byte_limit = args.pop(0).lower()

        if byte_limit == 'default':
            byte_limit = ()

        if args:
            time_limit = args.pop(0).lower()

            if time_limit == 'none':
                time_limit = None
        else:
            time_limit = ()

        if option not in self._options:
            self._options[option] = byte_limit, time_limit

    def parse(self, path):
        """Parse an OpenSSH config file and return matching declarations"""

        self._path = path
        self._line_no = 0

        with open(path) as file:
            for line in file:
                self._line_no += 1

                try:
                    args = shlex.split(line)
                except ValueError as exc:
                    self._error(str(exc))

                if not args or args[0][:1] == '#':
                    continue

                option = args.pop(0)
                loption = option.lower()

                if loption in self._no_split:
                    args = [line.lstrip()[len(loption):].strip()]

                if not self._matching and loption not in self._conditionals:
                    continue

                try:
                    option, handler = self._handlers[loption]
                except KeyError:
                    continue

                if not args:
                    self._error('Missing %s value', option)

                handler(self, option, args)

                if args:
                    self._error('Extra data at end: %s', ' '.join(args))

    def get(self, option, default=None):
        """Get the value of a config option"""

        return self._options.get(option, default)

    def get_compression_algs(self, default=None):
        """Return the compression algorithms to use"""

        compression = self.get('Compression')

        if compression is None:
            return default
        elif compression:
            return 'zlib@openssh.com,zlib,none'
        else:
            return 'none,zlib@openssh.com,zlib'


class SSHClientConfig(SSHConfig):
    """Settings from an OpenSSH client config file"""

    _conditionals = {'host', 'match'}
    _no_split = {'remotecommand'}

    def __init__(self, local_user, user, host):
        super().__init__()

        self._local_user = local_user
        self._user = user or local_user
        self._orig_host = host
        self._host = host

    def _match_val(self, match):
        """Return the value to match against in a match condition"""

        if match == 'host':
            return self._host
        elif match == 'originalhost':
            return self._orig_host
        elif match == 'localuser':
            return self._local_user
        elif match == 'user':
            return self._user
        else:
            return None

    def _match_host(self, option, args):
        """Begin a conditional block matching on host"""

        # pylint: disable=unused-argument

        pattern = ','.join(args)
        self._matching = WildcardPatternList(pattern).matches(self._host)
        args.clear()

    def _set_hostname(self, option, args):
        """Set hostname config option"""

        # pylint: disable=unused-argument

        value = args.pop(0)

        if option not in self._options:
            self._options[option] = value
            self._host = value

    def _set_user(self, option, args):
        """Set user config option"""

        value = args.pop(0)

        if option not in self._options:
            self._options[option] = value
            self._user = value

    # pylint: disable=bad-whitespace

    _handlers = {option.lower(): (option, handler) for option, handler in (
        ('Host',                  _match_host),
        ('Match',                 SSHConfig._match),

        ('AddressFamily',         SSHConfig._set_address_family),
        ('BindAddress',           SSHConfig._set_string),
        ('CASignatureAlgorithms', SSHConfig._set_string),
        ('CertificateFile',       SSHConfig._append_string),
        ('Ciphers',               SSHConfig._set_string),
        ('Compression',           SSHConfig._set_bool),
        ('ConnectTimeout',        SSHConfig._set_int),
        ('EnableSSHKeySign',      SSHConfig._set_bool),
        ('ForwardAgent',          SSHConfig._set_bool),
        ('ForwardX11Trusted',     SSHConfig._set_bool),
        ('HostKeyAlgorithms',     SSHConfig._set_string),
        ('Hostname',              _set_hostname),
        ('Include',               SSHConfig._include),
        ('IdentityAgent',         SSHConfig._set_string),
        ('IdentityFile',          SSHConfig._append_string),
        ('KexAlgorithms',         SSHConfig._set_string),
        ('MACs',                  SSHConfig._set_string),
        ('Port',                  SSHConfig._set_int),
        ('RekeyLimit',            SSHConfig._set_rekey_limits),
        ('RemoteCommand',         SSHConfig._set_string),
        ('SendEnv',               SSHConfig._append_string_list),
        ('ServerAliveCountMax',   SSHConfig._set_int),
        ('ServerAliveInterval',   SSHConfig._set_int),
        ('SetEnv',                SSHConfig._append_string_list),
        ('User',                  _set_user),
        ('UserKnownHostsFile',    SSHConfig._set_string)
    )}

    # pylint: enable=bad-whitespace


class SSHServerConfig(SSHConfig):
    """Settings from an OpenSSH server config file"""

    def _match_val(self, match):
        """Return the value to match against in a match condition"""

        # pylint: disable=unused-argument
        # TODO
        return None

    # pylint: disable=bad-whitespace

    _handlers = {option.lower(): (option, handler) for option, handler in (
        ('Match',               SSHConfig._match),

        ('AddressFamily',       SSHConfig._set_address_family),
        ('BindAddress',         SSHConfig._set_string),
        ('Ciphers',             SSHConfig._set_string),
        ('ClientAliveCountMax', SSHConfig._set_int),
        ('ClientAliveInterval', SSHConfig._set_int),
        ('Compression',         SSHConfig._set_bool),
        ('HostCertificate',     SSHConfig._append_string),
        ('HostKey',             SSHConfig._append_string),
        ('Include',             SSHConfig._include),
        ('KexAlgorithms',       SSHConfig._set_string),
        ('MACs',                SSHConfig._set_string),
        ('Port',                SSHConfig._set_int),
        ('RekeyLimit',          SSHConfig._set_rekey_limits)
    )}

    # pylint: enable=bad-whitespace


def load_client_config(local_user, user, host, config_paths):
    """Load OpenSSH client config files"""

    config = SSHClientConfig(local_user, user, host)

    if config_paths == ():
        default_config = Path('~', '.ssh', 'config').expanduser()
        config_paths = [default_config] if os.access(default_config,
                                                     os.R_OK) else []
    elif not config_paths:
        config_paths = []
    elif isinstance(config_paths, (str, bytes, PurePath)):
        config_paths = [config_paths]

    for path in config_paths:
        config.parse(path)

    return config


def load_server_config(config_paths):
    """Load OpenSSH server config files"""

    config = SSHServerConfig()

    if not config_paths:
        config_paths = []
    elif isinstance(config_paths, (str, bytes, PurePath)):
        config_paths = [config_paths]

    for path in config_paths:
        config.parse(path)

    return config
