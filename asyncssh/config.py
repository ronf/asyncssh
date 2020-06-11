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
import re
import shlex
import socket

from hashlib import sha1
from pathlib import Path, PurePath

from .constants import DEFAULT_PORT
from .pattern import WildcardPatternList


class ConfigParseError(ValueError):
    """Configuration parsing exception"""


class SSHConfig:
    """Settings from an OpenSSH config file"""

    _conditionals = {'match'}
    _no_split = set()
    _percent_expand = set()
    _handlers = {}

    def __init__(self):
        self._path = ''
        self._line_no = 0
        self._matching = True
        self._options = {}
        self._tokens = {'%': '%'}

    def _error(self, reason, *args):
        """Raise a configuration parsing error"""

        raise ConfigParseError('%s line %s: %s' % (self._path, self._line_no,
                                                   reason % args))

    def _match_val(self, match):
        """Return the value to match against in a match condition"""

        raise NotImplementedError

    def _set_tokens(self):
        """Set the tokens available for percent expansion"""

        raise NotImplementedError

    def _expand_val(self, value):
        """Perform percent token expansion on a string"""

        last_idx = 0
        result = []

        for match in re.finditer(r'%', value):
            idx = match.start()

            if idx < last_idx:
                continue

            try:
                result.extend([value[last_idx:idx],
                               self._tokens[value[idx+1]]])
                last_idx = idx + 2
            except IndexError:
                raise ConfigParseError('Invalid token substitution')
            except KeyError:
                raise ConfigParseError('Invalid token substitution: %s' %
                                       value[idx+1]) from None

        result.append(value[last_idx:])
        return ''.join(result)

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

    def _set_string_list(self, option, args):
        """Set whitespace-separated string config options as a list"""

        if option not in self._options:
            self._options[option] = args[:]

        args.clear()

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

        self._set_tokens()

        for option in self._percent_expand:
            try:
                value = self._options[option]
            except KeyError:
                pass
            else:
                if isinstance(value, list):
                    value = [self._expand_val(item) for item in value]
                else:
                    value = self._expand_val(value)

                self._options[option] = value

    @classmethod
    def load(cls, config, config_paths, *args, **kwargs):
        """Load a list of OpenSSH config files into a config object"""

        if not config:
            config = cls(*args, **kwargs)

        if isinstance(config_paths, (str, bytes, PurePath)):
            config_paths = [config_paths]

        for path in config_paths:
            config.parse(path)

        return config

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
    _percent_expand = {'CertificateFile', 'IdentityAgent',
                       'IdentityFile', 'RemoteCommand'}

    def __init__(self, local_user, user, host, port):
        super().__init__()

        self._local_user = local_user
        self._user = user
        self._orig_host = host
        self._host = host
        self._port = port

    def _match_val(self, match):
        """Return the value to match against in a match condition"""

        if match == 'host':
            return self._host
        elif match == 'originalhost':
            return self._orig_host
        elif match == 'localuser':
            return self._local_user
        elif match == 'user':
            return self._user or self._local_user
        else:
            return None

    def _match_host(self, option, args):
        """Begin a conditional block matching on host"""

        # pylint: disable=unused-argument

        pattern = ','.join(args)
        self._matching = WildcardPatternList(pattern).matches(self._orig_host)
        args.clear()

    def _set_hostname(self, option, args):
        """Set hostname config option"""

        # pylint: disable=unused-argument

        self._tokens['h'] = self._host
        value = self._expand_val(args.pop(0))

        if option not in self._options:
            self._options[option] = value
            self._host = value

    def _set_port(self, option, args):
        """Set port config option"""

        value = args.pop(0)

        try:
            value = int(value)
        except ValueError:
            self._error('Invalid port: %s', value)

        if self._port == ():
            self._options[option] = value
            self._port = value

    def _set_request_tty(self, option, args):
        """Set a pseudo-terminal request config option"""

        value = args.pop(0).lower()

        if value in ('yes', 'true'):
            value = True
        elif value in ('no', 'false'):
            value = False
        elif value not in ('force', 'auto'):
            self._error('Invalid %s value: %s', option, value)

        if option not in self._options:
            self._options[option] = value

    def _set_user(self, option, args):
        """Set user config option"""

        value = args.pop(0)

        if self._user == ():
            self._options[option] = value
            self._user = value

    def _set_tokens(self):
        """Set the tokens available for percent expansion"""

        local_host = socket.gethostname()

        idx = local_host.find('.')
        short_local_host = local_host if idx < 0 else local_host[:idx]

        port = str(self._port or DEFAULT_PORT)
        user = self._user or self._local_user

        conn_info = ''.join((local_host, self._host, port, user))
        conn_hash = sha1(conn_info.encode('utf-8')).hexdigest()

        self._tokens.update({'C': conn_hash,
                             'd': str(Path.home()),
                             'h': self._host,
                             'L': short_local_host,
                             'l': local_host,
                             'n': self._orig_host,
                             'p': port,
                             'r': user,
                             'u': self._local_user})

        if hasattr(os, 'getuid'): # pragma: no branch
            self._tokens['i'] = str(os.getuid())

    # pylint: disable=bad-whitespace

    _handlers = {option.lower(): (option, handler) for option, handler in (
        ('Host',                         _match_host),
        ('Match',                           SSHConfig._match),
        ('Include',                         SSHConfig._include),

        ('AddressFamily',                   SSHConfig._set_address_family),
        ('BindAddress',                     SSHConfig._set_string),
        ('CASignatureAlgorithms',           SSHConfig._set_string),
        ('CertificateFile',                 SSHConfig._append_string),
        ('ChallengeResponseAuthentication', SSHConfig._set_bool),
        ('Ciphers',                         SSHConfig._set_string),
        ('Compression',                     SSHConfig._set_bool),
        ('ConnectTimeout',                  SSHConfig._set_int),
        ('EnableSSHKeySign',                SSHConfig._set_bool),
        ('ForwardAgent',                    SSHConfig._set_bool),
        ('ForwardX11Trusted',               SSHConfig._set_bool),
        ('GlobalKnownHostsFile',            SSHConfig._set_string_list),
        ('GSSAPIAuthentication',            SSHConfig._set_bool),
        ('GSSAPIDelegateCredentials',       SSHConfig._set_bool),
        ('GSSAPIKeyExchange',               SSHConfig._set_bool),
        ('HostbasedAuthentication',         SSHConfig._set_bool),
        ('HostKeyAlgorithms',               SSHConfig._set_string),
        ('Hostname',                        _set_hostname),
        ('IdentityAgent',                   SSHConfig._set_string),
        ('IdentityFile',                    SSHConfig._append_string),
        ('KbdInteractiveAuthentication',    SSHConfig._set_bool),
        ('KexAlgorithms',                   SSHConfig._set_string),
        ('MACs',                            SSHConfig._set_string),
        ('PasswordAuthentication',          SSHConfig._set_bool),
        ('PreferredAuthentications',        SSHConfig._set_string),
        ('Port',                            _set_port),
        ('ProxyJump',                       SSHConfig._set_string),
        ('PubkeyAuthentication',            SSHConfig._set_bool),
        ('RekeyLimit',                      SSHConfig._set_rekey_limits),
        ('RemoteCommand',                   SSHConfig._set_string),
        ('RequestTTY',                      _set_request_tty),
        ('SendEnv',                         SSHConfig._append_string_list),
        ('ServerAliveCountMax',             SSHConfig._set_int),
        ('ServerAliveInterval',             SSHConfig._set_int),
        ('SetEnv',                          SSHConfig._append_string_list),
        ('User',                            _set_user),
        ('UserKnownHostsFile',              SSHConfig._set_string_list)
    )}


class SSHServerConfig(SSHConfig):
    """Settings from an OpenSSH server config file"""

    def _match_val(self, match):
        """Return the value to match against in a match condition"""

        # pylint: disable=unused-argument
        # TODO
        return None

    def _set_tokens(self):
        """Set the tokens available for percent expansion"""

        # TODO

    # pylint: disable=bad-whitespace

    _handlers = {option.lower(): (option, handler) for option, handler in (
        ('Match',                           SSHConfig._match),
        ('Include',                         SSHConfig._include),

        ('AddressFamily',                   SSHConfig._set_address_family),
        ('AuthorizedKeysFile',              SSHConfig._set_string_list),
        ('AllowAgentForwarding',            SSHConfig._set_bool),
        ('BindAddress',                     SSHConfig._set_string),
        ('CASignatureAlgorithms',           SSHConfig._set_string),
        ('ChallengeResponseAuthentication', SSHConfig._set_bool),
        ('Ciphers',                         SSHConfig._set_string),
        ('ClientAliveCountMax',             SSHConfig._set_int),
        ('ClientAliveInterval',             SSHConfig._set_int),
        ('Compression',                     SSHConfig._set_bool),
        ('GSSAPIAuthentication',            SSHConfig._set_bool),
        ('GSSAPIKeyExchange',               SSHConfig._set_bool),
        ('HostbasedAuthentication',         SSHConfig._set_bool),
        ('HostCertificate',                 SSHConfig._append_string),
        ('HostKey',                         SSHConfig._append_string),
        ('KbdInteractiveAuthentication',    SSHConfig._set_bool),
        ('KexAlgorithms',                   SSHConfig._set_string),
        ('LoginGraceTime',                  SSHConfig._set_int),
        ('MACs',                            SSHConfig._set_string),
        ('PasswordAuthentication',          SSHConfig._set_bool),
        ('PermitTTY',                       SSHConfig._set_bool),
        ('Port',                            SSHConfig._set_int),
        ('PubkeyAuthentication',            SSHConfig._set_bool),
        ('RekeyLimit',                      SSHConfig._set_rekey_limits)
    )}
