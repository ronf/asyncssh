# Copyright (c) 2020-2024 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Unit tests for parsing OpenSSH-compatible config file"""

import os
import socket
import unittest

from pathlib import Path
from unittest.mock import patch

import asyncssh

from asyncssh.config import SSHClientConfig, SSHServerConfig

from .util import TempDirTestCase


class _TestConfig(TempDirTestCase):
    """Unit tests for config module"""

    @classmethod
    def setUpClass(cls):
        """Set up $HOME and .ssh directory"""

        super().setUpClass()

        os.mkdir('.ssh', 0o700)
        os.environ['HOME'] = '.'
        os.environ['USERPROFILE'] = '.'

    def _load_config(self, config, last_config=None, reload=False):
        """Abstract method to load a config object"""

        raise NotImplementedError

    def _parse_config(self, config_data, **kwargs):
        """Return a config object based on the specified data"""

        with open('config', 'w') as f:
            f.write(config_data)

        return self._load_config('config', **kwargs)

    def test_blank_and_comment(self):
        """Test blank and comment lines"""

        config = self._parse_config('\n#Port 22')
        self.assertIsNone(config.get('Port'))

    def test_set_bool(self):
        """Test boolean config option"""

        for value, result in (('yes', True), ('true', True),
                              ('no', False), ('false', False)):
            config = self._parse_config('Compression %s' % value)
            self.assertEqual(config.get('Compression'), result)

        config = self._parse_config('Compression yes\nCompression no')
        self.assertEqual(config.get('Compression'), True)

    def test_set_int(self):
        """Test integer config option"""

        config = self._parse_config('Port 1')
        self.assertEqual(config.get('Port'), 1)

        config = self._parse_config('Port 1\nPort 2')
        self.assertEqual(config.get('Port'), 1)

    def test_set_string(self):
        """Test string config option"""

        config = self._parse_config('BindAddress addr')
        self.assertEqual(config.get('BindAddress'), 'addr')

        config = self._parse_config('BindAddress addr1\nBindAddress addr2')
        self.assertEqual(config.get('BindAddress'), 'addr1')

    def test_set_address_family(self):
        """Test address family config option"""

        for family, result in (('any', socket.AF_UNSPEC),
                               ('inet', socket.AF_INET),
                               ('inet6', socket.AF_INET6)):
            config = self._parse_config('AddressFamily %s' % family)
            self.assertEqual(config.get('AddressFamily'), result)

        config = self._parse_config('AddressFamily inet\n'
                                    'AddressFamily inet6')
        self.assertEqual(config.get('AddressFamily'), socket.AF_INET)

    def test_set_rekey_limit(self):
        """Test rekey limit config option"""

        for value, result in (('1', ('1', ())),
                              ('1 2', ('1', '2')),
                              ('1 none', ('1', None)),
                              ('default', ((), ())),
                              ('default 2', ((), '2')),
                              ('default none', ((), None))):
            config = self._parse_config('RekeyLimit %s' % value)
            self.assertEqual(config.get('RekeyLimit'), result)

        config = self._parse_config('RekeyLimit 1 2\nRekeyLimit 3 4')
        self.assertEqual(config.get('RekeyLimit'), ('1', '2'))

    def test_get_compression_algs(self):
        """Test getting compression algorithms"""

        config = self._parse_config('Compression yes')
        self.assertEqual(config.get_compression_algs(),
                         'zlib@openssh.com,zlib,none')

        config = self._parse_config('Compression no')
        self.assertEqual(config.get_compression_algs(),
                         'none,zlib@openssh.com,zlib')

        config = self._parse_config('')
        self.assertEqual(config.get_compression_algs(), ())

    def test_include(self):
        """Test include config option"""

        with open('.ssh/include', 'w') as f:
            f.write('Port 2222')

        for path in ('include', Path('.ssh/include').absolute().as_posix()):
            config = self._parse_config('Include %s' % path)
            self.assertEqual(config.get('Port'), 2222)

    def test_missing_include(self):
        """Test missing include target"""

        # Missing include files should be ignored
        self._parse_config('Include xxx')

    def test_multiple_include(self):
        """Test multiple levels of include"""

        os.mkdir('.ssh/dir1')
        os.mkdir('.ssh/dir2')

        with open('.ssh/include', 'w') as f:
            f.write('Include dir1/include2\n'
                    'Include dir2/include4\n')

        with open('.ssh/dir1/include2', 'w') as f:
            f.write('Include dir1/include3\n')

        with open('.ssh/dir1/include3', 'w') as f:
            f.write('AddressFamily inet\n')

        with open('.ssh/dir2/include4', 'w') as f:
            f.write('Port 2222\n')

        config = self._parse_config('Include include')
        self.assertEqual(config.get('AddressFamily'), socket.AF_INET)
        self.assertEqual(config.get('Port'), 2222)

    def test_match_all(self):
        """Test a match block which always matches"""

        config = self._parse_config('Match user xxx\nMatch all\nPort 2222')
        self.assertEqual(config.get('Port'), 2222)

    def test_match_exec(self):
        """Test a match block which runs a subprocess"""

        config = self._parse_config('Match exec "exit 0"\nPort 2222')
        self.assertEqual(config.get('Port'), 2222)


        config = self._parse_config('Match exec "exit 1"\nPort 2222')
        self.assertEqual(config.get('Port'), None)

    def test_config_disabled(self):
        """Test config loading being disabled"""

        self._load_config(None)

    def test_config_list(self):
        """Test reading multiple config files"""

        with open('config1', 'w') as f:
            f.write('BindAddress addr')

        with open('config2', 'w') as f:
            f.write('Port 2222')

        config = self._load_config(['config1', 'config2'])
        self.assertEqual(config.get('BindAddress'), 'addr')
        self.assertEqual(config.get('Port'), 2222)

    def test_equals(self):
        """Test config option with equals instead of space"""

        for delimiter in ('=', ' =', '= ', ' = '):
            config = self._parse_config('Compression%syes' % delimiter)
            self.assertEqual(config.get('Compression'), True)

    def test_unknown(self):
        """Test unknown config option"""

        config = self._parse_config('XXX')
        self.assertIsNone(config.get('XXX'))

    def test_errors(self):
        """Test config errors"""

        for desc, config_data in (
                ('Missing value', 'AddressFamily'),
                ('Unbalanced quotes', 'BindAddress "foo'),
                ('Extra data at end', 'BindAddress foo bar'),
                ('Invalid address family', 'AddressFamily xxx'),
                ('Invalid boolean', 'Compression xxx'),
                ('Invalid integer', 'Port xxx'),
                ('Invalid match condition', 'Match xxx')):
            with self.subTest(desc):
                with self.assertRaises(asyncssh.ConfigParseError):
                    self._parse_config(config_data)


class _TestClientConfig(_TestConfig):
    """Unit tests for client config objects"""

    def _load_config(self, config, last_config=None, reload=False,
                     local_user='user', user=(), host='host', port=()):
        """Load a client configuration"""

        # pylint: disable=arguments-differ

        return SSHClientConfig.load(last_config, config, reload,
                                    local_user, user, host, port)

    def test_set_string_none(self):
        """Test string config option"""

        config = self._parse_config('IdentityAgent none')
        self.assertIsNone(config.get('IdentityAgent', ()))

    def test_append_string(self):
        """Test appending a string config option to a list"""

        config = self._parse_config('IdentityFile foo\nIdentityFile bar')
        self.assertEqual(config.get('IdentityFile'), ['foo', 'bar'])

        config = self._parse_config('IdentityFile foo\nIdentityFile none')
        self.assertEqual(config.get('IdentityFile'), ['foo'])

        config = self._parse_config('IdentityFile none')
        self.assertEqual(config.get('IdentityFile'), [])

    def test_set_string_list(self):
        """Test string list config option"""

        config = self._parse_config('UserKnownHostsFile file1 file2')
        self.assertEqual(config.get('UserKnownHostsFile'), ['file1', 'file2'])

        config = self._parse_config('UserKnownHostsFile file1\n'
                                    'UserKnownHostsFile file2')
        self.assertEqual(config.get('UserKnownHostsFile'), ['file1'])

        config = self._parse_config('UserKnownHostsFile none\n'
                                    'UserKnownHostsFile file2')
        self.assertEqual(config.get('UserKnownHostsFile'), [])

    def test_append_string_list(self):
        """Test appending multiple string config options to a list"""

        config = self._parse_config('SendEnv foo\nSendEnv  bar baz')
        self.assertEqual(config.get('SendEnv'), ['foo', 'bar', 'baz'])

    def test_set_remote_command(self):
        """Test setting a remote command"""

        config = self._parse_config('    RemoteCommand     foo  bar  baz')
        self.assertEqual(config.get('RemoteCommand'), 'foo  bar  baz')

    def test_set_request_tty(self):
        """Test pseudo-terminal request config option"""

        for value, result in (('yes', True), ('true', True),
                              ('no', False), ('false', False),
                              ('force', 'force'), ('auto', 'auto')):
            config = self._parse_config('RequestTTY %s' % value)
            self.assertEqual(config.get('RequestTTY'), result)

        config = self._parse_config('RequestTTY yes\nRequestTTY no')
        self.assertEqual(config.get('RequestTTY'), True)

    def test_set_and_match_hostname(self):
        """Test setting and matching hostname"""

        config = self._parse_config('Host host\n'
                                    '  Hostname new%h\n'
                                    'Match originalhost host\n'
                                    '  BindAddress addr\n'
                                    'Match host host\n'
                                    '  Port 1111\n'
                                    'Match host newhost\n'
                                    '  Hostname newhost2\n'
                                    '  Port 2222')

        self.assertEqual(config.get('Hostname'), 'newhost')
        self.assertEqual(config.get('BindAddress'), 'addr')
        self.assertEqual(config.get('Port'), 2222)

    def test_host_key_alias(self):
        """Test setting HostKeyAlias"""

        config = self._parse_config('Host host\n'
                                    '  Hostname 127.0.0.1\n'
                                    '  HostKeyAlias alias')

        self.assertEqual(config.get('HostKeyAlias'), 'alias')

    def test_set_and_match_user(self):
        """Test setting and matching user"""

        config = self._parse_config('User newuser\n'
                                    'Match localuser user\n'
                                    '  BindAddress addr\n'
                                    'Match user user\n'
                                    '  Port 1111\n'
                                    'Match user new*\n'
                                    '  User newuser2\n'
                                    '  Port 2222')

        self.assertEqual(config.get('User'), 'newuser')
        self.assertEqual(config.get('BindAddress'), 'addr')
        self.assertEqual(config.get('Port'), 2222)

    def test_tag(self):
        """Test setting and matching a tag"""

        config = self._parse_config('Tag tag2\n'
                                    'Match tagged tag1\n'
                                    '  Port 1111\n'
                                    'Match tagged tag*\n'
                                    '  Port 2222')

        self.assertEqual(config.get('Port'), 2222)

    def test_port_already_set(self):
        """Test that port is ignored if set outside of the config"""

        config = self._parse_config('Port 2222', port=22)

        self.assertEqual(config.get('Port'), 22)

    def test_user_already_set(self):
        """Test that user is ignored if set outside of the config"""

        config = self._parse_config('User newuser', user='user')

        self.assertEqual(config.get('User'), 'user')

    def test_client_errors(self):
        """Test client config errors"""

        for desc, config_data in (
                ('Invalid pseudo-terminal request', 'RequestTTY xxx'),
                ('Missing match host', 'Match host')):
            with self.subTest(desc):
                with self.assertRaises(asyncssh.ConfigParseError):
                    self._parse_config(config_data)

    def test_percent_expansion(self):
        """Test token percent expansion"""

        def mock_gethostname():
            """Return a static local hostname for testing"""

            return 'thishost.local'

        def mock_expanduser(_):
            """Return a static local home directory"""

            return '/home/user'

        with patch('socket.gethostname', mock_gethostname):
            with patch('os.path.expanduser', mock_expanduser):
                config = self._parse_config(
                    'Hostname newhost\n'
                    'User newuser\n'
                    'Port 2222\n'
                    'RemoteCommand %% %C %d %h %L %l %n %p %r %u')

        self.assertEqual(config.get('RemoteCommand'),
                         '% 98625d1ca14854f2cdc34268f2afcad5237e2d9d '
                         '/home/user newhost thishost thishost.local '
                         'host 2222 newuser user')

    @unittest.skipUnless(hasattr(os, 'getuid'), 'UID not available')
    def test_uid_percent_expansion(self):
        """Test UID token percent expansion where available"""

        def mock_getuid():
            """Return a static local UID"""

            return 123

        with patch('os.getuid', mock_getuid):
            config = self._parse_config('RemoteCommand %i')

        self.assertEqual(config.get('RemoteCommand'), '123')

    def test_home_percent_expansion_unavailable(self):
        """Test home directory token percent expansion not being available"""

        def mock_expanduser(path):
            """Don't expand the home directory"""

            return path

        def mock_pathlib_expanduser(self):
            """Expand user even with os.path.expanduser mocked out"""

            return Path(os.environ['HOME'], *self.parts[1:])

        with self.assertRaises(asyncssh.ConfigParseError):
            with patch('os.path.expanduser', mock_expanduser), \
                    patch('pathlib.Path.expanduser', mock_pathlib_expanduser):
                self._parse_config('RemoteCommand %d')

    def test_uid_percent_expansion_unavailable(self):
        """Test UID token percent expansion not being available"""

        orig_hasattr = hasattr

        def mock_hasattr(obj, attr):
            if obj == os and attr == 'getuid':
                return False
            else:
                return orig_hasattr(obj, attr)

        with self.assertRaises(asyncssh.ConfigParseError):
            with patch('builtins.hasattr', mock_hasattr):
                self._parse_config('RemoteCommand %i')

    def test_invalid_percent_expansion(self):
        """Test invalid percent expansion"""

        for desc, config_data in (
                ('Bad token in hostname', 'Hostname %p'),
                ('Invalid token', 'IdentityFile %x'),
                ('Percent at end', 'IdentityFile %')):
            with self.subTest(desc):
                with self.assertRaises(asyncssh.ConfigParseError):
                    self._parse_config(config_data)

class _TestServerConfig(_TestConfig):
    """Unit tests for server config objects"""

    def _load_config(self, config, last_config=None, reload=False,
                     local_addr='127.0.0.1', local_port=22,
                     user='user', host=None, addr='127.0.0.1'):
        """Load a server configuration"""

        # pylint: disable=arguments-differ

        return SSHServerConfig.load(last_config, config, reload,
                                    local_addr, local_port, user, host, addr)

    def test_match_local_address(self):
        """Test matching on local address"""

        config = self._parse_config('Match localaddress 127.0.0.1\n'
                                    'PermitTTY no')
        self.assertEqual(config.get('PermitTTY'), False)

    def test_match_local_port(self):
        """Test matching on local port"""

        config = self._parse_config('Match localport 22\nPermitTTY no')
        self.assertEqual(config.get('PermitTTY'), False)

    def test_match_user(self):
        """Test matching on user"""

        config = self._parse_config('Match user user\nPermitTTY no')
        self.assertEqual(config.get('PermitTTY'), False)

    def test_match_address(self):
        """Test matching on client address"""

        config = self._parse_config('Match address 127.0.0.0/8\nPermitTTY no')
        self.assertEqual(config.get('PermitTTY'), False)

    def test_reload(self):
        """Test update of match options"""

        config = self._parse_config('Match address 1.1.1.1\n'
                                    '  PermitTTY no\n'
                                    'Match address 2.2.2.2\n'
                                    '  PermitTTY yes\n', addr='1.1.1.1')

        self.assertEqual(config.get('PermitTTY'), False)

        config = self._load_config('config', config, True, addr='2.2.2.2')

        self.assertEqual(config.get('PermitTTY'), True)


del _TestConfig


class _TestOptions(TempDirTestCase):
    """Test client and server connection options"""

    def test_client_options(self):
        """Test client connection options"""

        with open('config', 'w') as f:
            f.write('User newuser\nServerAliveInterval 1')

        options = asyncssh.SSHClientConnectionOptions(
            username='user', config='config')

        self.assertEqual(options.username, 'user')
        self.assertEqual(options.keepalive_interval, 1)

        with open('config', 'w') as f:
            f.write('ServerAliveInterval 2\nServerAliveCountMax 3\n')

        options = asyncssh.SSHClientConnectionOptions(options, config='config')

        self.assertEqual(options.keepalive_interval, 1)
        self.assertEqual(options.keepalive_count_max, 3)

    def test_server_options(self):
        """Test server connection options"""

        with open('config', 'w') as f:
            f.write('ClientAliveInterval 1\nClientAliveInterval 2')

        options = asyncssh.SSHServerConnectionOptions(config='config')

        self.assertEqual(options.keepalive_interval, 1)

        with open('config', 'w') as f:
            f.write('ClientAliveInterval 2\nClientAliveCountMax 3\n')

        options = asyncssh.SSHServerConnectionOptions(options, config='config')

        self.assertEqual(options.keepalive_interval, 1)
        self.assertEqual(options.keepalive_count_max, 3)
