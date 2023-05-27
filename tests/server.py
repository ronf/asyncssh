# Copyright (c) 2016-2021 by Ron Frederick <ronf@timeheart.net> and others.
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

"""SSH server used for unit tests"""

import asyncio
import os
import shutil
import signal
import socket
import subprocess

import asyncssh
from asyncssh.misc import async_context_manager

from .util import AsyncTestCase, all_tasks, current_task, get_test_key
from .util import run, x509_available


class Server(asyncssh.SSHServer):
    """Unit test SSH server"""

    def __init__(self):
        self._conn = None

    def connection_made(self, conn):
        """Record connection object for later use"""

        self._conn = conn

    def begin_auth(self, username):
        """Handle client authentication request"""

        return username != 'guest'


class ServerTestCase(AsyncTestCase):
    """Unit test class which starts an SSH server and agent"""

    _server = None
    _server_addr = ''
    _server_port = 0
    _agent_pid = None

    @classmethod
    @async_context_manager
    async def listen(cls, *, server_factory=(), options=None, **kwargs):
        """Create an SSH server for the tests to use"""

        if server_factory == ():
            server_factory = Server

        options = asyncssh.SSHServerConnectionOptions(
            options=options, server_factory=server_factory,
            gss_host=None, server_host_keys=['skey'])

        return await asyncssh.listen(port=0, family=socket.AF_INET,
                                     options=options, **kwargs)

    @classmethod
    @async_context_manager
    async def listen_reverse(cls, *, options=None, **kwargs):
        """Create a reverse SSH server for the tests to use"""

        options = asyncssh.SSHClientConnectionOptions(
            options=options, gss_host=None,
            known_hosts=(['skey.pub'], [], []))

        return await asyncssh.listen_reverse(port=0, family=socket.AF_INET,
                                             options=options, **kwargs)


    @classmethod
    async def create_server(cls, server_factory=(), **kwargs):
        """Create an SSH server for the tests to use"""

        return await cls.listen(server_factory=server_factory, **kwargs)

    @classmethod
    async def start_server(cls):
        """Start an SSH server for the tests to use"""

        return NotImplemented # pragma: no cover

    # Pylint doesn't like mixed case method names, but this was chosen to
    # match the convention used in the unittest module.

    # pylint: disable=invalid-name

    @classmethod
    async def asyncSetUpClass(cls):
        """Set up keys, an SSH server, and an SSH agent for the tests to use"""

        # pylint: disable=too-many-statements

        ckey = get_test_key('ssh-rsa')
        ckey.write_private_key('ckey')
        ckey.write_private_key('ckey_encrypted', passphrase='passphrase')
        ckey.write_public_key('ckey.pub')

        ckey_ecdsa = get_test_key('ecdsa-sha2-nistp256')
        ckey_ecdsa.write_private_key('ckey_ecdsa')
        ckey_ecdsa.write_public_key('ckey_ecdsa.pub')

        ckey_cert = ckey.generate_user_certificate(ckey, 'name',
                                                   principals=['ckey'])
        ckey_cert.write_certificate('ckey-cert.pub')

        skey = get_test_key('ssh-rsa', 1)
        skey.write_private_key('skey')
        skey.write_public_key('skey.pub')

        skey_ecdsa = get_test_key('ecdsa-sha2-nistp256', 1)
        skey_ecdsa.write_private_key('skey_ecdsa')
        skey_ecdsa.write_public_key('skey_ecdsa.pub')

        skey_cert = skey.generate_host_certificate(
            skey, 'name', principals=['127.0.0.1', 'localhost'])
        skey_cert.write_certificate('skey-cert.pub')

        skey_ecdsa_cert = skey_ecdsa.generate_host_certificate(
            skey_ecdsa, 'name', principals=['127.0.0.1', 'localhost'])
        skey_ecdsa_cert.write_certificate('skey_ecdsa-cert.pub')

        exp_cert = skey.generate_host_certificate(skey, 'name',
                                                  valid_after='-2d',
                                                  valid_before='-1d')
        skey.write_private_key('exp_skey')
        exp_cert.write_certificate('exp_skey-cert.pub')

        if x509_available: # pragma: no branch
            ckey_x509_self = ckey_ecdsa.generate_x509_user_certificate(
                ckey_ecdsa, 'OU=name', principals=['ckey'])
            ckey_ecdsa.write_private_key('ckey_x509_self')
            ckey_x509_self.append_certificate('ckey_x509_self', 'pem')
            ckey_x509_self.write_certificate('ckey_x509_self.pem', 'pem')
            ckey_x509_self.write_certificate('ckey_x509_self.pub')

            skey_x509_self = skey_ecdsa.generate_x509_host_certificate(
                skey_ecdsa, 'OU=name', principals=['127.0.0.1'])
            skey_ecdsa.write_private_key('skey_x509_self')
            skey_x509_self.append_certificate('skey_x509_self', 'pem')
            skey_x509_self.write_certificate('skey_x509_self.pem', 'pem')

            root_ca_key = get_test_key('ssh-rsa', 2)
            root_ca_key.write_private_key('root_ca_key')

            root_ca_cert = root_ca_key.generate_x509_ca_certificate(
                root_ca_key, 'OU=RootCA', ca_path_len=1)
            root_ca_cert.write_certificate('root_ca_cert.pem', 'pem')
            root_ca_cert.write_certificate('root_ca_cert.pub')

            int_ca_key = get_test_key('ssh-rsa', 3)
            int_ca_key.write_private_key('int_ca_key')

            int_ca_cert = root_ca_key.generate_x509_ca_certificate(
                int_ca_key, 'OU=IntCA', 'OU=RootCA', ca_path_len=0)
            int_ca_cert.write_certificate('int_ca_cert.pem', 'pem')

            ckey_x509_chain = int_ca_key.generate_x509_user_certificate(
                ckey, 'OU=name', 'OU=IntCA', principals=['ckey'])
            ckey.write_private_key('ckey_x509_chain')
            ckey_x509_chain.append_certificate('ckey_x509_chain', 'pem')
            int_ca_cert.append_certificate('ckey_x509_chain', 'pem')
            ckey_x509_chain.write_certificate('ckey_x509_partial.pem', 'pem')

            skey_x509_chain = int_ca_key.generate_x509_host_certificate(
                skey, 'OU=name', 'OU=IntCA', principals=['127.0.0.1'])
            skey.write_private_key('skey_x509_chain')
            skey_x509_chain.append_certificate('skey_x509_chain', 'pem')
            int_ca_cert.append_certificate('skey_x509_chain', 'pem')

            root_hash = root_ca_cert.x509_cert.subject_hash

            os.mkdir('cert_path')
            shutil.copy('root_ca_cert.pem',
                        os.path.join('cert_path', root_hash + '.0'))

            # Intentional hash mismatch
            shutil.copy('int_ca_cert.pem',
                        os.path.join('cert_path', root_hash + '.1'))

        for f in ('ckey', 'ckey_ecdsa', 'skey', 'exp_skey', 'skey_ecdsa'):
            os.chmod(f, 0o600)

        os.mkdir('.ssh', 0o700)
        os.mkdir(os.path.join('.ssh', 'crt'), 0o700)

        shutil.copy('ckey_ecdsa', os.path.join('.ssh', 'id_ecdsa'))
        shutil.copy('ckey_ecdsa.pub', os.path.join('.ssh', 'id_ecdsa.pub'))
        shutil.copy('ckey_encrypted', os.path.join('.ssh', 'id_rsa'))
        shutil.copy('ckey.pub', os.path.join('.ssh', 'id_rsa.pub'))
        shutil.copy('ckey-cert.pub', os.path.join('.ssh', 'id_rsa-cert.pub'))

        with open('authorized_keys', 'w') as auth_keys:
            with open('ckey.pub') as ckey_pub:
                shutil.copyfileobj(ckey_pub, auth_keys)

            with open('ckey_ecdsa.pub') as ckey_ecdsa_pub:
                shutil.copyfileobj(ckey_ecdsa_pub, auth_keys)

            auth_keys.write('cert-authority,principals="ckey",'
                            'permitopen=:* ')

            with open('ckey.pub') as ckey_pub:
                shutil.copyfileobj(ckey_pub, auth_keys)

        if x509_available: # pragma: no branch
            with open('authorized_keys_x509', 'w') as auth_keys_x509:
                with open('ckey_x509_self.pub') as ckey_self_pub:
                    shutil.copyfileobj(ckey_self_pub, auth_keys_x509)

                auth_keys_x509.write('cert-authority,principals="ckey" ')

                with open('root_ca_cert.pub') as root_pub:
                    shutil.copyfileobj(root_pub, auth_keys_x509)

            shutil.copy('skey_x509_self.pem',
                        os.path.join('.ssh', 'ca-bundle.crt'))

        os.environ['LOGNAME'] = 'guest'
        os.environ['HOME'] = '.'
        os.environ['USERPROFILE'] = '.'

        cls._server = await cls.start_server()

        sock = cls._server.sockets[0]
        cls._server_addr = '127.0.0.1'
        cls._server_port = sock.getsockname()[1]

        host = '[%s]:%d,localhost ' % (cls._server_addr, cls._server_port)

        with open('known_hosts', 'w') as known_hosts:
            known_hosts.write(host)

            with open('skey.pub') as skey_pub:
                shutil.copyfileobj(skey_pub, known_hosts)

            known_hosts.write('@cert-authority * ')

            with open('skey.pub') as skey_pub:
                shutil.copyfileobj(skey_pub, known_hosts)

        shutil.copy('known_hosts', os.path.join('.ssh', 'known_hosts'))

        if 'DISPLAY' in os.environ: # pragma: no cover
            del os.environ['DISPLAY']
        if 'SSH_ASKPASS' in os.environ: # pragma: no cover
            del os.environ['SSH_ASKPASS']
        if 'SSH_AUTH_SOCK' in os.environ: # pragma: no cover
            del os.environ['SSH_AUTH_SOCK']
        if 'XAUTHORITY' in os.environ: # pragma: no cover
            del os.environ['XAUTHORITY']

        try:
            output = run('ssh-agent -a agent 2>/dev/null')
        except subprocess.CalledProcessError: # pragma: no cover
            cls._agent_pid = None
        else:
            cls._agent_pid = int(output.splitlines()[2].split()[3][:-1])

            os.environ['SSH_AUTH_SOCK'] = 'agent'

            async with asyncssh.connect_agent() as agent:
                await agent.add_keys([ckey_ecdsa, (ckey, ckey_cert)])

        with open('ssh-keysign', 'wb'):
            pass

    @classmethod
    async def asyncTearDownClass(cls):
        """Shut down test server and agent"""

        tasks = all_tasks()
        tasks.remove(current_task())

        await asyncio.gather(*tasks, return_exceptions=True)

        cls._server.close()
        await cls._server.wait_closed()

        if cls._agent_pid: # pragma: no branch
            os.kill(cls._agent_pid, signal.SIGTERM)

    # pylint: enable=invalid-name

    def agent_available(self):
        """Return whether SSH agent is available"""

        return bool(self._agent_pid)

    @async_context_manager
    async def connect(self, host=(), port=(), gss_host=None,
                      options=None, **kwargs):
        """Open a connection to the test server"""

        return await asyncssh.connect(host or self._server_addr,
                                      port or self._server_port,
                                      gss_host=gss_host, options=options,
                                      **kwargs)

    @async_context_manager
    async def connect_reverse(self, options=None, gss_host=None, **kwargs):
        """Create a connection to the test server"""

        options = asyncssh.SSHServerConnectionOptions(options,
                                                      server_factory=Server,
                                                      server_host_keys=['skey'],
                                                      gss_host=gss_host)

        return await asyncssh.connect_reverse(self._server_addr,
                                              self._server_port,
                                              options=options, **kwargs)

    @async_context_manager
    async def run_client(self, sock, config=(), options=None, **kwargs):
        """Run an SSH client on an already-connected socket"""

        return await asyncssh.run_client(sock, config, options, **kwargs)

    @async_context_manager
    async def run_server(self, sock, config=(), options=None, **kwargs):
        """Run an SSH server on an already-connected socket"""

        options = asyncssh.SSHServerConnectionOptions(options,
                                                      server_factory=Server,
                                                      server_host_keys=['skey'])

        return await asyncssh.run_server(sock, config, options, **kwargs)

    async def create_connection(self, client_factory, **kwargs):
        """Create a connection to the test server"""

        conn = await self.connect(client_factory=client_factory, **kwargs)

        return conn, conn.get_owner()
