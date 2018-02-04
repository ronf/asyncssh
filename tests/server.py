# Copyright (c) 2016-2017 by Ron Frederick <ronf@timeheart.net>.
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

"""SSH server used for unit tests"""

import asyncio
import os
import shutil
import signal
import socket
import subprocess

import asyncssh
from asyncssh.misc import async_context_manager

from .util import AsyncTestCase, run, x509_available


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

    # Pylint doesn't like mixed case method names, but this was chosen to
    # match the convention used in the unittest module.

    # pylint: disable=invalid-name

    _server = None
    _server_addr = None
    _server_port = None
    _agent_pid = None

    @classmethod
    @asyncio.coroutine
    def create_server(cls, server_factory=(), *, loop=(),
                      server_host_keys=(), gss_host=None, **kwargs):
        """Create an SSH server for the tests to use"""

        if loop == ():
            loop = cls.loop

        if server_factory == ():
            server_factory = Server

        if server_host_keys == ():
            server_host_keys = ['skey']

        return (yield from asyncssh.create_server(
            server_factory, port=0, family=socket.AF_INET, loop=loop,
            server_host_keys=server_host_keys, gss_host=gss_host, **kwargs))

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SSH server for the tests to use"""

        return (yield from cls.create_server())

    @classmethod
    @asyncio.coroutine
    def asyncSetUpClass(cls):
        """Set up keys, an SSH server, and an SSH agent for the tests to use"""

        # pylint: disable=too-many-statements

        ckey = asyncssh.generate_private_key('ssh-rsa')
        ckey.write_private_key('ckey')
        ckey.write_private_key('ckey_encrypted', passphrase='passphrase')
        ckey.write_public_key('ckey.pub')

        ckey_ecdsa = asyncssh.generate_private_key('ecdsa-sha2-nistp256')
        ckey_ecdsa.write_private_key('ckey_ecdsa')
        ckey_ecdsa.write_public_key('ckey_ecdsa.pub')

        ckey_cert = ckey.generate_user_certificate(ckey, 'name',
                                                   principals=['ckey'])
        ckey_cert.write_certificate('ckey-cert.pub')

        skey = asyncssh.generate_private_key('ssh-rsa')
        skey.write_private_key('skey')
        skey.write_public_key('skey.pub')

        skey_ecdsa = asyncssh.generate_private_key('ecdsa-sha2-nistp256')
        skey_ecdsa.write_private_key('skey_ecdsa')
        skey_ecdsa.write_public_key('skey_ecdsa.pub')

        skey_cert = skey.generate_host_certificate(skey, 'name',
                                                   principals=['127.0.0.1'])
        skey_cert.write_certificate('skey-cert.pub')

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

            root_ca_key = asyncssh.generate_private_key('ssh-rsa')
            root_ca_key.write_private_key('root_ca_key')

            root_ca_cert = root_ca_key.generate_x509_ca_certificate(
                root_ca_key, 'OU=RootCA', ca_path_len=1)
            root_ca_cert.write_certificate('root_ca_cert.pem', 'pem')
            root_ca_cert.write_certificate('root_ca_cert.pub')

            int_ca_key = asyncssh.generate_private_key('ssh-rsa')
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
        os.mkdir('.ssh/crt', 0o700)

        shutil.copy('ckey_ecdsa', os.path.join('.ssh', 'id_ecdsa'))
        shutil.copy('ckey_ecdsa.pub', os.path.join('.ssh', 'id_ecdsa.pub'))
        shutil.copy('ckey_encrypted', os.path.join('.ssh', 'id_rsa'))
        shutil.copy('ckey.pub', os.path.join('.ssh', 'id_rsa.pub'))

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

        cls._server = yield from cls.start_server()

        sock = cls._server.sockets[0]
        cls._server_addr = '127.0.0.1'
        cls._server_port = sock.getsockname()[1]

        host = '[%s]:%s ' % (cls._server_addr, cls._server_port)

        with open('known_hosts', 'w') as known_hosts:
            known_hosts.write(host)

            with open('skey.pub') as skey_pub:
                shutil.copyfileobj(skey_pub, known_hosts)

            known_hosts.write('@cert-authority ' + host)

            with open('skey.pub') as skey_pub:
                shutil.copyfileobj(skey_pub, known_hosts)

        shutil.copy('known_hosts', os.path.join('.ssh', 'known_hosts'))

        os.environ['LOGNAME'] = 'guest'
        os.environ['HOME'] = '.'

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

            agent = yield from asyncssh.connect_agent()
            yield from agent.add_keys([ckey_ecdsa, (ckey, ckey_cert)])
            agent.close()

    @classmethod
    @asyncio.coroutine
    def asyncTearDownClass(cls):
        """Shut down test server and agent"""

        # Wait a bit for existing tasks to exit
        yield from asyncio.sleep(1)

        cls._server.close()
        yield from cls._server.wait_closed()

        if cls._agent_pid: # pragma: no branch
            os.kill(cls._agent_pid, signal.SIGTERM)

    # pylint: enable=invalid-name

    def agent_available(self):
        """Return whether SSH agent is available"""

        return bool(self._agent_pid)

    @asyncio.coroutine
    def create_connection(self, client_factory, loop=(),
                          gss_host=None, **kwargs):
        """Create a connection to the test server"""

        if loop == ():
            loop = self.loop

        return (yield from asyncssh.create_connection(client_factory,
                                                      self._server_addr,
                                                      self._server_port,
                                                      loop=loop,
                                                      gss_host=gss_host,
                                                      **kwargs))

    @async_context_manager
    def connect(self, **kwargs):
        """Open a connection to the test server"""

        conn, _ = yield from self.create_connection(None, **kwargs)

        return conn
