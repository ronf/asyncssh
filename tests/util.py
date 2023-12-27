# Copyright (c) 2015-2022 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Utility functions for unit tests"""

import asyncio
import binascii
import functools
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from unittest.mock import patch

from asyncssh import set_default_skip_rsa_key_validation
from asyncssh.gss import gss_available
from asyncssh.logging import logger
from asyncssh.misc import ConnectionLost, SignalReceived
from asyncssh.packet import Byte, String, UInt32, UInt64
from asyncssh.public_key import generate_private_key


# pylint: disable=ungrouped-imports, unused-import

try:
    import bcrypt
    bcrypt_available = hasattr(bcrypt, 'kdf')
except ImportError: # pragma: no cover
    bcrypt_available = False

nc_available = bool(shutil.which('nc'))

try:
    import uvloop
    uvloop_available = True
except ImportError: # pragma: no cover
    uvloop_available = False

try:
    from asyncssh.crypto import X509Name
    x509_available = True
except ImportError: # pragma: no cover
    x509_available = False

# pylint: enable=ungrouped-imports, unused-import

# pylint: disable=no-member

if hasattr(asyncio, 'all_tasks'):
    all_tasks = asyncio.all_tasks
    current_task = asyncio.current_task
else: # pragma: no cover
    all_tasks = asyncio.Task.all_tasks
    current_task = asyncio.Task.current_task

# pylint: enable=no-member


_test_keys = {}

set_default_skip_rsa_key_validation(True)


def asynctest(coro):
    """Decorator for async tests, for use with AsyncTestCase"""

    @functools.wraps(coro)
    def async_wrapper(self, *args, **kwargs):
        """Run a coroutine and wait for it to finish"""

        return self.loop.run_until_complete(coro(self, *args, **kwargs))

    return async_wrapper


def patch_getnameinfo(cls):
    """Decorator for patching socket.getnameinfo"""

    def getnameinfo(sockaddr, flags):
        """Mock reverse DNS lookup of client address"""

        # pylint: disable=unused-argument

        return ('localhost', sockaddr[1])

    return patch('socket.getnameinfo', getnameinfo)(cls)


def patch_extra_kex(cls):
    """Decorator for skipping extra kex algs"""

    def skip_extra_kex_algs(self):
        """Don't send extra key exchange algorithms"""

        # pylint: disable=unused-argument

        return []

    return patch('asyncssh.connection.SSHConnection._get_extra_kex_algs',
                 skip_extra_kex_algs)(cls)


def patch_gss(cls):
    """Decorator for patching GSSAPI classes"""

    if not gss_available: # pragma: no cover
        return cls

    # pylint: disable=import-outside-toplevel

    if sys.platform == 'win32': # pragma: no cover
        from .sspi_stub import SSPIAuth

        cls = patch('asyncssh.gss_win32.ClientAuth', SSPIAuth)(cls)
        cls = patch('asyncssh.gss_win32.ServerAuth', SSPIAuth)(cls)
    else:
        from .gssapi_stub import Name, Credentials, RequirementFlag
        from .gssapi_stub import SecurityContext

        cls = patch('asyncssh.gss_unix.Name', Name)(cls)
        cls = patch('asyncssh.gss_unix.Credentials', Credentials)(cls)
        cls = patch('asyncssh.gss_unix.RequirementFlag', RequirementFlag)(cls)
        cls = patch('asyncssh.gss_unix.SecurityContext', SecurityContext)(cls)

    return cls


async def echo(stdin, stdout, stderr=None):
    """Echo data from stdin back to stdout and stderr (if open)"""

    try:
        while not stdin.at_eof():
            data = await stdin.read(65536)

            if data:
                stdout.write(data)

                if stderr:
                    stderr.write(data)

        await stdout.drain()

        if stderr:
            await stderr.drain()

        stdout.write_eof()
    except SignalReceived as exc:
        if exc.signal == 'ABRT':
            raise ConnectionLost('Abort') from None
        else:
            stdin.channel.exit_with_signal(exc.signal)
    except OSError:
        pass

    stdout.close()


def _encode_options(options):
    """Encode SSH certificate critical options and extensions"""

    return b''.join((String(k) + String(v) for k, v in options.items()))


def get_test_key(alg_name, key_id=0, **kwargs):
    """Generate or return a key with the requested parameters"""

    params = tuple((alg_name, key_id)) + tuple(kwargs.items())

    try:
        key = _test_keys[params]
    except KeyError:
        key = generate_private_key(alg_name, **kwargs)
        _test_keys[params] = key

    return key


def make_certificate(cert_version, cert_type, key, signing_key, principals,
                     key_id='name', valid_after=0,
                     valid_before=0xffffffffffffffff, options=None,
                     extensions=None, bad_signature=False):
    """Construct an SSH certificate"""

    keydata = key.encode_ssh_public()
    principals = b''.join((String(p) for p in principals))
    options = _encode_options(options) if options else b''
    extensions = _encode_options(extensions) if extensions else b''
    signing_keydata = b''.join((String(signing_key.algorithm),
                                signing_key.encode_ssh_public()))

    data = b''.join((String(cert_version), String(os.urandom(32)), keydata,
                     UInt64(0), UInt32(cert_type), String(key_id),
                     String(principals), UInt64(valid_after),
                     UInt64(valid_before), String(options),
                     String(extensions), String(''), String(signing_keydata)))

    if bad_signature:
        data += String('')
    else:
        data += String(signing_key.sign(data, signing_key.sig_algorithms[0]))

    return b''.join((cert_version.encode('ascii'), b' ',
                     binascii.b2a_base64(data)))


def run(cmd):
    """Run a shell commands and return the output"""

    try:
        return subprocess.check_output(cmd, shell=True,
                                       stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as exc: # pragma: no cover
        logger.error('Error running command: %s' % cmd)
        logger.error(exc.output.decode())
        raise


def try_remove(filename):
    """Try to remove a file, ignoring errors"""

    try:
        os.remove(filename)
    except OSError: # pragma: no cover
        pass


class ConnectionStub:
    """Stub class used to replace an SSHConnection object"""

    def __init__(self, peer, server):
        self._peer = peer
        self._server = server

        if peer:
            self._packet_queue = asyncio.queues.Queue()
            self._queue_task = self.create_task(self._process_packets())
        else:
            self._packet_queue = None
            self._queue_task = None

        self._logger = logger.get_child(context='conn=99')

    @property
    def logger(self):
        """A logger associated with this connection"""

        return self._logger

    async def _run_task(self, coro):
        """Run an asynchronous task"""

        # pylint: disable=broad-except
        try:
            await coro
        except Exception as exc:
            if self._peer: # pragma: no branch
                self.queue_packet(exc)

            self.connection_lost(exc)

    def create_task(self, coro):
        """Create an asynchronous task"""

        return asyncio.ensure_future(self._run_task(coro))

    def is_client(self):
        """Return if this is a client connection"""

        return not self._server

    def is_server(self):
        """Return if this is a server connection"""

        return self._server

    def get_peer(self):
        """Return the peer of this connection"""

        return self._peer

    async def _process_packets(self):
        """Process the queue of incoming packets"""

        while True:
            data = await self._packet_queue.get()

            if data is None or isinstance(data, Exception):
                self._queue_task = None
                self.connection_lost(data)
                break

            self.process_packet(data)

    def connection_lost(self, exc):
        """Handle the closing of a connection"""

        raise NotImplementedError

    def process_packet(self, data):
        """Process an incoming packet"""

        raise NotImplementedError

    def queue_packet(self, data):
        """Add an incoming packet to the queue"""

        self._packet_queue.put_nowait(data)

    def send_packet(self, pkttype, *args, **kwargs):
        """Send a packet to this connection's peer"""

        # pylint: disable=unused-argument

        if self._peer:
            self._peer.queue_packet(Byte(pkttype) + b''.join(args))

    def close(self):
        """Close the connection, stopping processing of incoming packets"""

        if self._peer:
            self._peer.queue_packet(None)
            self._peer = None

        if self._queue_task:
            self.queue_packet(None)
            self._queue_task = None


if hasattr(unittest.TestCase, 'addClassCleanup'):
    ClassCleanupTestCase = unittest.TestCase
else: # pragma: no cover
    class ClassCleanupTestCase(unittest.TestCase):
        """Stripped down version of class cleanup for Python 3.7 & earlier"""

        _class_cleanups = []

        # pylint: disable=arguments-differ

        @classmethod
        def addClassCleanup(cls, function, *args, **kwargs):
            """Add a cleanup to run after tearDownClass"""

            cls._class_cleanups.append((function, args, kwargs))

        @classmethod
        def tearDownClass(cls):
            """Run cleanups after tearDown"""

            super().tearDownClass()

            while cls._class_cleanups:
                function, args, kwargs = cls._class_cleanups.pop()
                function(*args, **kwargs)


class TempDirTestCase(ClassCleanupTestCase):
    """Unit test class which operates in a temporary directory"""

    _tempdir = None

    @classmethod
    def setUpClass(cls):
        """Create temporary directory and set it as current directory"""

        cls._tempdir = tempfile.TemporaryDirectory()
        os.chdir(cls._tempdir.name)

    @classmethod
    def tearDownClass(cls):
        """Clean up temporary directory"""

        os.chdir('..')
        cls._tempdir.cleanup()


class AsyncTestCase(TempDirTestCase):
    """Unit test class which supports tests using asyncio"""

    loop = None

    @classmethod
    def setUpClass(cls):
        """Set up event loop to run async tests and run async class setup"""

        super().setUpClass()

        if uvloop_available and os.environ.get('USE_UVLOOP'): # pragma: no cover
            cls.loop = uvloop.new_event_loop()
        else:
            cls.loop = asyncio.new_event_loop()

        asyncio.set_event_loop(cls.loop)

        try:
            cls.loop.run_until_complete(cls.asyncSetUpClass())
        except AttributeError:
            pass

    @classmethod
    def tearDownClass(cls):
        """Run async class teardown and close event loop"""

        try:
            cls.loop.run_until_complete(cls.asyncTearDownClass())
        except AttributeError:
            pass

        cls.loop.close()

        super().tearDownClass()

    def setUp(self):
        """Run async setup if any"""

        try:
            self.loop.run_until_complete(self.asyncSetUp())
        except AttributeError:
            pass

    def tearDown(self):
        """Run async teardown if any"""

        try:
            self.loop.run_until_complete(self.asyncTearDown())
        except AttributeError:
            pass
