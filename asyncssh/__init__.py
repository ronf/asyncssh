# Copyright (c) 2013-2016 by Ron Frederick <ronf@timeheart.net>.
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

"""An asynchronous SSH2 library for Python"""

from .version import __author__, __author_email__, __url__, __version__

# pylint: disable=wildcard-import

from .constants import *

# pylint: enable=wildcard-import

from .agent import SSHAgentClient, SSHAgentKeyPair, connect_agent

from .auth_keys import SSHAuthorizedKeys
from .auth_keys import import_authorized_keys, read_authorized_keys

from .channel import SSHClientChannel, SSHServerChannel
from .channel import SSHTCPChannel, SSHUNIXChannel

from .client import SSHClient

from .connection import SSHClientConnection, SSHServerConnection
from .connection import create_connection, create_server, connect, listen

from .editor import SSHLineEditorChannel

from .known_hosts import SSHKnownHosts
from .known_hosts import import_known_hosts, read_known_hosts
from .known_hosts import match_known_hosts

from .listener import SSHListener

from .logging import logger

from .misc import Error, DisconnectError, ChannelOpenError
from .misc import PasswordChangeRequired
from .misc import BreakReceived, SignalReceived, TerminalSizeChanged

from .pbe import KeyEncryptionError

from .process import SSHClientProcess, SSHCompletedProcess, ProcessError
from .process import DEVNULL, PIPE, STDOUT

from .public_key import SSHKey, SSHKeyPair, SSHCertificate
from .public_key import KeyGenerationError, KeyImportError, KeyExportError
from .public_key import generate_private_key, import_private_key
from .public_key import import_public_key, import_certificate
from .public_key import read_private_key, read_public_key, read_certificate
from .public_key import read_private_key_list, read_public_key_list
from .public_key import read_certificate_list
from .public_key import load_keypairs, load_public_keys

from .session import SSHClientSession, SSHServerSession
from .session import SSHTCPSession, SSHUNIXSession

from .server import SSHServer

from .sftp import SFTPClient, SFTPServer, SFTPFile, SFTPError
from .sftp import SFTPAttrs, SFTPVFSAttrs, SFTPName
from .sftp import SEEK_SET, SEEK_CUR, SEEK_END

from .stream import SSHReader, SSHWriter

# Import these explicitly to trigger register calls in them
from . import ed25519, ecdsa, rsa, dsa, ecdh, dh
