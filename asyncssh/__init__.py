# Copyright (c) 2013-2026 by Ron Frederick <ronf@timeheart.net> and others.
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

"""An asynchronous SSH2 library for Python"""

# Import these explicitly to trigger register calls in them
from . import dsa, ecdsa, eddsa, kex_dh, kex_rsa, rsa, sk_ecdsa, sk_eddsa

# pylint: enable=wildcard-import
from .agent import SSHAgentClient, SSHAgentKeyPair, connect_agent
from .auth_keys import SSHAuthorizedKeys, import_authorized_keys, read_authorized_keys
from .channel import (
    SSHClientChannel,
    SSHServerChannel,
    SSHTCPChannel,
    SSHTunTapChannel,
    SSHUNIXChannel,
)
from .client import SSHClient
from .config import ConfigParseError
from .connection import (
    SSHAcceptHandler,
    SSHAcceptor,
    SSHClientConnection,
    SSHClientConnectionOptions,
    SSHServerConnection,
    SSHServerConnectionOptions,
    connect,
    connect_reverse,
    create_connection,
    create_server,
    get_server_auth_methods,
    get_server_host_key,
    listen,
    listen_reverse,
    run_client,
    run_server,
)

# pylint: disable=wildcard-import
from .constants import *
from .editor import SSHLineEditorChannel
from .forward import SSHForwarder
from .known_hosts import (
    SSHKnownHosts,
    import_known_hosts,
    match_known_hosts,
    read_known_hosts,
)
from .listener import SSHListener
from .logging import logger, set_debug_level, set_log_level, set_sftp_log_level
from .misc import (
    BreakReceived,
    BytesOrStr,
    ChannelListenError,
    ChannelOpenError,
    CompressionError,
    ConnectionLost,
    DisconnectError,
    Error,
    HostKeyNotVerifiable,
    IllegalUserName,
    KeyExchangeFailed,
    MACError,
    PasswordChangeRequired,
    PermissionDenied,
    ProtocolError,
    ProtocolNotSupported,
    ServiceNotAvailable,
    SignalReceived,
    TerminalSizeChanged,
)
from .pbe import KeyEncryptionError
from .pkcs11 import load_pkcs11_keys
from .process import (
    DEVNULL,
    PIPE,
    STDOUT,
    ProcessError,
    SSHClientProcess,
    SSHCompletedProcess,
    SSHServerProcess,
    SSHServerProcessFactory,
    TimeoutError,  # pylint: disable=redefined-builtin
)
from .public_key import (
    KeyExportError,
    KeyGenerationError,
    KeyImportError,
    SSHCertificate,
    SSHKey,
    SSHKeyPair,
    generate_private_key,
    import_certificate,
    import_private_key,
    import_public_key,
    load_certificates,
    load_keypairs,
    load_public_keys,
    load_resident_keys,
    read_certificate,
    read_certificate_list,
    read_private_key,
    read_private_key_list,
    read_public_key,
    read_public_key_list,
)
from .rsa import set_default_skip_rsa_key_validation
from .scp import scp
from .server import SSHServer
from .session import (
    DataType,
    SSHClientSession,
    SSHServerSession,
    SSHTCPSession,
    SSHTunTapSession,
    SSHUNIXSession,
)
from .sftp import (
    SEEK_CUR,
    SEEK_END,
    SEEK_SET,
    SFTPAttrs,
    SFTPBadMessage,
    SFTPByteRangeLockConflict,
    SFTPByteRangeLockRefused,
    SFTPCannotDelete,
    SFTPClient,
    SFTPClientFile,
    SFTPConnectionLost,
    SFTPDeletePending,
    SFTPDirNotEmpty,
    SFTPEOFError,
    SFTPError,
    SFTPFailure,
    SFTPFileAlreadyExists,
    SFTPFileCorrupt,
    SFTPFileIsADirectory,
    SFTPGroupInvalid,
    SFTPInvalidFilename,
    SFTPInvalidHandle,
    SFTPInvalidParameter,
    SFTPLimits,
    SFTPLinkLoop,
    SFTPLockConflict,
    SFTPName,
    SFTPNoConnection,
    SFTPNoMatchingByteRangeLock,
    SFTPNoMedia,
    SFTPNoSpaceOnFilesystem,
    SFTPNoSuchFile,
    SFTPNoSuchPath,
    SFTPNotADirectory,
    SFTPOpUnsupported,
    SFTPOwnerInvalid,
    SFTPPermissionDenied,
    SFTPQuotaExceeded,
    SFTPServer,
    SFTPUnknownPrincipal,
    SFTPVFSAttrs,
    SFTPWriteProtect,
)
from .sshsig import (
    SSHAllowedSigners,
    create_sshsig,
    import_allowed_signers,
    read_allowed_signers,
    validate_sshsig,
)
from .stream import (
    SFTPServerFactory,
    SSHReader,
    SSHServerSessionFactory,
    SSHSocketSessionFactory,
    SSHWriter,
)
from .subprocess import (
    SSHSubprocessProtocol,
    SSHSubprocessReadPipe,
    SSHSubprocessTransport,
    SSHSubprocessWritePipe,
)
from .version import __author__, __author_email__, __url__, __version__

__all__ = [
    '__author__', '__author_email__', '__url__', '__version__',
    'BreakReceived', 'BytesOrStr', 'ChannelListenError',
    'ChannelOpenError', 'CompressionError', 'ConfigParseError',
    'ConnectionLost', 'DEVNULL', 'DataType', 'DisconnectError', 'Error',
    'HostKeyNotVerifiable', 'IllegalUserName', 'KeyEncryptionError',
    'KeyExchangeFailed', 'KeyExportError', 'KeyGenerationError',
    'KeyImportError', 'MACError', 'PIPE', 'PasswordChangeRequired',
    'PermissionDenied', 'ProcessError', 'ProtocolError',
    'ProtocolNotSupported', 'SEEK_CUR', 'SEEK_END', 'SEEK_SET',
    'SFTPAttrs', 'SFTPBadMessage', 'SFTPByteRangeLockConflict',
    'SFTPByteRangeLockRefused', 'SFTPCannotDelete', 'SFTPClient',
    'SFTPClientFile', 'SFTPConnectionLost', 'SFTPDeletePending',
    'SFTPDirNotEmpty', 'SFTPEOFError', 'SFTPError', 'SFTPFailure',
    'SFTPFileAlreadyExists', 'SFTPFileCorrupt', 'SFTPFileIsADirectory',
    'SFTPGroupInvalid', 'SFTPInvalidFilename', 'SFTPInvalidHandle',
    'SFTPInvalidParameter', 'SFTPLimits', 'SFTPLinkLoop', 'SFTPLockConflict',
    'SFTPName', 'SFTPNoConnection', 'SFTPNoMatchingByteRangeLock',
    'SFTPNoMedia', 'SFTPNoSpaceOnFilesystem', 'SFTPNoSuchFile',
    'SFTPNoSuchPath', 'SFTPNotADirectory', 'SFTPOpUnsupported',
    'SFTPOwnerInvalid', 'SFTPPermissionDenied', 'SFTPQuotaExceeded',
    'SFTPServer', 'SFTPServerFactory', 'SFTPUnknownPrincipal', 'SFTPVFSAttrs',
    'SFTPWriteProtect', 'SSHAcceptHandler', 'SSHAcceptor', 'SSHAgentClient',
    'SSHAgentKeyPair', 'SSHAuthorizedKeys', 'SSHCertificate', 'SSHClient',
    'SSHClientChannel', 'SSHClientConnection', 'SSHClientConnectionOptions',
    'SSHClientProcess', 'SSHClientSession', 'SSHCompletedProcess',
    'SSHForwarder', 'SSHKey', 'SSHKeyPair', 'SSHKnownHosts',
    'SSHLineEditorChannel', 'SSHListener', 'SSHReader', 'SSHServer',
    'SSHServerChannel', 'SSHServerConnection',
    'SSHServerConnectionOptions', 'SSHServerProcess',
    'SSHServerProcessFactory', 'SSHServerSession',
    'SSHServerSessionFactory', 'SSHSocketSessionFactory',
    'SSHSubprocessProtocol', 'SSHSubprocessReadPipe',
    'SSHSubprocessTransport', 'SSHSubprocessWritePipe', 'SSHTCPChannel',
    'SSHTCPSession', 'SSHTunTapChannel', 'SSHTunTapSession',
    'SSHUNIXChannel', 'SSHUNIXSession', 'SSHWriter',
    'STDOUT', 'ServiceNotAvailable', 'SignalReceived', 'TerminalSizeChanged',
    'TimeoutError', 'connect', 'connect_agent', 'connect_reverse',
    'create_connection', 'create_server', 'create_sshsig',
    'generate_private_key', 'get_server_auth_methods', 'get_server_host_key',
    'import_authorized_keys', 'import_certificate', 'import_known_hosts',
    'import_private_key', 'import_public_key', 'listen', 'listen_reverse',
    'load_certificates', 'load_keypairs', 'load_pkcs11_keys',
    'load_public_keys', 'load_resident_keys', 'logger', 'match_known_hosts',
    'read_authorized_keys', 'read_certificate', 'read_certificate_list',
    'read_known_hosts', 'read_private_key', 'read_private_key_list',
    'read_public_key', 'read_public_key_list', 'run_client', 'run_server',
    'scp', 'set_debug_level', 'set_default_skip_rsa_key_validation',
    'set_log_level', 'set_sftp_log_level', 'validate_sshsig'
]
