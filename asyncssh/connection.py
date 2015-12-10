# Copyright (c) 2013-2015 by Ron Frederick <ronf@timeheart.net>.
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

"""SSH connection handlers"""

import asyncio
import getpass
import os
import socket
import sys
import time

from collections import OrderedDict

from .auth import lookup_client_auth
from .auth import get_server_auth_methods, lookup_server_auth

from .auth_keys import read_authorized_keys

from .channel import SSHClientChannel, SSHServerChannel, SSHTCPChannel

from .cipher import get_encryption_algs, get_encryption_params, get_cipher

from .compression import get_compression_algs, get_compression_params
from .compression import get_compressor, get_decompressor

from .constants import DEFAULT_LANG
from .constants import DISC_BY_APPLICATION, DISC_CONNECTION_LOST
from .constants import DISC_KEY_EXCHANGE_FAILED, DISC_HOST_KEY_NOT_VERIFYABLE
from .constants import DISC_MAC_ERROR, DISC_NO_MORE_AUTH_METHODS_AVAILABLE
from .constants import DISC_PROTOCOL_ERROR, DISC_SERVICE_NOT_AVAILABLE
from .constants import EXTENDED_DATA_STDERR
from .constants import MSG_DISCONNECT, MSG_IGNORE, MSG_UNIMPLEMENTED
from .constants import MSG_DEBUG, MSG_SERVICE_REQUEST, MSG_SERVICE_ACCEPT
from .constants import MSG_CHANNEL_OPEN, MSG_CHANNEL_OPEN_CONFIRMATION
from .constants import MSG_CHANNEL_OPEN_FAILURE, MSG_CHANNEL_WINDOW_ADJUST
from .constants import MSG_CHANNEL_DATA, MSG_CHANNEL_EXTENDED_DATA
from .constants import MSG_CHANNEL_EOF, MSG_CHANNEL_CLOSE, MSG_CHANNEL_REQUEST
from .constants import MSG_CHANNEL_SUCCESS, MSG_CHANNEL_FAILURE
from .constants import MSG_KEXINIT, MSG_NEWKEYS, MSG_KEX_FIRST, MSG_KEX_LAST
from .constants import MSG_USERAUTH_REQUEST, MSG_USERAUTH_FAILURE
from .constants import MSG_USERAUTH_SUCCESS, MSG_USERAUTH_BANNER
from .constants import MSG_USERAUTH_FIRST, MSG_USERAUTH_LAST
from .constants import MSG_GLOBAL_REQUEST, MSG_REQUEST_SUCCESS
from .constants import MSG_REQUEST_FAILURE
from .constants import OPEN_ADMINISTRATIVELY_PROHIBITED, OPEN_CONNECT_FAILED
from .constants import OPEN_UNKNOWN_CHANNEL_TYPE

from .forward import SSHPortForwarder, SSHLocalPortForwarder
from .forward import SSHRemotePortForwarder

from .kex import get_kex_algs, get_kex

from .known_hosts import match_known_hosts

from .listener import SSHClientListener, SSHForwardListener

from .logging import logger

from .mac import get_mac_algs, get_mac_params, get_mac

from .misc import ChannelOpenError, DisconnectError, PasswordChangeRequired
from .misc import ip_address

from .packet import Boolean, Byte, NameList, String, UInt32, UInt64
from .packet import PacketDecodeError, SSHPacket, SSHPacketHandler

from .public_key import CERT_TYPE_HOST, CERT_TYPE_USER
from .public_key import get_public_key_algs, get_certificate_algs
from .public_key import decode_ssh_public_key, decode_ssh_certificate
from .public_key import import_private_key, import_public_key
from .public_key import read_private_key, read_public_key
from .public_key import read_private_key_list, read_public_key_list
from .public_key import import_certificate, read_certificate
from .public_key import KeyImportError

from .saslprep import saslprep, SASLPrepError

from .sftp import SFTPClient, SFTPServer, SFTPClientSession

from .stream import SSHClientStreamSession, SSHServerStreamSession
from .stream import SSHTCPStreamSession, SSHReader, SSHWriter


# SSH default port
_DEFAULT_PORT = 22

# SSH service names
_USERAUTH_SERVICE = b'ssh-userauth'
_CONNECTION_SERVICE = b'ssh-connection'

# Default file names in .ssh directory to read private keys from
_DEFAULT_KEY_FILES = ('id_ed25519', 'id_ecdsa', 'id_rsa', 'id_dsa')

# Default rekey parameters
_DEFAULT_REKEY_BYTES = 1 << 30      # 1 GiB
_DEFAULT_REKEY_SECONDS = 3600       # 1 hour

# Default login timeout
_DEFAULT_LOGIN_TIMEOUT = 120        # 2 minutes

# Default channel parameters
_DEFAULT_WINDOW = 2*1024*1024       # 2 MiB
_DEFAULT_MAX_PKTSIZE = 32768        # 32 kiB


def _load_private_key(key, passphrase=None):
    """Load a private key

       This function loads a private key and an optional certificate.
       The key argument can be either a key reference or a tuple
       with a reference to a key and a reference to a matching
       certificate.

       Key references can either be the name of a file to load the
       key from, a byte string to import as a private key, or an
       already loaded :class:`SSHKey` private key.

       Certificate references can  be the name of a file to load the
       certificate from, a byte string to import as a certificate,
       an already loaded :class:`SSHCertificate`, or ``None`` if
       no certificate should be associated with the key.

       When a filename is provided in as a reference outside of a
       tuple, an attempt is made to load a private key from that
       file and a certificate from a file constructed by appending
       '-cert.pub' to the end of the filename.

       This function returns a tuple of a :class:`SSHKey` private
       key and either an :class:`SSHCertificate` or ``None``
       depending on whether an associated certificate was loaded.

    """

    if isinstance(key, str):
        cert = key + '-cert.pub'
        ignore_missing_cert = True
    elif isinstance(key, tuple):
        key, cert = key
        ignore_missing_cert = False
    else:
        cert = None

    if isinstance(key, str):
        key = read_private_key(key, passphrase)
    elif isinstance(key, bytes):
        key = import_private_key(key, passphrase)

    if isinstance(cert, str):
        try:
            cert = read_certificate(cert)
        except OSError:
            if ignore_missing_cert:
                cert = None
            else:
                raise
    elif isinstance(cert, bytes):
        cert = import_certificate(cert)

    if cert and key.get_ssh_public_key() != cert.key.get_ssh_public_key():
        raise ValueError('Certificate key mismatch')

    return key, cert


def _load_public_key(key):
    """Load a public key

       This function loads a public key. The key argument can be
       the name of a file to load the key from, a byte string to
       import the key from, or an already loaded :class:`SSHKey`
       public key.

    """

    if isinstance(key, str):
        key = read_public_key(key)
    elif isinstance(key, bytes):
        key = import_public_key(key)

    return key


def _load_private_key_list(keylist, passphrase=None):
    """Load list of private keys and optional associated certificates

       This function loads a collection of private keys, each with
       an optional certificate. The keylist argument can be either
       a filename to load private keys from (without any certificates)
       or a list of values representing keys and certificates as
       described in ::func::`_load_private_key`.

       This function returns a list of tuples of a :class:`SSHKey`
       private key and either an :class:`SSHCertificate` or
       ``None`` depending on whether an associated certificate
       was loaded.

    """

    if isinstance(keylist, str):
        keys = read_private_key_list(keylist, passphrase)
        return [(key, None) for key in keys]
    else:
        return [_load_private_key(key, passphrase) for key in keylist]

def _load_public_key_list(keylist):
    """Load public key list

       This function loads a collection of public keys. The keylist
       argument can be either a filename to load keys from or a
       list of values representing keys as described in
       :func:`_load_public_key`.

       It returns a list of loaded :class:`SSHKey` public keys.

    """

    if isinstance(keylist, str):
        return read_public_key_list(keylist)
    else:
        return [_load_public_key(key) for key in keylist]

def _load_authorized_keys(authorized_keys):
    """Load authorized keys list

       This function loads authorized client keys. The authorized_keys
       argument can be either a filename to load keys from or an
       already imported :class:`SSHAuthorizedKeys` object
       containing the authorized keys and their associated options.

    """

    if isinstance(authorized_keys, str):
        return read_authorized_keys(authorized_keys)
    else:
        return authorized_keys

def _select_algs(alg_type, algs, possible_algs, none_value=None):
    """Select a set of allowed algorithms"""

    if algs == ():
        return possible_algs
    elif algs:
        result = []

        for alg_str in algs:
            alg = alg_str.encode('ascii')
            if alg not in possible_algs:
                raise ValueError('%s is not a valid %s algorithm' %
                                 (alg_str, alg_type))

            result.append(alg)

        return result
    elif none_value:
        return [none_value]
    else:
        raise ValueError('No %s algorithms selected' % alg_type)


class SSHConnection(SSHPacketHandler):
    """Parent class for SSH connections"""

    def __init__(self, protocol_factory, loop, kex_algs, encryption_algs,
                 mac_algs, compression_algs, rekey_bytes, rekey_seconds,
                 server):
        self._protocol_factory = protocol_factory
        self._loop = loop
        self._transport = None
        self._peer_addr = None
        self._owner = None
        self._extra = {}
        self._server = server
        self._inpbuf = b''
        self._packet = b''
        self._pktlen = 0

        self._client_version = b''
        self._server_version = b''
        self._client_kexinit = b''
        self._server_kexinit = b''
        self._session_id = None

        self._send_seq = 0
        self._send_cipher = None
        self._send_blocksize = 8
        self._send_mac = None
        self._send_mode = None
        self._compressor = None
        self._compress_after_auth = False
        self._deferred_packets = []

        self._recv_handler = self._recv_version
        self._recv_seq = 0
        self._recv_cipher = None
        self._recv_blocksize = 8
        self._recv_mac = None
        self._recv_macsize = 0
        self._recv_mode = None
        self._decompressor = None
        self._decompress_after_auth = None
        self._next_recv_cipher = None
        self._next_recv_blocksize = 0
        self._next_recv_mac = None
        self._next_recv_macsize = 0
        self._next_recv_mode = None
        self._next_decompressor = None
        self._next_decompress_after_auth = None

        self._kex = None
        self._kexinit_sent = False
        self._kex_complete = False
        self._ignore_first_kex = False

        self._rekey_bytes = rekey_bytes
        self._rekey_bytes_sent = 0
        self._rekey_seconds = rekey_seconds
        self._rekey_time = time.time() + rekey_seconds

        self._enc_alg_cs = None
        self._enc_alg_sc = None

        self._mac_alg_cs = None
        self._mac_alg_sc = None

        self._cmp_alg_cs = None
        self._cmp_alg_sc = None

        self._next_service = None

        self._auth = None
        self._auth_in_progress = False
        self._auth_complete = False
        self._auth_methods = [b'none']
        self._auth_waiter = None
        self._username = None

        self._channels = {}
        self._next_recv_chan = 0

        self._global_request_queue = []
        self._global_request_waiters = []

        self._local_listeners = {}

        self._disconnected = False

        self._kex_algs = _select_algs('key exchange', kex_algs, get_kex_algs())
        self._enc_algs = _select_algs('encryption', encryption_algs,
                                      get_encryption_algs())
        self._mac_algs = _select_algs('MAC', mac_algs, get_mac_algs())
        self._cmp_algs = _select_algs('compression', compression_algs,
                                      get_compression_algs(), b'none')

        self._server_host_key_algs = []

    def __enter__(self):
        """Allow SSHConnection to be used as a context manager"""

        return self

    def __exit__(self, *exc_info):
        """Automatically close the connection when used as a context manager"""

        try:
            self.close()
        except RuntimeError as exc:
            # There's a race in some cases between the close call here
            # and the code which shuts down the event loop. Since the
            # loop.is_closed() method is only in Python 3.4.2 and later,
            # catch and ignore the RuntimeError for now if this happens.

            if exc.args[0] == 'Event loop is closed':
                pass
            else:
                raise

    def _cleanup(self, exc):
        """Clean up this connection"""

        if self._auth:
            self._auth.cancel()
            self._auth = None

        if self._channels:
            for chan in list(self._channels.values()):
                chan.process_connection_close(exc)
            self._channels = {}

        if self._local_listeners:
            for listener in self._local_listeners.values():
                listener.close()
            self._local_listeners = {}

        if self._owner:
            self._owner.connection_lost(exc)
            self._owner = None

        self._inpbuf = b''
        self._recv_handler = None

    def _force_close(self, exc):
        """Force this connection to close immediately"""

        if not self._transport:
            return

        self._transport.abort()
        self._transport = None

        self._loop.call_soon(self._cleanup, exc)

    def is_client(self):
        """Return if this is a client connection"""

        return not self._server

    def is_server(self):
        """Return if this is a server connection"""

        return self._server

    def get_owner(self):
        """Return the SSHClient or SSHServer which owns this connection"""

        return self._owner

    def get_hash_prefix(self):
        """Return the bytes used in calculating unique connection hashes

           This methods returns a packetized version of the client and
           server version and kexinit strings which is needed to perform
           key exchange hashes.

        """

        return b''.join((String(self._client_version),
                         String(self._server_version),
                         String(self._client_kexinit),
                         String(self._server_kexinit)))

    def connection_made(self, transport):
        """Handle a newly opened connection"""

        self._transport = transport

        peername = transport.get_extra_info('peername')
        self._peer_addr = peername[0] if peername else None

        self._owner = self._protocol_factory()
        self._protocol_factory = None

        try:
            self._connection_made()
            self._owner.connection_made(self)
            self._send_version()
        except DisconnectError as exc:
            self._loop.call_soon(self.connection_lost, exc)
        except: # pylint: disable=bare-except
            self._loop.call_soon(self.internal_error, sys.exc_info())

    def connection_lost(self, exc=None):
        """Handle the closing of a connection"""

        if exc is None and self._transport:
            exc = DisconnectError(DISC_CONNECTION_LOST, 'Connection lost')

        self._force_close(exc)

    def internal_error(self, exc_info=None):
        """Handle a fatal error in connection processing"""

        if not exc_info:
            exc_info = sys.exc_info()

        logger.debug('Uncaught exception', exc_info=exc_info)
        self.disconnect(DISC_BY_APPLICATION,
                        'Uncaught exception: %s' % str(exc_info[1]))
        self._loop.call_soon(self._cleanup, exc_info[1])

    def data_received(self, data):
        """Handle incoming data on the connection"""

        if data:
            self._inpbuf += data

            try:
                while self._inpbuf and self._recv_handler():
                    pass
            except DisconnectError as exc:
                self._force_close(exc)
            except: # pylint: disable=bare-except
                self.internal_error()

    def eof_received(self):
        """Handle an incoming end of file on the connection"""

        self.connection_lost(None)

    def pause_writing(self):
        """Handle a request from the transport to pause writing data"""

        # Do nothing with this for now
        pass

    def resume_writing(self):
        """Handle a request from the transport to resume writing data"""

        # Do nothing with this for now
        pass

    def add_channel(self, chan):
        """Add a new channel, returning its channel number"""

        while self._next_recv_chan in self._channels:
            self._next_recv_chan = (self._next_recv_chan + 1) & 0xffffffff

        recv_chan = self._next_recv_chan
        self._next_recv_chan = (self._next_recv_chan + 1) & 0xffffffff

        self._channels[recv_chan] = chan
        return recv_chan

    def remove_channel(self, recv_chan):
        """Remove the channel with the specified channel number"""

        del self._channels[recv_chan]

    def _choose_alg(self, alg_type, local_algs, remote_algs):
        """Choose a common algorithm from the client & server lists

           This method returns the earliest algorithm on the client's
           list which is supported by the server.

        """

        if self.is_client():
            client_algs, server_algs = local_algs, remote_algs
        else:
            client_algs, server_algs = remote_algs, local_algs

        for alg in client_algs:
            if alg in server_algs:
                return alg

        raise DisconnectError(DISC_KEY_EXCHANGE_FAILED,
                              'No matching %s algorithm found' % alg_type)

    def _send(self, data):
        """Send data to the SSH connection"""

        if self._transport:
            self._transport.write(data)

    def _send_version(self):
        """Start the SSH handshake"""

        from .version import __version__

        version = b'SSH-2.0-AsyncSSH_' + __version__.encode('ascii')

        if self.is_client():
            self._client_version = version
            self._extra.update(client_version=version.decode('ascii'))
        else:
            self._server_version = version
            self._extra.update(server_version=version.decode('ascii'))

        self._send(version + b'\r\n')

    def _recv_version(self):
        """Receive and parse the remote SSH version"""

        idx = self._inpbuf.find(b'\n')
        if idx < 0:
            return False

        version = self._inpbuf[:idx]
        if version.endswith(b'\r'):
            version = version[:-1]

        self._inpbuf = self._inpbuf[idx+1:]

        if (version.startswith(b'SSH-2.0-') or
                (self.is_client() and version.startswith(b'SSH-1.99-'))):
            # Accept version 2.0, or 1.99 if we're a client
            if self.is_server():
                self._client_version = version
                self._extra.update(client_version=version.decode('ascii'))
            else:
                self._server_version = version
                self._extra.update(server_version=version.decode('ascii'))

            self._send_kexinit()
            self._kexinit_sent = True
            self._recv_handler = self._recv_pkthdr
        elif self.is_client() and not version.startswith(b'SSH-'):
            # As a client, ignore the line if it doesn't appear to be a version
            pass
        else:
            # Otherwise, reject the unknown version
            self._force_close(DisconnectError(DISC_PROTOCOL_ERROR,
                                              'Unknown SSH version'))
            return False

        return True

    def _recv_pkthdr(self):
        """Receive and parse an SSH packet header"""

        if len(self._inpbuf) < self._recv_blocksize:
            return False

        self._packet = self._inpbuf[:self._recv_blocksize]
        self._inpbuf = self._inpbuf[self._recv_blocksize:]

        pktlen = self._packet[:4]

        if self._recv_cipher:
            if self._recv_mode == 'chacha':
                nonce = UInt64(self._recv_seq)
                pktlen = self._recv_cipher.crypt_len(pktlen, nonce)
            elif self._recv_mode not in ('gcm', 'etm'):
                self._packet = self._recv_cipher.decrypt(self._packet)
                pktlen = self._packet[:4]

        self._pktlen = int.from_bytes(pktlen, 'big')
        self._recv_handler = self._recv_packet
        return True

    def _recv_packet(self):
        """Receive the remainder of an SSH packet and process it"""

        rem = 4 + self._pktlen + self._recv_macsize - self._recv_blocksize
        if len(self._inpbuf) < rem:
            return False

        rest = self._inpbuf[:rem-self._recv_macsize]

        if self._recv_mode in ('chacha', 'gcm'):
            self._packet += rest
            mac = self._inpbuf[rem-self._recv_macsize:rem]

            hdr = self._packet[:4]
            self._packet = self._packet[4:]

            if self._recv_mode == 'chacha':
                nonce = UInt64(self._recv_seq)
                self._packet = \
                    self._recv_cipher.verify_and_decrypt(hdr, self._packet,
                                                         nonce, mac)
            else:
                self._packet = \
                    self._recv_cipher.verify_and_decrypt(hdr, self._packet,
                                                         mac)

            if not self._packet:
                raise DisconnectError(DISC_MAC_ERROR,
                                      'MAC verification failed')

            payload = self._packet[1:-self._packet[0]]
        elif self._recv_mode == 'etm':
            self._packet += rest
            mac = self._inpbuf[rem-self._recv_macsize:rem]

            if self._recv_mac:
                if not self._recv_mac.verify(UInt32(self._recv_seq) +
                                             self._packet, mac):
                    raise DisconnectError(DISC_MAC_ERROR,
                                          'MAC verification failed')

            self._packet = self._packet[4:]

            if self._recv_cipher:
                self._packet = self._recv_cipher.decrypt(self._packet)

            payload = self._packet[1:-self._packet[0]]
        else:
            if self._recv_cipher:
                rest = self._recv_cipher.decrypt(rest)

            self._packet += rest
            mac = self._inpbuf[rem-self._recv_macsize:rem]

            if self._recv_mac:
                if not self._recv_mac.verify(UInt32(self._recv_seq) +
                                             self._packet, mac):
                    raise DisconnectError(DISC_MAC_ERROR,
                                          'MAC verification failed')

            payload = self._packet[5:-self._packet[4]]

        self._inpbuf = self._inpbuf[rem:]

        if self._decompressor and (self._auth_complete or
                                   not self._decompress_after_auth):
            payload = self._decompressor.decompress(payload)

        try:
            packet = SSHPacket(payload)
            pkttype = packet.get_byte()

            if self._kex and MSG_KEX_FIRST <= pkttype <= MSG_KEX_LAST:
                if self._ignore_first_kex:
                    self._ignore_first_kex = False
                    processed = True
                else:
                    processed = self._kex.process_packet(pkttype, packet)
            elif (self._auth and
                  MSG_USERAUTH_FIRST <= pkttype <= MSG_USERAUTH_LAST):
                processed = self._auth.process_packet(pkttype, packet)
            else:
                processed = self.process_packet(pkttype, packet)
        except PacketDecodeError as exc:
            raise DisconnectError(DISC_PROTOCOL_ERROR, str(exc))

        if not processed:
            self.send_packet(Byte(MSG_UNIMPLEMENTED), UInt32(self._recv_seq))

        if self._transport:
            self._recv_seq = (self._recv_seq + 1) & 0xffffffff
            self._recv_handler = self._recv_pkthdr

        return True

    def send_packet(self, *args):
        """Send an SSH packet"""

        payload = b''.join(args)
        pkttype = payload[0]

        if (self._auth_complete and self._kex_complete and
                (self._rekey_bytes_sent >= self._rekey_bytes or
                 time.monotonic() >= self._rekey_time)):
            self._send_kexinit()
            self._kexinit_sent = True

        if (((pkttype in {MSG_SERVICE_REQUEST, MSG_SERVICE_ACCEPT} or
              pkttype > MSG_KEX_LAST) and not self._kex_complete) or
                (pkttype == MSG_USERAUTH_BANNER and
                 not self._auth_in_progress) or
                (pkttype > MSG_USERAUTH_LAST and not self._auth_complete)):
            self._deferred_packets.append(payload)
            return

        # If we're encrypting and we have no data outstanding, insert an
        # ignore packet into the stream
        if self._send_cipher and payload[0] != MSG_IGNORE:
            self.send_packet(Byte(MSG_IGNORE), String(b''))

        if self._compressor and (self._auth_complete or
                                 not self._compress_after_auth):
            payload = self._compressor.compress(payload)

        hdrlen = 1 if self._send_mode in ('chacha', 'gcm', 'etm') else 5

        padlen = -(hdrlen + len(payload)) % self._send_blocksize
        if padlen < 4:
            padlen += self._send_blocksize

        packet = Byte(padlen) + payload + os.urandom(padlen)
        pktlen = len(packet)
        hdr = UInt32(pktlen)

        if self._send_mode == 'chacha':
            nonce = UInt64(self._send_seq)
            hdr = self._send_cipher.crypt_len(hdr, nonce)
            packet, mac = self._send_cipher.encrypt_and_sign(hdr, packet,
                                                             nonce)
            packet = hdr + packet
        elif self._send_mode == 'gcm':
            packet, mac = self._send_cipher.encrypt_and_sign(hdr, packet)
            packet = hdr + packet
        elif self._send_mode == 'etm':
            if self._send_cipher:
                packet = self._send_cipher.encrypt(packet)

            packet = hdr + packet

            if self._send_mac:
                mac = self._send_mac.sign(UInt32(self._send_seq) + packet)
            else:
                mac = b''
        else:
            packet = hdr + packet

            if self._send_mac:
                mac = self._send_mac.sign(UInt32(self._send_seq) + packet)
            else:
                mac = b''

            if self._send_cipher:
                packet = self._send_cipher.encrypt(packet)

        self._send(packet + mac)
        self._send_seq = (self._send_seq + 1) & 0xffffffff

        if self._kex_complete:
            self._rekey_bytes_sent += pktlen

    def _send_deferred_packets(self):
        """Send packets deferred due to key exchange or auth"""

        deferred_packets = self._deferred_packets
        self._deferred_packets = []

        for packet in deferred_packets:
            self.send_packet(packet)

    def _send_kexinit(self):
        """Start a key exchange"""

        self._kex_complete = False
        self._rekey_bytes_sent = 0
        self._rekey_time = time.monotonic() + self._rekey_seconds

        cookie = os.urandom(16)
        kex_algs = NameList(self._kex_algs)
        host_key_algs = NameList(self._server_host_key_algs)
        enc_algs = NameList(self._enc_algs)
        mac_algs = NameList(self._mac_algs)
        cmp_algs = NameList(self._cmp_algs)
        langs = NameList([])

        packet = b''.join((Byte(MSG_KEXINIT), cookie, kex_algs, host_key_algs,
                           enc_algs, enc_algs, mac_algs, mac_algs, cmp_algs,
                           cmp_algs, langs, langs, Boolean(False), UInt32(0)))

        if self.is_server():
            self._server_kexinit = packet
        else:
            self._client_kexinit = packet

        self.send_packet(packet)

    def send_newkeys(self, k, h):
        """Finish a key exchange and send a new keys message"""

        if not self._session_id:
            self._session_id = h

        enc_keysize_cs, enc_ivsize_cs, enc_blocksize_cs, mode_cs = \
            get_encryption_params(self._enc_alg_cs)
        enc_keysize_sc, enc_ivsize_sc, enc_blocksize_sc, mode_sc = \
            get_encryption_params(self._enc_alg_sc)

        if mode_cs in ('chacha', 'gcm'):
            mac_keysize_cs, mac_hashsize_cs = 0, 16
        else:
            mac_keysize_cs, mac_hashsize_cs, etm_cs = \
                get_mac_params(self._mac_alg_cs)
            if etm_cs:
                mode_cs = 'etm'

        if mode_sc in ('chacha', 'gcm'):
            mac_keysize_sc, mac_hashsize_sc = 0, 16
        else:
            mac_keysize_sc, mac_hashsize_sc, etm_sc = \
                get_mac_params(self._mac_alg_sc)
            if etm_sc:
                mode_sc = 'etm'

        cmp_after_auth_cs = get_compression_params(self._cmp_alg_cs)
        cmp_after_auth_sc = get_compression_params(self._cmp_alg_sc)

        iv_cs = self._kex.compute_key(k, h, b'A', self._session_id,
                                      enc_ivsize_cs)
        iv_sc = self._kex.compute_key(k, h, b'B', self._session_id,
                                      enc_ivsize_sc)
        enc_key_cs = self._kex.compute_key(k, h, b'C', self._session_id,
                                           enc_keysize_cs)
        enc_key_sc = self._kex.compute_key(k, h, b'D', self._session_id,
                                           enc_keysize_sc)
        mac_key_cs = self._kex.compute_key(k, h, b'E', self._session_id,
                                           mac_keysize_cs)
        mac_key_sc = self._kex.compute_key(k, h, b'F', self._session_id,
                                           mac_keysize_sc)
        self._kex = None

        next_cipher_cs = get_cipher(self._enc_alg_cs, enc_key_cs, iv_cs)
        next_cipher_sc = get_cipher(self._enc_alg_sc, enc_key_sc, iv_sc)

        if mode_cs in ('chacha', 'gcm'):
            self._mac_alg_cs = self._enc_alg_cs
            next_mac_cs = None
        else:
            next_mac_cs = get_mac(self._mac_alg_cs, mac_key_cs)

        if mode_sc in ('chacha', 'gcm'):
            self._mac_alg_sc = self._enc_alg_sc
            next_mac_sc = None
        else:
            next_mac_sc = get_mac(self._mac_alg_sc, mac_key_sc)

        self.send_packet(Byte(MSG_NEWKEYS))

        if self.is_client():
            self._send_cipher = next_cipher_cs
            self._send_blocksize = max(8, enc_blocksize_cs)
            self._send_mac = next_mac_cs
            self._send_mode = mode_cs
            self._compressor = get_compressor(self._cmp_alg_cs)
            self._compress_after_auth = cmp_after_auth_cs

            self._next_recv_cipher = next_cipher_sc
            self._next_recv_blocksize = max(8, enc_blocksize_sc)
            self._next_recv_mac = next_mac_sc
            self._next_recv_macsize = mac_hashsize_sc
            self._next_recv_mode = mode_sc
            self._next_decompressor = get_decompressor(self._cmp_alg_sc)
            self._next_decompress_after_auth = cmp_after_auth_sc

            self._extra.update(
                send_cipher=self._enc_alg_cs.decode('ascii'),
                send_mac=self._mac_alg_cs.decode('ascii'),
                send_compression=self._cmp_alg_cs.decode('ascii'),
                recv_cipher=self._enc_alg_sc.decode('ascii'),
                recv_mac=self._mac_alg_sc.decode('ascii'),
                recv_compression=self._cmp_alg_sc.decode('ascii'))
        else:
            self._send_cipher = next_cipher_sc
            self._send_blocksize = max(8, enc_blocksize_sc)
            self._send_mac = next_mac_sc
            self._send_mode = mode_sc
            self._compressor = get_compressor(self._cmp_alg_sc)
            self._compress_after_auth = cmp_after_auth_sc

            self._next_recv_cipher = next_cipher_cs
            self._next_recv_blocksize = max(8, enc_blocksize_cs)
            self._next_recv_mac = next_mac_cs
            self._next_recv_macsize = mac_hashsize_cs
            self._next_recv_mode = mode_cs
            self._next_decompressor = get_decompressor(self._cmp_alg_cs)
            self._next_decompress_after_auth = cmp_after_auth_cs

            self._extra.update(
                send_cipher=self._enc_alg_sc.decode('ascii'),
                send_mac=self._mac_alg_sc.decode('ascii'),
                send_compression=self._cmp_alg_sc.decode('ascii'),
                recv_cipher=self._enc_alg_cs.decode('ascii'),
                recv_mac=self._mac_alg_cs.decode('ascii'),
                recv_compression=self._cmp_alg_cs.decode('ascii'))

            self._next_service = _USERAUTH_SERVICE

        self._kex_complete = True
        self._send_deferred_packets()

    def send_service_request(self, service):
        """Send a service request"""

        self._next_service = service
        self.send_packet(Byte(MSG_SERVICE_REQUEST), String(service))

    def send_userauth_request(self, method, *args, key=None):
        """Send a user authentication request"""

        packet = b''.join((Byte(MSG_USERAUTH_REQUEST), String(self._username),
                           String(_CONNECTION_SERVICE), String(method)) + args)

        if key:
            packet += String(key.sign(String(self._session_id) + packet))

        self.send_packet(packet)

    def send_userauth_failure(self, partial_success):
        """Send a user authentication failure response"""

        self._auth = None
        self.send_packet(Byte(MSG_USERAUTH_FAILURE),
                         NameList(get_server_auth_methods(self)),
                         Boolean(partial_success))

    def send_userauth_success(self):
        """Send a user authentication success response"""

        self.send_packet(Byte(MSG_USERAUTH_SUCCESS))
        self._auth = None
        self._auth_in_progress = False
        self._auth_complete = True
        self._extra.update(username=self._username)
        self._send_deferred_packets()

        # This method is only in SSHServerConnection
        # pylint: disable=no-member
        self._cancel_login_timer()

    def send_channel_open_confirmation(self, send_chan, recv_chan,
                                       recv_window, recv_pktsize,
                                       *result_args):
        """Send a channel open confirmation"""

        self.send_packet(Byte(MSG_CHANNEL_OPEN_CONFIRMATION),
                         UInt32(send_chan), UInt32(recv_chan),
                         UInt32(recv_window), UInt32(recv_pktsize),
                         *result_args)

    def send_channel_open_failure(self, send_chan, code, reason, lang):
        """Send a channel open failure"""

        reason = reason.encode('utf-8')
        lang = lang.encode('ascii')

        self.send_packet(Byte(MSG_CHANNEL_OPEN_FAILURE), UInt32(send_chan),
                         UInt32(code), String(reason), String(lang))

    @asyncio.coroutine
    def _make_global_request(self, request, *args):
        """Send a global request and wait for the response"""

        waiter = asyncio.Future(loop=self._loop)
        self._global_request_waiters.append(waiter)

        self.send_packet(Byte(MSG_GLOBAL_REQUEST), String(request),
                         Boolean(True), *args)

        return (yield from waiter)

    def _report_global_response(self, result):
        """Report back the response to a previously issued global request"""

        _, _, want_reply = self._global_request_queue.pop(0)

        if want_reply:
            if result:
                response = b'' if result is True else result
                self.send_packet(Byte(MSG_REQUEST_SUCCESS), response)
            else:
                self.send_packet(Byte(MSG_REQUEST_FAILURE))

        if self._global_request_queue:
            self._service_next_global_request()

    def _service_next_global_request(self):
        """Process next item on global request queue"""

        handler, packet, _ = self._global_request_queue[0]
        if callable(handler):
            handler(packet)
        else:
            self._report_global_response(False)

    @asyncio.coroutine
    def _create_tcp_listener(self, listen_host, listen_port):
        """Create a listener for TCP/IP port forwarding"""

        if listen_host == '':
            listen_host = None

        addrinfo = yield from self._loop.getaddrinfo(listen_host, listen_port,
                                                     family=socket.AF_UNSPEC,
                                                     type=socket.SOCK_STREAM,
                                                     flags=socket.AI_PASSIVE)

        if not addrinfo:
            raise OSError('getaddrinfo() returned empty list')

        sockets = []

        for family, socktype, proto, _, sa in addrinfo:
            try:
                sock = socket.socket(family, socktype, proto)
            except OSError:
                continue

            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)

            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, True)

            if sa[1] == 0:
                sa = sa[:1] + (listen_port,) + sa[2:]

            try:
                sock.bind(sa)
            except OSError as exc:
                for sock in sockets:
                    sock.close()

                raise OSError(exc.errno, 'error while attempting to bind on '
                              'address %r: %s' % (sa, exc.strerror)) from None

            if listen_port == 0:
                listen_port = sock.getsockname()[1]

            sockets.append(sock)

        return listen_port, sockets

    @asyncio.coroutine
    def _create_forward_listener(self, listen_port, sockets, factory):
        """Create an SSHForwardListener for a set of listening sockets"""

        servers = []

        for sock in sockets:
            server = yield from self._loop.create_server(factory, sock=sock)
            servers.append(server)

        return SSHForwardListener(listen_port, servers)

    def _connection_made(self):
        """Handle the opening of a new connection"""

        raise NotImplementedError

    def _process_disconnect(self, pkttype, packet):
        """Process a disconnect message"""

        # pylint: disable=unused-argument

        code = packet.get_uint32()
        reason = packet.get_string()
        lang = packet.get_string()
        packet.check_end()

        try:
            reason = reason.decode('utf-8')
            lang = lang.decode('ascii')
        except UnicodeDecodeError:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Invalid disconnect message') from None

        if code != DISC_BY_APPLICATION:
            exc = DisconnectError(code, reason, lang)
        else:
            exc = None

        self._force_close(exc)

    def _process_ignore(self, pkttype, packet):
        """Process an ignore message"""

        # pylint: disable=no-self-use,unused-argument

        _ = packet.get_string()     # data
        packet.check_end()

        # Do nothing

    def _process_unimplemented(self, pkttype, packet):
        """Process an unimplemented message response"""

        # pylint: disable=no-self-use,unused-argument

        _ = packet.get_uint32()     # seq
        packet.check_end()

        # Ignore this

    def _process_debug(self, pkttype, packet):
        """Process a debug message"""

        # pylint: disable=unused-argument

        always_display = packet.get_boolean()
        msg = packet.get_string()
        lang = packet.get_string()
        packet.check_end()

        try:
            msg = msg.decode('utf-8')
            lang = lang.decode('ascii')
        except UnicodeDecodeError:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Invalid debug message') from None

        self._owner.debug_msg_received(msg, lang, always_display)

    def _process_service_request(self, pkttype, packet):
        """Process a service request"""

        # pylint: disable=unused-argument

        service = packet.get_string()
        packet.check_end()

        if service == self._next_service:
            self._next_service = None
            self.send_packet(Byte(MSG_SERVICE_ACCEPT), String(service))

            if self.is_server() and service == _USERAUTH_SERVICE:
                self._auth_in_progress = True
                self._send_deferred_packets()
        else:
            raise DisconnectError(DISC_SERVICE_NOT_AVAILABLE,
                                  'Unexpected service request received')

    def _process_service_accept(self, pkttype, packet):
        """Process a service accept response"""

        # pylint: disable=unused-argument

        service = packet.get_string()
        packet.check_end()

        if service == self._next_service:
            self._next_service = None

            if self.is_client() and service == _USERAUTH_SERVICE:
                self._auth_in_progress = True

                # This method is only in SSHClientConnection
                # pylint: disable=no-member
                self.try_next_auth()
        else:
            raise DisconnectError(DISC_SERVICE_NOT_AVAILABLE,
                                  'Unexpected service accept received')

    def _process_kexinit(self, pkttype, packet):
        """Process a key exchange request"""

        # pylint: disable=unused-argument

        if self._kex:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Key exchange already in progress')

        _ = packet.get_bytes(16)                        # cookie
        kex_algs = packet.get_namelist()
        server_host_key_algs = packet.get_namelist()
        enc_algs_cs = packet.get_namelist()
        enc_algs_sc = packet.get_namelist()
        mac_algs_cs = packet.get_namelist()
        mac_algs_sc = packet.get_namelist()
        cmp_algs_cs = packet.get_namelist()
        cmp_algs_sc = packet.get_namelist()
        _ = packet.get_namelist()                       # lang_cs
        _ = packet.get_namelist()                       # lang_sc
        first_kex_follows = packet.get_boolean()
        _ = packet.get_uint32()                         # reserved
        packet.check_end()

        if self.is_server():
            self._client_kexinit = packet.get_consumed_payload()

            # This method is only in SSHServerConnection
            # pylint: disable=no-member
            if not self._choose_server_host_key(server_host_key_algs):
                raise DisconnectError(DISC_KEY_EXCHANGE_FAILED, 'Unable to '
                                      'find compatible server host key')
        else:
            self._server_kexinit = packet.get_consumed_payload()

        if self._kexinit_sent:
            self._kexinit_sent = False
        else:
            self._send_kexinit()

        kex_alg = self._choose_alg('key exchange', self._kex_algs, kex_algs)
        self._kex = get_kex(self, kex_alg)
        self._ignore_first_kex = (first_kex_follows and
                                  self._kex.algorithm != kex_algs[0])

        self._enc_alg_cs = self._choose_alg('encryption', self._enc_algs,
                                            enc_algs_cs)
        self._enc_alg_sc = self._choose_alg('encryption', self._enc_algs,
                                            enc_algs_sc)

        self._mac_alg_cs = self._choose_alg('MAC', self._mac_algs, mac_algs_cs)
        self._mac_alg_sc = self._choose_alg('MAC', self._mac_algs, mac_algs_sc)

        self._cmp_alg_cs = self._choose_alg('compression', self._cmp_algs,
                                            cmp_algs_cs)
        self._cmp_alg_sc = self._choose_alg('compression', self._cmp_algs,
                                            cmp_algs_sc)

    def _process_newkeys(self, pkttype, packet):
        """Process a new keys message, finishing a key exchange"""

        # pylint: disable=unused-argument

        packet.check_end()

        if self._next_recv_cipher:
            self._recv_cipher = self._next_recv_cipher
            self._recv_blocksize = self._next_recv_blocksize
            self._recv_mac = self._next_recv_mac
            self._recv_mode = self._next_recv_mode
            self._recv_macsize = self._next_recv_macsize
            self._decompressor = self._next_decompressor
            self._decompress_after_auth = self._next_decompress_after_auth

            self._next_recv_cipher = None
        else:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'New keys not negotiated')

        if self.is_client() and not (self._auth_in_progress or
                                     self._auth_complete):
            self.send_service_request(_USERAUTH_SERVICE)

    def _process_userauth_request(self, pkttype, packet):
        """Process a user authentication request"""

        # pylint: disable=unused-argument

        username = packet.get_string()
        service = packet.get_string()
        method = packet.get_string()

        if service != _CONNECTION_SERVICE:
            raise DisconnectError(DISC_SERVICE_NOT_AVAILABLE,
                                  'Unexpected service in auth request')

        try:
            username = saslprep(username.decode('utf-8'))
        except (UnicodeDecodeError, SASLPrepError):
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Invalid auth request message') from None

        if self.is_client():
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Unexpected userauth request')
        elif self._auth_complete:
            # Silent ignore requests if we're already authenticated
            pass
        else:
            if username != self._username:
                self._username = username

                if not self._owner.begin_auth(username):
                    self.send_userauth_success()
                    return

            if self._auth:
                self._auth.cancel()

            self._auth = lookup_server_auth(self, self._username,
                                            method, packet)

    def _process_userauth_failure(self, pkttype, packet):
        """Process a user authentication failure response"""

        # pylint: disable=unused-argument

        self._auth_methods = packet.get_namelist()
        partial_success = packet.get_boolean()
        packet.check_end()

        if self.is_client() and self._auth:
            if partial_success: # pragma: no cover
                # Partial success not implemented yet
                self._auth.auth_succeeded()
            else:
                self._auth.auth_failed()

            # This method is only in SSHClientConnection
            # pylint: disable=no-member
            self.try_next_auth()
        else:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Unexpected userauth response')

    def _process_userauth_success(self, pkttype, packet):
        """Process a user authentication success response"""

        # pylint: disable=unused-argument

        packet.check_end()

        if self.is_client() and self._auth:
            self._auth.auth_succeeded()
            self._auth.cancel()
            self._auth = None
            self._auth_in_progress = False
            self._auth_complete = True
            self._extra.update(username=self._username)
            self._send_deferred_packets()

            self._owner.auth_completed()

            if self._auth_waiter:
                if not self._auth_waiter.cancelled():
                    self._auth_waiter.set_result(None)

                self._auth_waiter = None
        else:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Unexpected userauth response')

    def _process_userauth_banner(self, pkttype, packet):
        """Process a user authentication banner message"""

        # pylint: disable=unused-argument

        msg = packet.get_string()
        lang = packet.get_string()
        packet.check_end()

        try:
            msg = msg.decode('utf-8')
            lang = lang.decode('ascii')
        except UnicodeDecodeError:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Invalid userauth banner') from None

        if self.is_client():
            self._owner.auth_banner_received(msg, lang)
        else:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Unexpected userauth banner')

    def _process_global_request(self, pkttype, packet):
        """Process a global request"""

        # pylint: disable=unused-argument

        request = packet.get_string()
        want_reply = packet.get_boolean()

        try:
            request = request.decode('ascii')
        except UnicodeDecodeError:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Invalid global request') from None

        name = '_process_' + request.replace('-', '_') + '_global_request'
        handler = getattr(self, name, None)

        self._global_request_queue.append((handler, packet, want_reply))
        if len(self._global_request_queue) == 1:
            self._service_next_global_request()

    def _process_global_response(self, pkttype, packet):
        """Process a global response"""

        # pylint: disable=unused-argument

        if self._global_request_waiters:
            waiter = self._global_request_waiters.pop(0)
            if not waiter.cancelled():
                waiter.set_result((pkttype, packet))
        else:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Unexpected global response')

    def _process_channel_open(self, pkttype, packet):
        """Process a channel open request"""

        # pylint: disable=unused-argument

        chantype = packet.get_string()
        send_chan = packet.get_uint32()
        send_window = packet.get_uint32()
        send_pktsize = packet.get_uint32()

        try:
            chantype = chantype.decode('ascii')
        except UnicodeDecodeError:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Invalid channel open request') from None

        try:
            name = '_process_' + chantype.replace('-', '_') + '_open'
            handler = getattr(self, name, None)
            if callable(handler):
                chan, session = handler(packet)
                chan.process_open(send_chan, send_window,
                                  send_pktsize, session)
            else:
                raise ChannelOpenError(OPEN_UNKNOWN_CHANNEL_TYPE,
                                       'Unknown channel type')
        except ChannelOpenError as exc:
            self.send_channel_open_failure(send_chan, exc.code,
                                           exc.reason, exc.lang)

    def _process_channel_open_confirmation(self, pkttype, packet):
        """Process a channel open confirmation response"""

        # pylint: disable=unused-argument

        recv_chan = packet.get_uint32()
        send_chan = packet.get_uint32()
        send_window = packet.get_uint32()
        send_pktsize = packet.get_uint32()

        chan = self._channels.get(recv_chan)
        if chan:
            chan.process_open_confirmation(send_chan, send_window,
                                           send_pktsize, packet)
        else:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Invalid channel number')

    def _process_channel_open_failure(self, pkttype, packet):
        """Process a channel open failure response"""

        # pylint: disable=unused-argument

        recv_chan = packet.get_uint32()
        code = packet.get_uint32()
        reason = packet.get_string()
        lang = packet.get_string()
        packet.check_end()

        try:
            reason = reason.decode('utf-8')
            lang = lang.decode('ascii')
        except UnicodeDecodeError:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Invalid channel open failure') from None

        chan = self._channels.get(recv_chan)
        if chan:
            chan.process_open_failure(code, reason, lang)
        else:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Invalid channel number')

    def _process_channel_msg(self, pkttype, packet):
        """Process a channel-specific message"""

        recv_chan = packet.get_uint32()

        chan = self._channels.get(recv_chan)
        if chan:
            chan.process_packet(pkttype, packet)
        else:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Invalid channel number')

    packet_handlers = {
        MSG_DISCONNECT:                 _process_disconnect,
        MSG_IGNORE:                     _process_ignore,
        MSG_UNIMPLEMENTED:              _process_unimplemented,
        MSG_DEBUG:                      _process_debug,
        MSG_SERVICE_REQUEST:            _process_service_request,
        MSG_SERVICE_ACCEPT:             _process_service_accept,

        MSG_KEXINIT:                    _process_kexinit,
        MSG_NEWKEYS:                    _process_newkeys,

        MSG_USERAUTH_REQUEST:           _process_userauth_request,
        MSG_USERAUTH_FAILURE:           _process_userauth_failure,
        MSG_USERAUTH_SUCCESS:           _process_userauth_success,
        MSG_USERAUTH_BANNER:            _process_userauth_banner,

        MSG_GLOBAL_REQUEST:             _process_global_request,
        MSG_REQUEST_SUCCESS:            _process_global_response,
        MSG_REQUEST_FAILURE:            _process_global_response,

        MSG_CHANNEL_OPEN:               _process_channel_open,
        MSG_CHANNEL_OPEN_CONFIRMATION:  _process_channel_open_confirmation,
        MSG_CHANNEL_OPEN_FAILURE:       _process_channel_open_failure,
        MSG_CHANNEL_WINDOW_ADJUST:      _process_channel_msg,
        MSG_CHANNEL_DATA:               _process_channel_msg,
        MSG_CHANNEL_EXTENDED_DATA:      _process_channel_msg,
        MSG_CHANNEL_EOF:                _process_channel_msg,
        MSG_CHANNEL_CLOSE:              _process_channel_msg,
        MSG_CHANNEL_REQUEST:            _process_channel_msg,
        MSG_CHANNEL_SUCCESS:            _process_channel_msg,
        MSG_CHANNEL_FAILURE:            _process_channel_msg
    }

    def abort(self):
        """Forcibly close the SSH connection

           This method closes the SSH connection immediately, without
           waiting for pending operations to complete and wihtout sending
           an explicit SSH disconnect message. Buffered data waiting to be
           sent will be lost and no more data will be received. When the
           the connection is closed, :meth:`connection_lost()
           <SSHClient.connection_lost>` on the associated :class:`SSHClient`
           object will be called with the value ``None``.

        """

        self._force_close(None)

    def close(self):
        """Cleanly close the SSH connection

           This method calls :meth:`disconnect` with the reason set to
           indicate that the connection was closed explicitly by the
           application.

        """

        self.disconnect(DISC_BY_APPLICATION, 'Disconnected by application')

    def disconnect(self, code, reason, lang=DEFAULT_LANG):
        """Disconnect the SSH connection

           This method sends a disconnect message and closes the SSH
           connection after buffered data waiting to be written has been
           sent. No more data will be received. When the connection is
           fully closed, :meth:`connection_lost() <SSHClient.connection_lost>`
           on the associated :class:`SSHClient` or :class:`SSHServer` object
           will be called with the value ``None``.

           :param integer code:
               The reason for the disconnect, from
               :ref:`disconnect reason codes <DisconnectReasons>`
           :param string reason:
               A human readable reason for the disconnect
           :param string lang:
               The language the reason is in

        """

        if not self._transport:
            return

        for chan in list(self._channels.values()):
            chan.close()

        reason = reason.encode('utf-8')
        lang = lang.encode('ascii')
        self.send_packet(Byte(MSG_DISCONNECT), UInt32(code),
                         String(reason), String(lang))

        self._transport.close()
        self._transport = None

    def get_extra_info(self, name, default=None):
        """Get additional information about the connection

           This method returns extra information about the connection once
           it is established. Supported values include everything supported
           by a socket transport plus:

             | username
             | client_version
             | server_version
             | send_cipher
             | send_mac
             | send_compression
             | recv_cipher
             | recv_mac
             | recv_compression

           See :meth:`get_extra_info() <asyncio.BaseTransport.get_extra_info>`
           in :class:`asyncio.BaseTransport` for more information.

        """

        return self._extra.get(name,
                               self._transport.get_extra_info(name, default)
                               if self._transport else default)

    def send_debug(self, msg, lang=DEFAULT_LANG, always_display=False):
        """Send a debug message on this connection

           This method can be called to send a debug message to the
           other end of the connection.

           :param string msg:
               The debug message to send
           :param string lang:
               The language the message is in
           :param boolean always_display:
               Whether or not to display the message

        """

        msg = msg.encode('utf-8')
        lang = lang.encode('ascii')
        self.send_packet(Byte(MSG_DEBUG), Boolean(always_display),
                         String(msg), String(lang))

    @asyncio.coroutine
    def forward_connection(self, dest_host, dest_port):
        """Forward a tunneled SSH connection

           This method is a coroutine which can be returned by a
           ``session_factory`` to forward connections tunneled over
           SSH to the specified destination host and port.

           :param string dest_host:
               The hostname or address to forward the connections to
           :param integer dest_port:
               The port number to forward the connections to

           :returns: coroutine that returns an :class:`SSHTCPSession`

        """

        try:
            def protocol_factory():
                """Return an SSH port forwarder tied to this connection"""

                return SSHPortForwarder(self, self._loop)

            _, peer = yield from self._loop.create_connection(protocol_factory,
                                                              dest_host,
                                                              dest_port)
        except OSError as exc:
            raise ChannelOpenError(OPEN_CONNECT_FAILED, str(exc)) from None

        return SSHRemotePortForwarder(self, self._loop, peer)


class SSHClientConnection(SSHConnection):
    """SSH client connection

       This class represents an SSH client connection.

       Once authentication is successful on a connection, new client
       sessions can be opened by calling :meth:`create_session`.

       Direct TCP connections can be opened by calling
       :meth:`create_connection`.

       Remote listeners for forwarded TCP connections can be opened by
       calling :meth:`create_server`.

       TCP port forwarding can be set up by calling :meth:`forward_local_port`
       or :meth:`forward_remote_port`.

    """

    def __init__(self, client_factory, loop, host, port, known_hosts,
                 username, password, client_keys, passphrase, kex_algs,
                 encryption_algs, mac_algs, compression_algs, rekey_bytes,
                 rekey_seconds, auth_waiter):
        super().__init__(client_factory, loop, kex_algs, encryption_algs,
                         mac_algs, compression_algs, rekey_bytes,
                         rekey_seconds, server=False)

        self._host = host
        self._port = port if port != _DEFAULT_PORT else None
        self._known_hosts = known_hosts
        self._server_host_keys = set()
        self._server_ca_keys = set()
        self._revoked_server_keys = set()

        if username is None:
            username = getpass.getuser()

        self._username = saslprep(username)

        if client_keys:
            self._client_keys = _load_private_key_list(client_keys, passphrase)
        else:
            self._client_keys = []

            if client_keys is ():
                for file in _DEFAULT_KEY_FILES:
                    try:
                        file = os.path.join(os.environ['HOME'], '.ssh', file)
                        client_key = _load_private_key(file, passphrase)
                        self._client_keys.append(client_key)
                    except OSError:
                        pass

        self._password = password
        self._kbdint_password_auth = False

        self._remote_listeners = {}
        self._dynamic_remote_listeners = {}

        self._auth_waiter = auth_waiter

    def _connection_made(self):
        """Handle the opening of a new connection"""

        if self._known_hosts is None:
            self._server_host_keys = None
            self._server_ca_keys = None
            self._revoked_server_keys = None
            self._server_host_key_algs = (get_public_key_algs() +
                                          get_certificate_algs())
        else:
            if not self._known_hosts:
                self._known_hosts = os.path.join(os.environ['HOME'], '.ssh',
                                                 'known_hosts')

            if isinstance(self._known_hosts, (str, bytes)):
                server_host_keys, server_ca_keys, revoked_server_keys = \
                    match_known_hosts(self._known_hosts, self._host,
                                      self._peer_addr, self._port)
            else:
                server_host_keys, server_ca_keys, revoked_server_keys = \
                    self._known_hosts

                server_host_keys = _load_public_key_list(server_host_keys)
                server_ca_keys = _load_public_key_list(server_ca_keys)
                revoked_server_keys = \
                    _load_public_key_list(revoked_server_keys)

            self._server_host_keys = set()
            self._server_host_key_algs = []

            self._server_ca_keys = set(server_ca_keys)
            if server_ca_keys:
                self._server_host_key_algs.extend(get_certificate_algs())

            self._revoked_server_keys = set(revoked_server_keys)

            for key in server_host_keys:
                self._server_host_keys.add(key)
                if key.algorithm not in self._server_host_key_algs:
                    self._server_host_key_algs.append(key.algorithm)

        if not self._server_host_key_algs:
            raise DisconnectError(DISC_HOST_KEY_NOT_VERIFYABLE,
                                  'No trusted server host keys available')

    def _cleanup(self, exc):
        """Clean up this client connection"""

        if self._remote_listeners:
            for listener in self._remote_listeners.values():
                listener.close()

            self._remote_listeners = {}
            self._dynamic_remote_listeners = {}

        if self._auth_waiter:
            if not self._auth_waiter.cancelled():
                self._auth_waiter.set_exception(exc)

            self._auth_waiter = None

        super()._cleanup(exc)

    def validate_server_host_key(self, data):
        """Validate and return the server's host key"""

        try:
            cert = decode_ssh_certificate(data)
        except KeyImportError:
            pass
        else:
            if self._revoked_server_keys is not None and \
               cert.signing_key in self._revoked_server_keys:
                raise DisconnectError(DISC_HOST_KEY_NOT_VERIFYABLE,
                                      'Revoked server CA key')

            if self._server_ca_keys is not None and \
               cert.signing_key not in self._server_ca_keys:
                raise DisconnectError(DISC_HOST_KEY_NOT_VERIFYABLE,
                                      'Untrusted server CA key')

            try:
                cert.validate(CERT_TYPE_HOST, self._host)
            except ValueError as exc:
                raise DisconnectError(DISC_HOST_KEY_NOT_VERIFYABLE,
                                      str(exc)) from None

            return cert.key

        try:
            key = decode_ssh_public_key(data)
        except KeyImportError:
            pass
        else:
            if self._revoked_server_keys is not None and \
               key in self._revoked_server_keys:
                raise DisconnectError(DISC_HOST_KEY_NOT_VERIFYABLE,
                                      'Revoked server host key')

            if self._server_host_keys is not None and \
               key not in self._server_host_keys:
                raise DisconnectError(DISC_HOST_KEY_NOT_VERIFYABLE,
                                      'Untrusted server host key')

            return key

        raise DisconnectError(DISC_HOST_KEY_NOT_VERIFYABLE,
                              'Unable to decode server host key')

    def try_next_auth(self):
        """Attempt client authentication using the next compatible method"""

        if self._auth:
            self._auth.cancel()
            self._auth = None

        while self._auth_methods:
            method = self._auth_methods.pop(0)

            self._auth = lookup_client_auth(self, method)
            if self._auth:
                return

        self._force_close(DisconnectError(DISC_NO_MORE_AUTH_METHODS_AVAILABLE,
                                          'Permission denied'))

    @asyncio.coroutine
    def public_key_auth_requested(self):
        """Return a client key to authenticate with"""

        if self._client_keys:
            key, cert = self._client_keys.pop(0)
        else:
            result = self._owner.public_key_auth_requested()

            if asyncio.iscoroutine(result):
                result = yield from result

            key, cert = _load_private_key(result)

        if cert:
            self._client_keys.insert(0, (key, None))
            return cert.algorithm, key, cert.data
        elif key:
            return key.algorithm, key, key.get_ssh_public_key()
        else:
            return None, None, None

    @asyncio.coroutine
    def password_auth_requested(self):
        """Return a password to authenticate with"""

        # Only allow password auth if the connection supports encryption
        # and a MAC.
        if (not self._send_cipher or
                (not self._send_mac and
                 self._send_mode not in ('chacha', 'gcm'))):
            return None

        if self._password:
            result = self._password
            self._password = None
        else:
            result = self._owner.password_auth_requested()

            if asyncio.iscoroutine(result):
                result = yield from result

        return result

    @asyncio.coroutine
    def password_change_requested(self, prompt, lang):
        """Return a password to authenticate with and what to change it to"""

        result = self._owner.password_change_requested(prompt, lang)

        if asyncio.iscoroutine(result):
            result = yield from result

        return result

    def password_changed(self):
        """Report a successful password change"""

        self._owner.password_changed()

    def password_change_failed(self):
        """Report a failed password change"""

        self._owner.password_change_failed()

    @asyncio.coroutine
    def kbdint_auth_requested(self):
        """Return the list of supported keyboard-interactive auth methods

           If keyboard-interactive auth is not supported in the client but
           a password was provided when the connection was opened, this
           will allow sending the password via keyboard-interactive auth.

        """

        # Only allow keyboard interactive auth if the connection supports
        # encryption and a MAC.
        if (not self._send_cipher or
                (not self._send_mac and
                 self._send_mode not in ('chacha', 'gcm'))):
            return None

        result = self._owner.kbdint_auth_requested()

        if asyncio.iscoroutine(result):
            result = yield from result

        if result is NotImplemented:
            if self._password is not None and not self._kbdint_password_auth:
                self._kbdint_password_auth = True
                result = ''
            else:
                result = None

        return result

    @asyncio.coroutine
    def kbdint_challenge_received(self, name, instructions, lang, prompts):
        """Return responses to a keyboard-interactive auth challenge"""

        if self._kbdint_password_auth:
            if len(prompts) == 0:
                # Silently drop any empty challenges used to print messages
                result = []
            elif len(prompts) == 1 and 'password' in prompts[0][0].lower():
                password = self.password_auth_requested()

                if asyncio.iscoroutine(password):
                    password = yield from password

                result = [password] if password is not None else None
            else:
                result = None
        else:
            result = self._owner.kbdint_challenge_received(name, instructions,
                                                           lang, prompts)

            if asyncio.iscoroutine(result):
                result = yield from result

        return result

    def _process_session_open(self, packet):
        """Process an inbound session open request

           These requests are disallowed on an SSH client.

        """

        # pylint: disable=no-self-use,unused-argument

        raise ChannelOpenError(OPEN_ADMINISTRATIVELY_PROHIBITED,
                               'Session open forbidden on client')

    def _process_direct_tcpip_open(self, packet):
        """Process an inbound direct TCP/IP channel open request

           These requests are disallowed on an SSH client.

        """

        # pylint: disable=no-self-use,unused-argument

        raise ChannelOpenError(OPEN_ADMINISTRATIVELY_PROHIBITED,
                               'Direct TCP/IP open forbidden on client')

    def _process_forwarded_tcpip_open(self, packet):
        """Process an inbound forwarded TCP/IP channel open request"""

        dest_host = packet.get_string()
        dest_port = packet.get_uint32()
        orig_host = packet.get_string()
        orig_port = packet.get_uint32()
        packet.check_end()

        try:
            dest_host = dest_host.decode('utf-8')
            orig_host = orig_host.decode('utf-8')
        except UnicodeDecodeError:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Invalid channel open request') from None

        # Some buggy servers send back a port of ``0`` instead of the actual
        # listening port when reporting connections which arrive on a listener
        # set up on a dynamic port. This lookup attempts to work around that.
        listener = (self._remote_listeners.get((dest_host, dest_port)) or
                    self._dynamic_remote_listeners.get(dest_host))

        if listener:
            return listener.process_connection(orig_host, orig_port)
        else:
            raise ChannelOpenError(OPEN_CONNECT_FAILED, 'No such listener')

    @asyncio.coroutine
    def close_client_listener(self, listener, listen_host, listen_port):
        """Close a remote TCP/IP listener"""

        yield from self._make_global_request(
            b'cancel-tcpip-forward', String(listen_host.encode('utf-8')),
            UInt32(listen_port))

        if self._dynamic_remote_listeners[listen_host] == listener:
            del self._dynamic_remote_listeners[listen_host]

        del self._remote_listeners[listen_host, listen_port]

    @asyncio.coroutine
    def create_session(self, session_factory, command=None, *, subsystem=None,
                       env={}, term_type=None, term_size=None, term_modes={},
                       encoding='utf-8', window=_DEFAULT_WINDOW,
                       max_pktsize=_DEFAULT_MAX_PKTSIZE):
        """Create an SSH client session

           This method is a coroutine which can be called to create an SSH
           client session used to execute a command, start a subsystem
           such as sftp, or if no command or subsystem is specific run an
           interactive shell. Optional arguments allow terminal and
           environment information to be provided.

           By default, this class expects string data in its send and
           receive functions, which it encodes on the SSH connection in
           UTF-8 (ISO 10646) format. An optional encoding argument can
           be passed in to select a different encoding, or ``None`` can
           be passed in if the application wishes to send and receive
           raw bytes.

           Other optional arguments include the SSH receive window size and
           max packet size which default to 2 MB and 32 KB, respectively.

           :param callable session_factory:
               A callable which returns an :class:`SSHClientSession` object
               that will be created to handle activity on this session
           :param string command: (optional)
               The remote command to execute. By default, an interactive
               shell is started if no command or subsystem is provided.
           :param string subsystem: (optional)
               The name of a remote subsystem to start up
           :param dictionary env: (optional)
               The set of environment variables to set for this session.
               Keys and values passed in here will be converted to
               Unicode strings encoded as UTF-8 (ISO 10646) for
               transmission.

               .. note:: Many SSH servers restrict which environment
                         variables a client is allowed to set. The
                         server's configuration may need to be edited
                         before environment variables can be
                         successfully set in the remote environment.
           :param string term_type: (optional)
               The terminal type to set for this session. If this is not set,
               a pseudo-terminal will not be requested for this session.
           :param term_size: (optional)
               The terminal width and height in characters and optionally
               the width and height in pixels
           :param term_modes: (optional)
               POSIX terminal modes to set for this session, where keys
               are taken from :ref:`POSIX terminal modes <PTYModes>` with
               values defined in section 8 of :rfc:`4254#section-8`.
           :param string encoding: (optional)
               The Unicode encoding to use for data exchanged on the connection
           :param integer window: (optional)
               The receive window size for this session
           :param integer max_pktsize: (optional)
               The maximum packet size for this session
           :type term_size: *tuple of 2 or 4 integers*

           :returns: an :class:`SSHClientChannel` and :class:`SSHClientSession`

        """

        chan = SSHClientChannel(self, self._loop, encoding,
                                window, max_pktsize)

        return (yield from chan.create(session_factory, command, subsystem,
                                       env, term_type, term_size, term_modes))

    @asyncio.coroutine
    def open_session(self, *args, **kwargs):
        """Open an SSH client session

           This method is a coroutine wrapper around :meth:`create_session`
           designed to provide a "high-level" stream interface for creating
           an SSH client session. Instead of taking a ``session_factory``
           argument for constructing an object which will handle activity
           on the session via callbacks, it returns an :class:`SSHWriter`
           and two :class:`SSHReader` objects representing stdin, stdout,
           and stderr which can be used to perform I/O on the session. With
           the exception of ``session_factory``, all of the arguments to
           :meth:`create_session` are supported and have the same meaning.

        """

        chan, session = yield from self.create_session(SSHClientStreamSession,
                                                       *args, **kwargs)

        return (SSHWriter(session, chan), SSHReader(session, chan),
                SSHReader(session, chan, EXTENDED_DATA_STDERR))

    @asyncio.coroutine
    def create_connection(self, session_factory, dest_host, dest_port,
                          orig_host='', orig_port=0, *, encoding=None,
                          window=_DEFAULT_WINDOW,
                          max_pktsize=_DEFAULT_MAX_PKTSIZE):
        """Create an SSH TCP direct connection

           This method is a coroutine which can be called to request that
           the server open a new outbound TCP connection to the specified
           destination host and port. If the connection is successfully
           opened, a new SSH channel will be opened with data being handled
           by a :class:`SSHTCPSession` object created by ``session_factory``.

           Optional arguments include the host and port of the original
           client opening the connection when performing TCP port forwarding.

           By default, this class expects data to be sent and received as
           raw bytes. However, an optional encoding argument can be
           passed in to select the encoding to use, allowing the
           application send and receive string data.

           Other optional arguments include the SSH receive window size and
           max packet size which default to 2 MB and 32 KB, respectively.

           :param callable session_factory:
               A callable which returns an :class:`SSHClientSession` object
               that will be created to handle activity on this session
           :param string dest_host:
               The hostname or address to connect to
           :param integer dest_port:
               The port number to connect to
           :param string orig_host: (optional)
               The hostname or address of the client requesting the connection
           :param integer orig_port: (optional)
               The port number of the client requesting the connection
           :param string encoding: (optional)
               The Unicode encoding to use for data exchanged on the connection
           :param integer window: (optional)
               The receive window size for this session
           :param integer max_pktsize: (optional)
               The maximum packet size for this session

           :returns: an :class:`SSHTCPChannel` and :class:`SSHTCPSession`

           :raises: :exc:`ChannelOpenError` if the connection can't be opened

        """

        chan = SSHTCPChannel(self, self._loop, encoding, window, max_pktsize)

        return (yield from chan.connect(session_factory, dest_host, dest_port,
                                        orig_host, orig_port))

    @asyncio.coroutine
    def open_connection(self, *args, **kwargs):
        """Open an SSH TCP direct connection

           This method is a coroutine wrapper around :meth:`create_connection`
           designed to provide a "high-level" stream interface for creating
           an SSH TCP direct connection. Instead of taking a
           ``session_factory`` argument for constructing an object which will
           handle activity on the session via callbacks, it returns
           :class:`SSHReader` and :class:`SSHWriter` objects which can be
           used to perform I/O on the connection.

           With the exception of ``session_factory``, all of the arguments
           to :meth:`create_connection` are supported and have the same
           meaning here.

           :returns: an :class:`SSHReader` and :class:`SSHWriter`

           :raises: :exc:`ChannelOpenError` if the connection can't be opened

        """

        chan, session = yield from self.create_connection(SSHTCPStreamSession,
                                                          *args, **kwargs)

        return SSHReader(session, chan), SSHWriter(session, chan)

    @asyncio.coroutine
    def create_server(self, session_factory, listen_host, listen_port, *,
                      encoding=None, window=_DEFAULT_WINDOW,
                      max_pktsize=_DEFAULT_MAX_PKTSIZE):
        """Create a remote SSH TCP listener

           This method is a coroutine which can be called to request that
           the server listen on the specified remote address and port for
           incoming TCP connections. If the request is successful, the
           return value is an :class:`SSHListener` object which can be
           used later to shut down the listener. If the request fails,
           ``None`` is returned.

           :param session_factory:
               A callable or coroutine which takes arguments of the original
               host and port of the client and decides whether to accept the
               connection or not, either returning an :class:`SSHTCPSession`
               object used to handle activity on that connection or raising
               :exc:`ChannelOpenError` to indicate that the connection
               should not be accepted
           :param string listen_host:
               The hostname or address on the remote host to listen on
           :param integer listen_port:
               The port number on the remote host to listen on
           :param string encoding: (optional)
               The Unicode encoding to use for data exchanged on the connection
           :param integer window: (optional)
               The receive window size for this session
           :param integer max_pktsize: (optional)
               The maximum packet size for this session
           :type session_factory: callable or coroutine

           :returns: :class:`SSHListener` or ``None`` if the listener can't
                     be opened

        """

        listen_host = listen_host.lower()

        pkttype, packet = \
            yield from self._make_global_request(
                b'tcpip-forward', String(listen_host.encode('utf-8')),
                UInt32(listen_port))

        if pkttype == MSG_REQUEST_SUCCESS:
            if listen_port == 0:
                listen_port = packet.get_uint32()
                dynamic = True
            else:
                # OpenSSH 6.8 introduced a bug which causes the reply
                # to contain an extra uint32 value of 0 when non-dynamic
                # ports are requested, causing the check_end() call below
                # to fail. This check works around this problem.
                if len(packet.get_remaining_payload()) == 4:
                    packet.get_uint32()

                dynamic = False

            packet.check_end()

            listener = SSHClientListener(self, self._loop, session_factory,
                                         listen_host, listen_port, encoding,
                                         window, max_pktsize)

            if dynamic:
                self._dynamic_remote_listeners[listen_host] = listener

            self._remote_listeners[listen_host, listen_port] = listener
            return listener
        else:
            packet.check_end()
            return None

    @asyncio.coroutine
    def start_server(self, handler_factory, *args, **kwargs):
        """Start a remote SSH TCP listener

           This method is a coroutine wrapper around :meth:`create_server`
           designed to provide a "high-level" stream interface for creating
           remote SSH TCP listeners. Instead of taking a ``session_factory``
           argument for constructing an object which will handle activity on
           the session via callbacks, it takes a ``handler_factory`` which
           returns a callable or coroutine that will be passed
           :class:`SSHReader` and :class:`SSHWriter` objects which can be
           used to perform I/O on each new connection which arrives. Like
           :meth:`create_server`, ``handler_factory`` can also raise
           :exc:`ChannelOpenError` if the connection should not be accepted.

           With the exception of ``handler_factory`` replacing
           ``session_factory``, all of the arguments to :meth:`create_server`
           are supported and have the same meaning here.

           :param handler_factory:
               A callable or coroutine which takes arguments of the original
               host and port of the client and decides whether to accept the
               connection or not, either returning a callback or coroutine
               used to handle activity on that connection or raising
               :exc:`ChannelOpenError` to indicate that the connection
               should not be accepted
           :type handler_factory: callable or coroutine

           :returns: :class:`SSHListener` or ``None`` if the listener can't
                     be opened

        """

        def session_factory(orig_host, orig_port):
            """Return a TCP stream session handler"""

            return SSHTCPStreamSession(handler_factory(orig_host, orig_port))

        return (yield from self.create_server(session_factory,
                                              *args, **kwargs))

    @asyncio.coroutine
    def forward_local_port(self, listen_host, listen_port,
                           dest_host, dest_port):
        """Set up local port forwarding

           This method is a coroutine which attempts to set up port
           forwarding from a local listening port to a remote host and port
           via the SSH connection. If the request is successful, the
           return value is an :class:`SSHListener` object which can be used
           later to shut down the port forwarding.

           :param string listen_host:
               The hostname or address on the local host to listen on
           :param integer listen_port:
               The port number on the local host to listen on
           :param string dest_host:
               The hostname or address to forward the connections to
           :param integer dest_port:
               The port number to forward the connections to

           :returns: :class:`SSHListener`

           :raises: :exc:`OSError` if the listener can't be opened

        """

        def factory():
            """Return a local port forwarder"""

            return SSHLocalPortForwarder(self, self._loop,
                                         self.create_connection,
                                         dest_host, dest_port)

        listen_port, sockets = \
            yield from self._create_tcp_listener(listen_host, listen_port)

        return (yield from self._create_forward_listener(listen_port, sockets,
                                                         factory))

    @asyncio.coroutine
    def forward_remote_port(self, listen_host, listen_port,
                            dest_host, dest_port):
        """Set up remote port forwarding

           This method is a coroutine which attempts to set up port
           forwarding from a remote listening port to a local host and port
           via the SSH connection. If the request is successful, the
           return value is an :class:`SSHListener` object which can be
           used later to shut down the port forwarding. If the request
           fails, ``None`` is returned.

           :param string listen_host:
               The hostname or address on the remote host to listen on
           :param integer listen_port:
               The port number on the remote host to listen on
           :param string dest_host:
               The hostname or address to forward connections to
           :param integer dest_port:
               The port number to forward connections to

           :returns: :class:`SSHListener` or ``None`` if the listener can't
                     be opened

        """

        def session_factory(orig_host, orig_port):
            """Return an SSHTCPConnection used to do remote port forwarding"""

            # pylint: disable=unused-argument
            return self.forward_connection(dest_host, dest_port)

        return self.create_server(session_factory, listen_host, listen_port)

    @asyncio.coroutine
    def start_sftp_client(self, path_encoding='utf-8', path_errors='strict'):
        """Start an SFTP client

           This method is a coroutine which attempts to start a secure
           file transfer session. If it succeeds, it returns an
           :class:`SFTPClient` object which can be used to copy and
           access files on the remote host.

           An optional Unicode encoding can be specified for sending and
           receiving pathnames, defaulting to UTF-8 with strict error
           checking. If an encoding of ``None`` is specified, pathnames
           will be left as bytes rather than being converted to & from
           strings.

           :param string path_encoding:
               The Unicode encoding to apply when sending and receiving
               remote pathnames
           :param string path_errors:
               The error handling strategy to apply on encode/decode errors

           :returns: :class:`SFTPClient`

           :raises: :exc:`SFTPError` if the session can't be opened

        """

        def session_factory():
            """Return an SFTP client session handler"""

            return SFTPClientSession(self._loop, version_waiter)

        version_waiter = asyncio.Future(loop=self._loop)

        _, session = yield from self.create_session(session_factory,
                                                    subsystem='sftp',
                                                    encoding=None)

        yield from version_waiter

        return SFTPClient(session, path_encoding, path_errors)


class SSHServerConnection(SSHConnection):
    """SSH server connection

       This class represents an SSH server connection.

       During authentication, :meth:`send_auth_banner` can be called to
       send an authentication banner to the client.

       Once authenticated, :class:`SSHServer` objects wishing to create
       session objects with non-default channel properties can call
       :meth:`create_server_channel` from their :meth:`session_requested()
       <SSHServer.session_requested>` method and return a tuple of
       the :class:`SSHServerChannel` object returned from that and either
       an :class:`SSHServerSession` object or a coroutine which returns
       an :class:`SSHServerSession`.

       Similarly, :class:`SSHServer` objects wishing to create TCP
       connection objects with non-default channel properties can call
       :meth:`create_tcp_channel` from their :meth:`connection_requested()
       <SSHServer.connection_requested>` method and return a tuple of
       the :class:`SSHTCPChannel` object returned from that and either
       an :class:`SSHTCPSession` object or a coroutine which returns an
       :class:`SSHTCPSession`.

    """

    def __init__(self, server_factory, loop, server_host_keys, passphrase,
                 authorized_client_keys, kex_algs, encryption_algs, mac_algs,
                 compression_algs, allow_pty, session_factory,
                 session_encoding, sftp_factory, window, max_pktsize,
                 rekey_bytes, rekey_seconds, login_timeout):
        super().__init__(server_factory, loop, kex_algs, encryption_algs,
                         mac_algs, compression_algs, rekey_bytes,
                         rekey_seconds, server=True)

        self._allow_pty = allow_pty
        self._session_factory = session_factory
        self._session_encoding = session_encoding
        self._sftp_factory = sftp_factory
        self._window = window
        self._max_pktsize = max_pktsize

        if login_timeout:
            self._login_timer = loop.call_later(login_timeout,
                                                self._login_timer_callback)
        else:
            self._login_timer = None

        server_host_keys = _load_private_key_list(server_host_keys, passphrase)

        self._server_host_keys = OrderedDict()

        for key, cert in server_host_keys:
            if key.algorithm in self._server_host_keys:
                raise ValueError('Multiple keys of type %s found' %
                                 key.algorithm.decode('ascii'))

            self._server_host_keys[key.algorithm] = (key,
                                                     key.get_ssh_public_key())

            if cert:
                if cert.algorithm in self._server_host_keys:
                    raise ValueError('Multiple keys of type %s found' %
                                     cert.algorithm.decode('ascii'))

                self._server_host_keys[cert.algorithm] = (key, cert.data)

        if not self._server_host_keys:
            raise ValueError('No server host keys provided')

        self._server_host_key_algs = self._server_host_keys.keys()

        self._client_keys = _load_authorized_keys(authorized_client_keys)

        self._server_host_key = None
        self._key_options = {}
        self._cert_options = None
        self._kbdint_password_auth = False

    def _cleanup(self, exc):
        """Clean up this server connection"""

        self._cancel_login_timer()
        super()._cleanup(exc)

    def _cancel_login_timer(self):
        """Cancel the login timer"""

        if self._login_timer:
            self._login_timer.cancel()
            self._login_timer = None

    def _login_timer_callback(self):
        """Close the connection if authentication hasn't completed yet"""

        self._login_timer = None

        if not self._auth_complete:
            self.connection_lost(DisconnectError(DISC_CONNECTION_LOST,
                                                 'Login timeout expired'))

    def _connection_made(self):
        """Handle the opening of a new connection"""

        pass

    def _choose_server_host_key(self, peer_host_key_algs):
        """Choose the server host key to use

           Given a list of host key algorithms supported by the client,
           select the first compatible server host key we have and return
           whether or not we were able to find a match.

        """

        for alg in peer_host_key_algs:
            if alg in self._server_host_keys:
                self._server_host_key = self._server_host_keys[alg]
                return True

        return False

    def get_server_host_key(self):
        """Return the chosen server host key

           This method returns the chosen server host private key and a
           corresponding public key or certificate which contains it.

        """

        return self._server_host_key

    @asyncio.coroutine
    def _validate_client_certificate(self, username, key_data):
        """Validate a client certificate for the specified user"""

        try:
            cert = decode_ssh_certificate(key_data)
        except KeyImportError:
            return None

        options = None

        if self._client_keys:
            options = self._client_keys.validate(cert.signing_key,
                                                 self._peer_addr,
                                                 cert.principals, ca=True)

        if options is None:
            result = self._owner.validate_ca_key(username, cert.signing_key)

            if asyncio.iscoroutine(result):
                result = yield from result

            if not result:
                return None

            options = {}

        self._key_options = options

        if self.get_key_option('principals'):
            username = None

        try:
            cert.validate(CERT_TYPE_USER, username)
        except ValueError:
            return None

        allowed_addresses = self.get_certificate_option('source-address')
        if allowed_addresses:
            ip = ip_address(self._peer_addr)
            if not any(ip in network for network in allowed_addresses):
                return None

        self._cert_options = cert.options

        return cert.key

    @asyncio.coroutine
    def _validate_client_public_key(self, username, key_data):
        """Validate a client public key for the specified user"""

        try:
            key = decode_ssh_public_key(key_data)
        except KeyImportError:
            return None

        options = None

        if self._client_keys:
            options = self._client_keys.validate(key, self._peer_addr)

        if options is None:
            result = self._owner.validate_public_key(username, key)

            if asyncio.iscoroutine(result):
                result = yield from result

            if not result:
                return None

            options = {}

        self._key_options = options

        return key

    def public_key_auth_supported(self):
        """Return whether or not public key authentication is supported"""

        return (bool(self._client_keys) or
                self._owner.public_key_auth_supported())

    @asyncio.coroutine
    def validate_public_key(self, username, key_data, msg, signature):
        """Validate the public key or certificate for the specified user

           This method validates that the public key or certificate provided
           is allowed for the specified user. If msg and signature are
           provided, the key is used to also validate the message signature.
           It returns ``True`` when the key is allowed and the signature (if
           present) is valid. Otherwise, it returns ``False``.

        """

        key = ((yield from self._validate_client_certificate(username,
                                                             key_data)) or
               (yield from self._validate_client_public_key(username,
                                                            key_data)))

        if key is None:
            return False
        elif msg:
            return key.verify(String(self._session_id) + msg, signature)
        else:
            return True

    def password_auth_supported(self):
        """Return whether or not password authentication is supported"""

        return self._owner.password_auth_supported()

    @asyncio.coroutine
    def validate_password(self, username, password):
        """Return whether password is valid for this user"""

        result = self._owner.validate_password(username, password)

        if asyncio.iscoroutine(result):
            result = yield from result

        return result

    @asyncio.coroutine
    def change_password(self, username, old_password, new_password):
        """Handle a password change request for a user"""

        result = self._owner.change_password(username, old_password,
                                             new_password)

        if asyncio.iscoroutine(result):
            result = yield from result

        return result

    def kbdint_auth_supported(self):
        """Return whether or not keyboard-interactive authentication
           is supported"""

        result = self._owner.kbdint_auth_supported()

        if result is True:
            return True
        elif (result is NotImplemented and
              self._owner.password_auth_supported()):
            self._kbdint_password_auth = True
            return True
        else:
            return False

    @asyncio.coroutine
    def get_kbdint_challenge(self, username, lang, submethods):
        """Return a keyboard-interactive auth challenge"""

        if self._kbdint_password_auth:
            result = ('', '', DEFAULT_LANG, (('Password:', False),))
        else:
            result = self._owner.get_kbdint_challenge(username, lang,
                                                      submethods)

            if asyncio.iscoroutine(result):
                result = yield from result

        return result

    @asyncio.coroutine
    def validate_kbdint_response(self, username, responses):
        """Return whether the keyboard-interactive response is valid
           for this user"""

        if self._kbdint_password_auth:
            if len(responses) != 1:
                return False

            try:
                result = self._owner.validate_password(username, responses[0])

                if asyncio.iscoroutine(result):
                    result = yield from result
            except PasswordChangeRequired:
                # Don't support password change requests for now in
                # keyboard-interactive auth
                result = False
        else:
            result = self._owner.validate_kbdint_response(username, responses)

            if asyncio.iscoroutine(result):
                result = yield from result

        return result

    def _process_session_open(self, packet):
        """Process an incoming session open request"""

        packet.check_end()

        if self._session_factory or self._sftp_factory:
            chan = self.create_server_channel(self._session_encoding,
                                              self._window, self._max_pktsize)
            session = SSHServerStreamSession(self._allow_pty,
                                             self._session_factory,
                                             self._sftp_factory)
        else:
            result = self._owner.session_requested()

            if not result:
                raise ChannelOpenError(OPEN_CONNECT_FAILED, 'Session refused')

            if isinstance(result, tuple):
                chan, result = result
            else:
                chan = self.create_server_channel(self._session_encoding,
                                                  self._window,
                                                  self._max_pktsize)

            if callable(result):
                session = SSHServerStreamSession(self._allow_pty, result, None)
            else:
                session = result

        return chan, session

    def _process_direct_tcpip_open(self, packet):
        """Process an incoming direct TCP/IP open request"""

        dest_host = packet.get_string()
        dest_port = packet.get_uint32()
        orig_host = packet.get_string()
        orig_port = packet.get_uint32()
        packet.check_end()

        try:
            dest_host = dest_host.decode('utf-8')
            orig_host = orig_host.decode('utf-8')
        except UnicodeDecodeError:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Invalid channel open request') from None

        if not self.check_key_permission('port-forwarding') or \
           not self.check_certificate_permission('port-forwarding'):
            raise ChannelOpenError(OPEN_ADMINISTRATIVELY_PROHIBITED,
                                   'Port forwarding not permitted')

        permitted_opens = self.get_key_option('permitopen')

        if permitted_opens and \
           (dest_host, dest_port) not in permitted_opens and \
           (dest_host, None) not in permitted_opens:
            raise ChannelOpenError(OPEN_ADMINISTRATIVELY_PROHIBITED,
                                   'Port forwarding not permitted to %s '
                                   'port %s' % (dest_host, dest_port))

        result = self._owner.connection_requested(dest_host, dest_port,
                                                  orig_host, orig_port)

        if not result:
            raise ChannelOpenError(OPEN_CONNECT_FAILED, 'Connection refused')

        if result is True:
            result = self.forward_connection(dest_host, dest_port)

        if isinstance(result, tuple):
            chan, result = result
        else:
            chan = self.create_tcp_channel()

        if callable(result):
            session = SSHTCPStreamSession(result)
        else:
            session = result

        chan.set_inbound_peer_names(dest_host, dest_port, orig_host, orig_port)

        return chan, session

    def _process_tcpip_forward_global_request(self, packet):
        """Process an incoming TCP/IP port forwarding request"""

        listen_host = packet.get_string()
        listen_port = packet.get_uint32()
        packet.check_end()

        try:
            listen_host = listen_host.decode('utf-8').lower()
        except UnicodeDecodeError:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Invalid TCP forward request') from None

        if not self.check_key_permission('port-forwarding') or \
           not self.check_certificate_permission('port-forwarding'):
            self._report_global_response(False)
            return

        result = self._owner.server_requested(listen_host, listen_port)

        if not result:
            self._report_global_response(False)
            return

        if result is True:
            result = self._create_default_forwarder(listen_host, listen_port)

        asyncio.async(self._finish_forward(result, listen_host, listen_port),
                      loop=self._loop)

    @asyncio.coroutine
    def _create_default_forwarder(self, listen_host, listen_port):
        """Create a TCP listener which does port forwarding"""

        def factory():
            """Return a local port forwarder"""

            return SSHLocalPortForwarder(self, self._loop,
                                         self.create_connection,
                                         listen_host, listen_port)

        listen_port, sockets = \
            yield from self._create_tcp_listener(listen_host, listen_port)

        return (yield from self._create_forward_listener(listen_port, sockets,
                                                         factory))

    @asyncio.coroutine
    def _finish_forward(self, listener, listen_host, listen_port):
        """Finish processing a port forwarding request"""

        if asyncio.iscoroutine(listener):
            try:
                listener = yield from listener
            except OSError:
                listener = None
            except: # pylint: disable=bare-except
                self.internal_error()
                return

        if listener:
            if listen_port == 0:
                listen_port = listener.get_port()
                result = UInt32(listen_port)
            else:
                result = True

            self._local_listeners[listen_host, listen_port] = listener

            self._report_global_response(result)
        else:
            self._report_global_response(False)

    def _process_cancel_tcpip_forward_global_request(self, packet):
        """Process a request to cancel TCP/IP port forwarding"""

        listen_host = packet.get_string()
        listen_port = packet.get_uint32()
        packet.check_end()

        try:
            listen_host = listen_host.decode('utf-8').lower()
        except UnicodeDecodeError:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Invalid TCP forward request') from None

        listener = self._local_listeners.pop((listen_host, listen_port))
        if not listener:
            raise DisconnectError(DISC_PROTOCOL_ERROR, 'No such listener')

        listener.close()

    def send_auth_banner(self, msg, lang=DEFAULT_LANG):
        """Send an authentication banner to the client

           This method can be called to send an authentication banner to
           the client, displaying information while authentication is
           in progress. It is an error to call this method after the
           authentication is complete.

           :param string msg:
               The message to display
           :param string lang:
               The language the message is in

           :raises: :exc:`OSError` if authentication is already completed

        """

        if self._auth_complete:
            raise OSError('Authentication already completed')

        msg = msg.encode('utf-8')
        lang = lang.encode('ascii')
        self.send_packet(Byte(MSG_USERAUTH_BANNER), String(msg), String(lang))

    def set_authorized_keys(self, authorized_keys):
        """Set the keys trusted for client public key authentication

           This method can be called to set the trusted user and
           CA keys for client public key authentication. It should
           generally be called from the :meth:`begin_auth
           <SSHServer.begin_auth>` method of :class:`SSHServer` to
           set the appropriate keys for the user attempting to
           authenticate.

           :param authorized_keys:
               The keys to trust for client public key authentication
           :type authorized_keys: *see* :ref:`SpecifyingAuthorizedKeys`

        """

        self._client_keys = _load_authorized_keys(authorized_keys)

    def get_key_option(self, option, default=None):
        """Return option from authorized_keys

           If a client key or certificate was presented during authentication,
           this method returns the value of the requested option in the
           corresponding authorized_keys entry if it was set. Otherwise, it
           returns the default value provided.

           The following standard options are supported:

               | command (string)
               | environment (dictionary of name/value pairs)
               | from (list of host patterns)
               | permitopen (list of host/port tuples)
               | principals (list of usernames)

           Non-standard options are also supported and will return the
           value ``True`` if the option is present without a value or
           return a list of strings containing the values associated
           with each occurrence of that option name. If the option is
           not present, the specified default value is returned.

           :param string option:
               The name of the option to look up.
           :param default:
               The default value to return if the option is not present.

           :returns: The value of the option in authorized_keys, if set

        """

        if self._key_options is not None:
            return self._key_options.get(option, default)
        else:
            return default

    def check_key_permission(self, permission):
        """Check permissions in authorized_keys

           If a client key or certificate was presented during
           authentication, this method returns whether the specified
           permission is allowed by the corresponding authorized_keys
           entry. By default, all permissions are granted, but they
           can be revoked by specifying an option starting with
           'no-' without a value.

           The following standard options are supported:

               | X11-forwarding
               | agent-forwarding
               | port-forwarding
               | pty
               | user-rc

           AsyncSSH internally enforces port-forwarding and pty
           permissions but ignores the other values since it does
           not implement those features.

           Non-standard permissions can also be checked, as long as the
           option follows the convention of starting with 'no-'.

           :param string permission:
               The name of the permission to check (without the 'no-').

           :returns: A boolean indicating if the permission is granted.

        """

        if self._key_options is not None:
            return not self._key_options.get('no-' + permission, False)
        else:
            return True

    def get_certificate_option(self, option, default=None):
        """Return option from user certificate

           If a user certificate was presented during authentication,
           this method returns the value of the requested option in
           the certificate if it was set. Otherwise, it returns the
           default value provided.

           The following options are supported:

               | force-command (string)
               | source-address (list of CIDR-style IP network addresses)

           :param string option:
               The name of the option to look up.
           :param default:
               The default value to return if the option is not present.

           :returns: The value of the option in the user certificate, if set

        """

        if self._cert_options is not None:
            return self._cert_options.get(option, default)
        else:
            return default

    def check_certificate_permission(self, permission):
        """Check permissions in user certificate

           If a user certificate was presented during authentication,
           this method returns whether the specified permission was
           granted in the certificate. Otherwise, it acts as if all
           permissions are granted and returns ``True``.

           The following permissions are supported:

               | X11-forwarding
               | agent-forwarding
               | port-forwarding
               | pty
               | user-rc

           AsyncSSH internally enforces port-forwarding and pty permissions
           but ignores the other values since it does not implement those
           features.

           :param string permission:
               The name of the permission to check (without the 'permit-').

           :returns: A boolean indicating if the permission is granted.

        """

        if self._cert_options is not None:
            return self._cert_options.get('permit-' + permission, False)
        else:
            return True

    def create_server_channel(self, encoding='utf-8', window=_DEFAULT_WINDOW,
                              max_pktsize=_DEFAULT_MAX_PKTSIZE):
        """Create an SSH server channel for a new SSH session

           This method can be called by :meth:`session_requested()
           <SSHServer.session_requested>` to create an
           :class:`SSHServerChannel` with the desired encoding, window,
           and max packet size for a newly created SSH server session.

           :param string encoding: (optional)
               The Unicode encoding to use for data exchanged on the
               session, defaulting to UTF-8 (ISO 10646) format. If ``None``
               is passed in, the application can send and receive raw
               bytes.
           :param integer window: (optional)
               The receive window size for this session
           :param integer max_pktsize: (optional)
               The maximum packet size for this session

           :returns: :class:`SSHServerChannel`

        """

        return SSHServerChannel(self, self._loop, encoding,
                                window, max_pktsize)

    def create_tcp_channel(self, encoding=None, window=_DEFAULT_WINDOW,
                           max_pktsize=_DEFAULT_MAX_PKTSIZE):
        """Create an SSH TCP channel for a new direct TCP connection

           This method can be called by :meth:`connection_requested()
           <SSHServer.connection_requested>` to create an
           :class:`SSHTCPChannel` with the desired encoding, window, and
           max packet size for a newly created SSH direct connection.

           :param string encoding: (optional)
               The Unicode encoding to use for data exchanged on the
               connection. This defaults to ``None``, allowing the
               application to send and receive raw bytes.
           :param integer window: (optional)
               The receive window size for this session
           :param integer max_pktsize: (optional)
               The maximum packet size for this session

           :returns: :class:`SSHTCPChannel`

        """

        return SSHTCPChannel(self, self._loop, encoding, window, max_pktsize)

    @asyncio.coroutine
    def create_connection(self, session_factory, listen_host, listen_port,
                          orig_host='', orig_port=0, *, encoding=None,
                          window=_DEFAULT_WINDOW,
                          max_pktsize=_DEFAULT_MAX_PKTSIZE):
        """Create an SSH TCP forwarded connection

           This method is a coroutine which can be called to notify the
           client about a new inbound TCP connection arriving on the
           specified listening host and port. If the connection is successfully
           opened, a new SSH channel will be opened with data being handled
           by a :class:`SSHTCPSession` object created by ``session_factory``.

           Optional arguments include the host and port of the original
           client opening the connection when performing TCP port forwarding.

           By default, this class expects data to be sent and received as
           raw bytes. However, an optional encoding argument can be
           passed in to select the encoding to use, allowing the
           application send and receive string data.

           Other optional arguments include the SSH receive window size and
           max packet size which default to 2 MB and 32 KB, respectively.

           :param callable session_factory:
               A callable which returns an :class:`SSHClientSession` object
               that will be created to handle activity on this session
           :param string listen_host:
               The hostname or address of the listener receiving the connection
           :param integer listen_port:
               The port number of the listener receiving the connection
           :param string orig_host: (optional)
               The hostname or address of the client requesting the connection
           :param integer orig_port: (optional)
               The port number of the client requesting the connection
           :param string encoding: (optional)
               The Unicode encoding to use for data exchanged on the connection
           :param integer window: (optional)
               The receive window size for this session
           :param integer max_pktsize: (optional)
               The maximum packet size for this session

           :returns: an :class:`SSHTCPChannel` and :class:`SSHTCPSession`

        """

        chan = SSHTCPChannel(self, self._loop, encoding, window, max_pktsize)

        return (yield from chan.accept(session_factory, listen_host,
                                       listen_port, orig_host, orig_port))

    @asyncio.coroutine
    def open_connection(self, handler_factory, *args, **kwargs):
        """Open an SSH TCP forwarded connection

           This method is a coroutine wrapper around :meth:`create_connection`
           designed to provide a "high-level" stream interface for creating
           an SSH TCP forwarded connection. Instead of taking a
           ``session_factory`` argument for constructing an object which will
           handle activity on the session via callbacks, it returns
           :class:`SSHReader` and :class:`SSHWriter` objects which can be
           used to perform I/O on the connection.

           With the exception of ``session_factory``, all of the arguments
           to :meth:`create_connection` are supported and have the same
           meaning here.

           :returns: an :class:`SSHReader` and :class:`SSHWriter`

        """

        def session_factory():
            """Return a TCP stream session handler"""

            return SSHTCPStreamSession(handler_factory)

        chan, session = yield from self.create_connection(session_factory,
                                                          *args, **kwargs)

        return SSHReader(session, chan), SSHWriter(session, chan)


class SSHClient:
    """SSH client protocol handler

       Applications should subclass this when implementing an SSH client.
       The functions listed below should be overridden to define
       application-specific behavior. In particular, the method
       :meth:`auth_completed` should be defined to open the desired
       SSH channels on this connection once authentication has been
       completed.

       For simple password or public key based authentication, nothing
       needs to be defined here if the password or client keys are passed
       in when the connection is created. However, to prompt interactively
       or otherwise dynamically select these values, the methods
       :meth:`password_auth_requested` and/or :meth:`public_key_auth_requested`
       can be defined. Keyboard-interactive authentication is also supported
       via :meth:`kbdint_auth_requested` and :meth:`kbdint_challenge_received`.

       If the server sends an authentication banner, the method
       :meth:`auth_banner_received` will be called.

       If the server requires a password change, the method
       :meth:`password_change_requested` will be called, followed by either
       :meth:`password_changed` or :meth:`password_change_failed` depending
       on whether the password change is successful.

    """

    # pylint: disable=no-self-use,unused-argument

    def connection_made(self, connection):
        """Called when a connection is made

           This method is called as soon as the TCP connection completes. The
           connection parameter should be stored if needed for later use.

           :param connection:
               The connection which was successfully opened
           :type connection: :class:`SSHClientConnection`

        """

    def connection_lost(self, exc):
        """Called when a connection is lost or closed

           This method is called when a connection is closed. If the
           connection is shut down cleanly, *exc* will be ``None``.
           Otherwise, it will be an exception explaining the reason for
           the disconnect.

           :param exc:
               The exception which caused the connection to close, or
               ``None`` if the connection closed cleanly
           :type exc: :class:`Exception`

        """

    def debug_msg_received(self, msg, lang, always_display):
        """A debug message was received on this connection

           This method is called when the other end of the connection sends
           a debug message. Applications should implement this method if
           they wish to process these debug messages.

           :param string msg:
               The debug message sent
           :param string lang:
               The language the message is in
           :param boolean always_display:
               Whether or not to display the message

        """

    def auth_banner_received(self, msg, lang):
        """An incoming authentication banner was received

           This method is called when the server sends a banner to display
           during authentication. Applications should implement this method
           if they wish to do something with the banner.

           :param string msg:
               The message the server wanted to display
           :param string lang:
               The language the message is in

        """

    def auth_completed(self):
        """Authentication was completed successfully

           This method is called when authentication has completed
           succesfully. Applications may use this method to create
           whatever client sessions and direct TCP/IP connections are
           needed and/or set up listeners for incoming TCP/IP connections
           coming from the server.

        """

        # pylint: disable=no-self-use

    def public_key_auth_requested(self):
        """Public key authentication has been requested

           This method should return a private key corresponding to
           the user that authentication is being attempted for.

           This method may be called multiple times and can return a
           different key to try each time it is called. When there are
           no keys left to try, it should return ``None`` to indicate
           that some other authentication method should be tried.

           If client keys were provided when the connection was opened,
           they will be tried before this method is called.

           If blocking operations need to be performed to determine the
           key to authenticate with, this method may be defined as a
           coroutine.

           :returns: A key as described in :ref:`SpecifyingPrivateKeys`
                     or ``None`` to move on to another authentication
                     method

        """

        return None

    def password_auth_requested(self):
        """Password authentication has been requested

           This method should return a string containing the password
           corresponding to the user that authentication is being
           attempted for. It may be called multiple times and can
           return a different password to try each time, but most
           servers have a limit on the number of attempts allowed.
           When there's no password left to try, this method should
           return ``None`` to indicate that some other authentication
           method should be tried.

           If a password was provided when the connection was opened,
           it will be tried before this method is called.

           If blocking operations need to be performed to determine the
           password to authenticate with, this method may be defined as
           a coroutine.

           :returns: A string containing the password to authenticate
                     with or ``None`` to move on to another authentication
                     method

        """

        return None

    def password_change_requested(self, prompt, lang):
        """A password change has been requested

           This method is called when password authentication was
           attempted and the user's password was expired on the
           server. To request a password change, this method should
           return a tuple or two strings containing the old and new
           passwords. Otherwise, it should return ``NotImplemented``.

           If blocking operations need to be performed to determine the
           passwords to authenticate with, this method may be defined
           as a coroutine.

           By default, this method returns ``NotImplemented``.

           :param string prompt:
               The prompt requesting that the user enter a new password
           :param string lang:
               The language that the prompt is in

           :returns: A tuple of two strings containing the old and new
                     passwords or ``NotImplemented`` if password changes
                     aren't supported

        """

        return NotImplemented

    def password_changed(self):
        """The requested password change was successful

           This method is called to indicate that a requested password
           change was successful. It is generally followed by a call to
           :meth:`auth_completed` since this means authentication was
           also successful.

        """

    def password_change_failed(self):
        """The requested password change has failed

           This method is called to indicate that a requested password
           change failed, generally because the requested new password
           doesn't meet the password criteria on the remote system.
           After this method is called, other forms of authentication
           will automatically be attempted.

        """

    def kbdint_auth_requested(self):
        """Keyboard-interactive authentication has been requested

           This method should return a string containing a comma-separated
           list of submethods that the server should use for
           keyboard-interactive authentication. An empty string can be
           returned to let the server pick the type of keyboard-interactive
           authentication to perform. If keyboard-interactive authentication
           is not supported, ``None`` should be returned.

           By default, keyboard-interactive authentication is supported
           if a password was provided when the :class:`SSHClient` was
           created and it hasn't been sent yet. If the challenge is not
           a password challenge, this authentication will fail. This
           method and the :meth:`kbdint_challenge_received` method can be
           overridden if other forms of challenge should be supported.

           If blocking operations need to be performed to determine the
           submethods to request, this method may be defined as a
           coroutine.

           :returns: A string containing the submethods the server should
                     use for authentication or ``None`` to move on to
                     another authentication method

        """

        return NotImplemented

    def kbdint_challenge_received(self, name, instruction, lang, prompts):
        """A keyboard-interactive auth challenge has been received

           This method is called when the server sends a keyboard-interactive
           authentication challenge.

           The return value should be a list of strings of the same length
           as the number of prompts provided if the challenge can be
           answered, or ``None`` to indicate that some other form of
           authentication should be attempted.

           If blocking operations need to be performed to determine the
           responses to authenticate with, this method may be defined
           as a coroutine.

           By default, this method will look for a challenge consisting
           of a single 'Password:' prompt, and call the method
           :meth:`password_auth_requested` to provide the response.
           It will also ignore challenges with no prompts (generally used
           to provide instructions). Any other form of challenge will
           cause this method to return ``None`` to move on to another
           authentication method.

           :param string name:
               The name of the challenge
           :param string instruction:
               Instructions to the user about how to respond to the challenge
           :param string lang:
               The language the challenge is in
           :param prompts:
               The challenges the user should respond to and whether or
               not the responses should be echoed when they are entered
           :type prompts: list of tuples of string and boolean

           :returns: List of string responses to the challenge or ``None``
                     to move on to another authentication method

        """

        return None


class SSHServer:
    """SSH server protocol handler

       Applications should subclass this when implementing an SSH server.
       At a minimum, one or more of the authentication handlers will need
       to be overridden to perform authentication, or :meth:`begin_auth`
       should be overridden to return ``False`` to indicate that no
       authentication is required.

       In addition, one or more of the :meth:`session_requested`,
       :meth:`connection_requested`, or :meth:`server_requested` methods
       will need to be overridden to handle requests to open sessions or
       direct TCP/IP connections or set up listeners for forwarded
       TCP/IP connections.

    """

    # pylint: disable=no-self-use,unused-argument

    def connection_made(self, connection):
        """Called when a connection is made

           This method is called when a new TCP connection is accepted. The
           connection parameter should be stored if needed for later use.

        """

    def connection_lost(self, exc):
        """Called when a connection is lost or closed

           This method is called when a connection is closed. If the
           connection is shut down cleanly, *exc* will be ``None``.
           Otherwise, it will be an exception explaining the reason for
           the disconnect.

        """

    def debug_msg_received(self, msg, lang, always_display):
        """A debug message was received on this connection

           This method is called when the other end of the connection sends
           a debug message. Applications should implement this method if
           they wish to process these debug messages.

           :param string msg:
               The debug message sent
           :param string lang:
               The language the message is in
           :param boolean always_display:
               Whether or not to display the message

        """

    def begin_auth(self, username):
        """Authentication has been requested by the client

           This method will be called when authentication is attempted for
           the specified user. Applications should use this method to
           prepare whatever state they need to complete the authentication,
           such as loading in the set of authorized keys for that user. If
           no authentication is required for this user, this method should
           return ``False`` to cause the authentication to immediately
           succeed. Otherwise, it should return ``True`` to indicate that
           authentication should proceed.

           :param string username:
               The name of the user being authenticated

           :returns: A boolean indicating whether authentication is required

        """

        return True

    def public_key_auth_supported(self):
        """Return whether or not public key authentication is supported

           This method should return ``True`` if client public key
           authentication is supported. Applications wishing to support
           it must have this method return ``True`` and implement
           :meth:`validate_public_key` to return whether or not the key
           provided by the client is valid for the user being authenticated.

           By default, it returns ``False`` indicating the client public
           key authentication is not supported.

           :returns: A boolean indicating if public key authentication is
                     supported or not

        """

        return False

    def validate_public_key(self, username, key):
        """Return whether key is an authorized client key for this user

           Basic key-based client authentication can be supported by
           passing authorized keys in the ``authorized_client_keys``
           argument of :func:`create_server`, or by calling
           :meth:`set_authorized_keys
           <SSHServerConnection.set_authorized_keys>` on the server
           connection from the :meth:`begin_auth` method. However, for
           more flexibility in matching on the allowed set of keys, this
           method can be implemented by the application to do the
           matching itself. It should return ``True`` if the specified
           key is a valid client key for the user being authenticated.

           This method may be called multiple times with different keys
           provided by the client. Applications should precompute as
           much as possible in the :meth:`begin_auth` method so that
           this function can quickly return whether the key provided is
           in the list.

           If blocking operations need to be performed to determine the
           validity of the key, this method may be defined as a coroutine.

           By default, this method returns ``False`` for all client keys.

               .. note:: This function only needs to report whether the
                         public key provided is a valid client key for this
                         user. If it is, AsyncSSH will verify that the
                         client possesses the corresponding private key
                         before allowing the authentication to succeed.

           :param string username:
               The user being authenticated
           :param key:
               The public key sent by the client
           :type key: :class:`SSHKey` *public key*

           :returns: A boolean indicating if the specified key is a valid
                     client key for the user being authenticated

        """

        return False

    def validate_ca_key(self, username, key):
        """Return whether key is an authorized CA key for this user

           Basic key-based client authentication can be supported by
           passing authorized keys in the ``authorized_client_keys``
           argument of :func:`create_server`, or by calling
           :meth:`set_authorized_keys
           <SSHServerConnection.set_authorized_keys>` on the server
           connection from the :meth:`begin_auth` method. However, for
           more flexibility in matching on the allowed set of keys, this
           method can be implemented by the application to do the
           matching itself. It should return ``True`` if the specified
           key is a valid certificate authority key for the user being
           authenticated.

           This method may be called multiple times with different keys
           provided by the client. Applications should precompute as
           much as possible in the :meth:`begin_auth` method so that
           this function can quickly return whether the key provided is
           in the list.

           If blocking operations need to be performed to determine the
           validity of the key, this method may be defined as a coroutine.

           By default, this method returns ``False`` for all CA keys.

               .. note:: This function only needs to report whether the
                         public key provided is a valid CA key for this
                         user. If it is, AsyncSSH will verify that the
                         certificate is valid, that the user is one of
                         the valid principals for the certificate, and
                         that the client possesses the private key
                         corresponding to the public key in the certificate
                         before allowing the authentication to succeed.

           :param string username:
               The user being authenticated
           :param key:
               The public key which signed the certificate sent by the client
           :type key: :class:`SSHKey` *public key*

           :returns: A boolean indicating if the specified key is a valid
                     CA key for the user being authenticated

        """

        return False

    def password_auth_supported(self):
        """Return whether or not password authentication is supported

           This method should return ``True`` if password authentication
           is supported. Applications wishing to support it must have
           this method return ``True`` and implement :meth:`validate_password`
           to return whether or not the password provided by the client
           is valid for the user being authenticated.

           By default, this method returns ``False`` indicating that
           password authentication is not supported.

           :returns: A boolean indicating if password authentication is
                     supported or not

        """

        return False

    def validate_password(self, username, password):
        """Return whether password is valid for this user

           This method should return ``True`` if the specified password
           is a valid password for the user being authenticated. It must
           be overridden by applications wishing to support password
           authentication.

           If the password provided is valid but expired, this method
           may raise :exc:`PasswordChangeRequired` to request that the
           client provide a new password before authentication is
           allowed to complete. In this case, the application must
           override :meth:`change_password` to handle the password
           change request.

           This method may be called multiple times with different
           passwords provided by the client. Applications may wish
           to limit the number of attempts which are allowed. This
           can be done by having :meth:`password_auth_supported` begin
           returning ``False`` after the maximum number of attempts is
           exceeded.

           If blocking operations need to be performed to determine the
           validity of the password, this method may be defined as a
           coroutine.

           By default, this method returns ``False`` for all passwords.

           :param string username:
               The user being authenticated
           :param string password:
               The password sent by the client

           :returns: A boolean indicating if the specified password is
                     valid for the user being authenticated

           :raises: :exc:`PasswordChangeRequired` if the password
                    provided is expired and needs to be changed

        """

        return False

    def change_password(self, username, old_password, new_password):
        """Handle a request to change a user's password

           This method is called when a user makes a request to
           change their password. It should first validate that
           the old password provided is correct and then attempt
           to change the user's password to the new value.

           If the old password provided is valid and the change to
           the new password is successful, this method should
           return ``True``. If the old password is not valid or
           password changes are not supported, it should return
           ``False``. It may also raise :exc:`PasswordChangeRequired`
           to request that the client try again if the new password
           is not acceptable for some reason.

           If blocking operations need to be performed to determine the
           validity of the old password or to change to the new password,
           this method may be defined as a coroutine.

           By default, this method returns ``False``, rejecting all
           password changes.

           :param string username:
               The user whose password should be changed
           :param string old_password:
               The user's current password
           :param string new_password:
               The new password being requested

           :returns: A boolean indicating if the password change
                     is successful or not

           :raises: :exc:`PasswordChangeRequired` if the new password
                    is not acceptable and the client should be asked
                    to provide another

        """

        return False

    def kbdint_auth_supported(self):
        """Return whether or not keyboard-interactive authentication
           is supported

           This method should return ``True`` if keyboard-interactive
           authentication is supported. Applications wishing to support
           it must have this method return ``True`` and implement
           :meth:`get_kbdint_challenge` and :meth:`validate_kbdint_response`
           to generate the apporiate challenges and validate the responses
           for the user being authenticated.

           By default, this method returns ``NotImplemented`` tying
           this authentication to password authentication. If the
           application implements password authentication and this
           method is not overridden, keyboard-interactive authentication
           will be supported by prompting for a password and passing
           that to the password authentication callbacks.

           :returns: A boolean indicating if keyboard-interactive
                     authentication is supported or not

        """

        return NotImplemented

    def get_kbdint_challenge(self, username, lang, submethods):
        """Return a keyboard-interactive auth challenge

           This method should return ``True`` if authentication should
           succeed without any challenge, ``False`` if authentication
           should fail without any challenge, or an auth challenge
           consisting of a challenge name, instructions, a language tag,
           and a list of tuples containing prompt strings and booleans
           indicating whether input should be echoed when a value is
           entered for that prompt.

           If blocking operations need to be performed to determine the
           challenge to issue, this method may be defined as a coroutine.

           :param string username:
               The user being authenticated
           :param string lang:
               The language requested by the client for the challenge
           :param string submethods:
               A comma-separated list of the types of challenges the client
               can support, or the empty string if the server should choose

           :returns: An authentication challenge as described above

        """

        return False

    def validate_kbdint_response(self, username, responses):
        """Return whether the keyboard-interactive response is valid
           for this user

           This method should validate the keyboard-interactive responses
           provided and return ``True`` if authentication should succeed
           with no further challenge, ``False`` if authentication should
           fail, or an additional auth challenge in the same format returned
           by :meth:`get_kbdint_challenge`. Any series of challenges can be
           returned this way. To print a message in the middle of a sequence
           of challenges without prompting for additional data, a challenge
           can be returned with an empty list of prompts. After the client
           acknowledges this message, this function will be called again
           with an empty list of responses to continue the authentication.

           If blocking operations need to be performed to determine the
           validity of the response or the next challenge to issue, this
           method may be defined as a coroutine.

           :param string username:
               The user being authenticated
           :param responses:
               A list of responses to the last challenge
           :type responses: list of strings

           :returns: ``True``, ``False``, or the next challenge

        """

        return False

    def session_requested(self):
        """Handle an incoming session request

           This method is called when a session open request is received
           from the client, indicating it wishes to open a channel to be
           used for running a shell, executing a command, or connecting
           to a subsystem. If the application wishes to accept the session,
           it must override this method to return either an
           :class:`SSHServerSession` object to use to process
           the data received on the channel or a tuple consisting of an
           :class:`SSHServerChannel` object created with
           :meth:`create_server_channel
           <SSHServerConnection.create_server_channel>` and an
           :class:`SSHServerSession`, if the application
           wishes to pass non-default arguments when creating the channel.

           If blocking operations need to be performed before the session
           can be created, a coroutine which returns an
           :class:`SSHServerSession` object can be returned instead of
           the session iself. This can be either returned directly or as
           a part of a tuple with an :class:`SSHServerChannel` object.

           To reject this request, this method should return ``False``
           to send back a "Session refused" response or raise a
           :exc:`ChannelOpenError` exception with the reason for
           the failure.

           The details of what type of session the client wants to start
           will be delivered to methods on the :class:`SSHServerSession`
           object which is returned, along with other information such
           as environment variables, terminal type, size, and modes.

           By default, all session requests are rejected.

           :returns: One of the following:

                       * An :class:`SSHServerSession` object or a coroutine
                         which returns an :class:`SSHServerSession`
                       * A tuple consisting of an :class:`SSHServerChannel`
                         and the above
                       * A callable or coroutine handler function which
                         takes AsyncSSH stream objects for stdin, stdout,
                         and stderr as arguments
                       * A tuple consisting of an :class:`SSHServerChannel`
                         and the above
                       * ``False`` to refuse the request

           :raises: :exc:`ChannelOpenError` if the session shouldn't
                    be accepted

        """

        return False

    def connection_requested(self, dest_host, dest_port, orig_host, orig_port):
        """Handle a direct TCP/IP connection request

           This method is called when a direct TCP/IP connection
           request is received by the server. Applications wishing
           to accept such connections must override this method.

           To allow standard port forwarding of data on the connection
           to the requested destination host and port, this method
           should return ``True``.

           To reject this request, this method should return ``False``
           to send back a "Connection refused" response or raise an
           :exc:`ChannelOpenError` exception with the reason for
           the failure.

           If the application wishes to process the data on the
           connection itself, this method should return either an
           :class:`SSHTCPSession` object which can be used to process the
           data received on the channel or a tuple consisting of of an
           :class:`SSHTCPChannel` object created with
           :meth:`create_tcp_channel()
           <SSHServerConnection.create_tcp_channel>` and an
           :class:`SSHTCPSession`, if the application wishes
           to pass non-default arguments when creating the channel.

           If blocking operations need to be performed before the session
           can be created, a coroutine which returns an
           :class:`SSHTCPSession` object can be returned instead of
           the session iself. This can be either returned directly or as
           a part of a tuple with an :class:`SSHTCPChannel` object.

           By default, all connection requests are rejected.

           :param string dest_host:
               The address the client wishes to connect to
           :param integer dest_port:
               The port the client wishes to connect to
           :param string orig_host:
               The address the connection was originated from
           :param integer orig_port:
               The port the connection was originated from

           :returns: One of the following:

                     * An :class:`SSHTCPSession` object or a coroutine
                       which returns an :class:`SSHTCPSession`
                     * A tuple consisting of an :class:`SSHTCPChannel`
                       and the above
                     * A callable or coroutine handler function which
                       takes AsyncSSH stream objects for reading and
                       writing to the connection
                     * A tuple consisting of an :class:`SSHTCPChannel`
                       and the above
                     * ``True`` to request standard port forwarding
                     * ``False`` to refuse the connection

           :raises: :exc:`ChannelOpenError` if the connection shouldn't
                    be accepted

        """

        return False

    def server_requested(self, listen_host, listen_port):
        """Handle a request to listen on a TCP/IP address and port

           This method is called when a client makes a request to
           listen on an address and port for incoming TCP connections.
           The port to listen on may be ``0`` to request a dynamically
           allocated port. Applications wishing to allow TCP/IP connection
           forwarding must override this method.

           To set up standard port forwarding of connections received
           on this address and port, this method should return ``True``.

           If the application wishes to manage listening for incoming
           connections itself, this method should return an
           :class:`SSHListener` object that listens for new connections
           and calls :meth:`create_connection
           <SSHServerConnection.create_connection>` on each of them to
           forward them back to the client or returns ``None`` if the
           listener can't be set up.

           If blocking operations need to be performed to set up the
           listener, a coroutine which returns an :class:`SSHListener`
           can be returned instead of the listener itself.

           To reject this request, this method should return ``False``.

           By default, this method rejects all server requests.

           :param string listen_host:
               The address the server should listen on
           :param integer listen_port:
               The port the server should listen on, or the value ``0``
               to request that the server dynamically allocate a port

           :returns: One of the following:

                     * An :class:`SSHListener` object or a coroutine
                       which returns an :class:`SSHListener` or ``False``
                       if the listener can't be opened
                     * ``True`` to set up standard port forwarding
                     * ``False`` to reject the request

        """

        return False


@asyncio.coroutine
def create_connection(client_factory, host, port=_DEFAULT_PORT, *,
                      loop=None, family=0, flags=0, local_addr=None,
                      known_hosts=(), username=None, password=None,
                      client_keys=(), passphrase=None,
                      kex_algs=(), encryption_algs=(),
                      mac_algs=(), compression_algs=(),
                      rekey_bytes=_DEFAULT_REKEY_BYTES,
                      rekey_seconds=_DEFAULT_REKEY_SECONDS):
    """Create an SSH client connection

       This function is a coroutine which can be run to create an outbound SSH
       client connection to the specified host and port.

       When successful, the following steps occur:

           1. The connection is established and an :class:`SSHClientConnection`
              object is created to represent it.
           2. The ``client_factory`` is called without arguments and should
              return an :class:`SSHClient` object.
           3. The client object is tied to the connection and its
              :meth:`connection_made() <SSHClient.connection_made>` method
              is called.
           4. The SSH handshake and authentication process is initiated,
              calling methods on the client object if needed.
           5. When authentication completes successfully, the client's
              :meth:`auth_completed() <SSHClient.auth_completed>` method is
              called.
           6. The coroutine returns the ``(connection, client)`` pair. At
              this point, the connection is ready for sessions to be opened
              or port forwarding to be set up.

       If an error occurs, it will be raised as an exception and the partially
       open connection and client objects will be cleaned up.

       .. note:: Unlike :func:`socket.create_connection`, asyncio calls
                 to create a connection do not support a ``timeout``
                 parameter. However, asyncio calls can be wrapped in a
                 call to :func:`asyncio.wait_for` or :func:`asyncio.wait`
                 which takes a timeout and provides equivalent functionality.

       :param callable client_factory:
           A callable which returns an :class:`SSHClient` object that will
           be tied to the connection
       :param string host:
           The hostname or address to connect to
       :param integer port: (optional)
           The port number to connect to. If not specified, the default
           SSH port is used.
       :param loop: (optional)
           The event loop to use when creating the connection. If not
           specified, the default event loop is used.
       :param family: (optional)
           The address family to use when creating the socket. By default,
           the address family is automatically selected based on the host.
       :param flags: (optional)
           The flags to pass to getaddrinfo() when looking up the host address
       :param local_addr: (optional)
           The host and port to bind the socket to before connecting
       :param known_hosts: (optional)
           The list of keys which will be used to validate the server host
           key presented during the SSH handshake. If this is not specified,
           the keys will be looked up in the file :file:`.ssh/known_hosts`.
           If this is explicitly set to ``None``, server host key validation
           will be disabled.
       :param string username: (optional)
           Username to authenticate as on the server. If not specified,
           the currently logged in user on the local machine will be used.
       :param string password: (optional)
           The password to use for client password authentication or
           keyboard-interactive authentication which prompts for a password.
           If this is not specified, client password authentication will
           not be performed.
       :param client_keys: (optional)
           A list of keys which will be used to authenticate this client
           via public key authentication. If no client keys are specified,
           an attempt will be made to load them from the files
           :file:`.ssh/id_ed25519`, :file:`.ssh/id_ecdsa`,
           :file:`.ssh/id_rsa`, and :file:`.ssh/id_dsa`,
           with optional certificates loaded from the files
           :file:`.ssh/id_ed25519-cert.pub`, :file:`.ssh/id_ecdsa-cert.pub`,
           :file:`.ssh/id_rsa-cert.pub`, and :file:`.ssh/id_dsa-cert.pub`.
           If this argument is explicitly set to ``None``, client public
           key authentication will not be performed.
       :param string passphrase: (optional)
           The passphrase to use to decrypt client keys when loading them,
           if they are encrypted. If this is not specified, only unencrypted
           client keys can be loaded. If the keys passed into client_keys
           are already loaded, this argument is ignored.
       :param kex_algs: (optional)
           A list of allowed key exchange algorithms in the SSH handshake,
           taken from :ref:`key exchange algorithms <KexAlgs>`
       :param encryption_algs: (optional)
           A list of encryption algorithms to use during the SSH handshake,
           taken from :ref:`encryption algorithms <EncryptionAlgs>`
       :param mac_algs: (optional)
           A list of MAC algorithms to use during the SSH handshake, taken
           from :ref:`MAC algorithms <MACAlgs>`
       :param compression_algs: (optional)
           A list of compression algorithms to use during the SSH handshake,
           taken from :ref:`compression algorithms <CompressionAlgs>`, or
           ``None`` to disable compression
       :param integer rekey_bytes: (optional)
           The number of bytes which can be sent before the SSH session
           key is renegotiated. This defaults to 1 GB.
       :param integer rekey_seconds: (optional)
           The maximum time in seconds before the SSH session key is
           renegotiated. This defaults to 1 hour.
       :type family: ``socket.AF_UNSPEC``, ``socket.AF_INET``, or
                     ``socket.AF_INET6``
       :type flags: flags to pass to :meth:`getaddrinfo() <socket.getaddrinfo>`
       :type local_addr: tuple of string and integer
       :type known_hosts: *see* :ref:`SpecifyingKnownHosts`
       :type client_keys: *see* :ref:`SpecifyingPrivateKeys`
       :type kex_algs: list of strings
       :type encryption_algs: list of strings
       :type mac_algs: list of strings
       :type compression_algs: list of strings

       :returns: An :class:`SSHClientConnection` and :class:`SSHClient`

    """

    def conn_factory():
        """Return an SSH client connection handler"""

        return SSHClientConnection(client_factory, loop, host, port,
                                   known_hosts, username, password,
                                   client_keys, passphrase, kex_algs,
                                   encryption_algs, mac_algs,
                                   compression_algs, rekey_bytes,
                                   rekey_seconds, auth_waiter)

    if not client_factory:
        client_factory = SSHClient

    if not loop:
        loop = asyncio.get_event_loop()

    auth_waiter = asyncio.Future(loop=loop)

    _, conn = yield from loop.create_connection(conn_factory, host, port,
                                                family=family, flags=flags,
                                                local_addr=local_addr)

    yield from auth_waiter

    return conn, conn.get_owner()


@asyncio.coroutine
def create_server(server_factory, host=None, port=_DEFAULT_PORT, *,
                  loop=None, family=0, flags=socket.AI_PASSIVE, backlog=100,
                  reuse_address=None, server_host_keys, passphrase=None,
                  authorized_client_keys=None, kex_algs=(),
                  encryption_algs=(), mac_algs=(), compression_algs=(),
                  allow_pty=True, session_factory=None,
                  session_encoding='utf-8', sftp_factory=None,
                  window=_DEFAULT_WINDOW, max_pktsize=_DEFAULT_MAX_PKTSIZE,
                  rekey_bytes=_DEFAULT_REKEY_BYTES,
                  rekey_seconds=_DEFAULT_REKEY_SECONDS,
                  login_timeout=_DEFAULT_LOGIN_TIMEOUT):
    """Create an SSH server

       This function is a coroutine which can be run to create an SSH server
       bound to the specified host and port. The return value is an object
       derived from :class:`asyncio.AbstractServer` which can be used to
       later shut down the server.

       :param callable server_factory:
           A callable which returns an :class:`SSHServer` object that will
           be created for each new inbound connection
       :param string host: (optional)
           The hostname or address to listen on. If not specified, listeners
           are created for all addresses.
       :param integer port: (optional)
           The port number to listen on. If not specified, the default
           SSH port is used.
       :param loop: (optional)
           The event loop to use when creating the server. If not
           specified, the default event loop is used.
       :param family: (optional)
           The address family to use when creating the server. By default,
           the address families are automatically selected based on the host.
       :param flags: (optional)
           The flags to pass to getaddrinfo() when looking up the host
       :param integer backlog: (optional)
           The maximum number of queued connections allowed on listeners
       :param boolean reuse_address: (optional)
           Whether or not to reuse a local socket in the TIME_WAIT state
           without waiting for its natural timeout to expire. If not
           specified, this will be automatically set to ``True`` on UNIX.
       :param server_host_keys:
           A list of private keys and optional certificates which can be
           used by the server as a host key. This argument must be
           specified.
       :param string passphrase: (optional)
           The passphrase to use to decrypt server host keys when loading
           them, if they are encrypted. If this is not specified, only
           unencrypted server host keys can be loaded. If the keys passed
           into server_host_keys are already loaded, this argument is
           ignored.
       :param authorized_client_keys: (optional)
           A list of authorized user and CA public keys which should be
           trusted for certifcate-based client public key authentication.
       :param kex_algs: (optional)
           A list of allowed key exchange algorithms in the SSH handshake,
           taken from :ref:`key exchange algorithms <KexAlgs>`
       :param encryption_algs: (optional)
           A list of encryption algorithms to use during the SSH handshake,
           taken from :ref:`encryption algorithms <EncryptionAlgs>`
       :param mac_algs: (optional)
           A list of MAC algorithms to use during the SSH handshake, taken
           from :ref:`MAC algorithms <MACAlgs>`
       :param compression_algs: (optional)
           A list of compression algorithms to use during the SSH handshake,
           taken from :ref:`compression algorithms <CompressionAlgs>`, or
           ``None`` to disable compression
       :param boolean allow_pty: (optional)
           Whether or not to allow allocation of a pseudo-tty in sessions,
           defaulting to ``True``
       :param callable session_factory: (optional)
           A callable or coroutine handler function which takes AsyncSSH
           stream objects for stdin, stdout, and stderr that will be called
           each time a new shell, exec, or subsytem other than SFTP is
           requested by the client. If not specified, sessions are rejected
           by default unless the :meth:`session_requested()
           <SSHServer.session_requested>` method is overridden on the
           :class:`SSHServer` object returned by ``server_factory`` to make
           this decision.
       :param string session_encoding: (optional)
           The Unicode encoding to use for data exchanged on sessions on
           this server, defaulting to UTF-8 (ISO 10646) format. If ``None``
           is passed in, the application can send and receive raw bytes.
       :param callable sftp_factory: (optional)
           A callable which returns an :class:`SFTPServer` object that
           will be created each time an SFTP session is requested by the
           client, or ``True`` to use the base :class:`SFTPServer` class
           to handle SFTP requests. If not specified, SFTP sessions are
           rejected by default.
       :param integer window: (optional)
           The receive window size for sessions on this server
       :param integer max_pktsize: (optional)
           The maximum packet size for sessions on this server
       :param integer rekey_bytes: (optional)
           The number of bytes which can be sent before the SSH session
           key is renegotiated, defaulting to 1 GB
       :param integer rekey_seconds: (optional)
           The maximum time in seconds before the SSH session key is
           renegotiated, defaulting to 1 hour
       :param integer login_timeout: (optional)
           The maximum time in seconds allowed for authentication to
           complete, defaulting to 2 minutes
       :type family: ``socket.AF_UNSPEC``, ``socket.AF_INET``, or
                     ``socket.AF_INET6``
       :type flags: flags to pass to :meth:`getaddrinfo() <socket.getaddrinfo>`
       :type server_host_keys: *see* :ref:`SpecifyingPrivateKeys`
       :type authorized_client_keys: *see* :ref:`SpecifyingAuthorizedKeys`
       :type kex_algs: list of strings
       :type encryption_algs: list of strings
       :type mac_algs: list of strings
       :type compression_algs: list of strings

       :returns: :class:`asyncio.AbstractServer`

    """

    if not server_factory:
        server_factory = SSHServer

    if sftp_factory is True:
        sftp_factory = SFTPServer

    if not loop:
        loop = asyncio.get_event_loop()

    def conn_factory():
        """Return an SSH server connection handler"""

        return SSHServerConnection(server_factory, loop, server_host_keys,
                                   passphrase, authorized_client_keys,
                                   kex_algs, encryption_algs, mac_algs,
                                   compression_algs, allow_pty,
                                   session_factory, session_encoding,
                                   sftp_factory, window, max_pktsize,
                                   rekey_bytes, rekey_seconds, login_timeout)

    return (yield from loop.create_server(conn_factory, host, port,
                                          family=family, flags=flags,
                                          backlog=backlog,
                                          reuse_address=reuse_address))


@asyncio.coroutine
def connect(host, port=_DEFAULT_PORT, **kwargs):
    """Make an SSH client connection

       This function is a coroutine wrapper around :func:`create_connection`
       which can be used when a custom SSHClient instance is not needed.
       It takes all the same arguments as :func:`create_connection`
       except for ``client_factory`` and returns only the
       :class:`SSHClientConnection` object rather than a tuple of
       an :class:`SSHClientConnection` and :class:`SSHClient`.

       When using this call, the following restrictions apply:

           1. No callbacks are called when the connection is successfully
              opened, when it is closed, or when authentication completes.

           2. Any authentication information must be provided as arguments
              to this call, as any authentication callbacks will deny
              other authentication attempts. Also, authentication banner
              information will be ignored.

           3. Any debug messages sent by the server will be ignored.

    """

    conn, _ = yield from create_connection(None, host, port, **kwargs)

    return conn


@asyncio.coroutine
def listen(host, port=_DEFAULT_PORT, *, server_host_keys, **kwargs):
    """Start an SSH server

       This function is a coroutine wrapper around :func:`create_server`
       which can be used when a custom SSHServer instance is not needed.
       It takes all the same arguments as :func:`create_server` except for
       ``server_factory``.

       When using this call, the following restrictions apply:

           1. No callbacks are called when a new connection arrives,
              when a connection is closed, or when authentication
              completes.

           2. Any authentication information must be provided as arguments
              to this call, as any authentication callbacks will deny other
              authentication attempts. Currently, this allows only public
              key authentication to be used, by passing in the
              ``authorized_client_keys`` argument.

           3. Only handlers using the streams API are supported and the same
              handlers must be used for all clients. These handlers must
              be provided in the ``session_factory`` and/or ``sftp_factory``
              arguments to this call.

           4. Any debug messages sent by the client will be ignored.

    """

    return (yield from create_server(None, host, port,
                                     server_host_keys=server_host_keys,
                                     **kwargs))
