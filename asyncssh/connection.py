# Copyright (c) 2013 by Ron Frederick <ronf@timeheart.net>.
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

import asyncore, getpass, os, socket, sys, time
from collections import OrderedDict
from os import urandom

from .auth import *
from .channel import *
from .constants import *
from .cipher import *
from .compression import *
from .kex import *
from .mac import *
from .misc import *
from .packet import *
from .public_key import *
from .saslprep import *

# SSH default port
_DEFAULT_PORT = 22

# SSH service names
_USERAUTH_SERVICE   = b'ssh-userauth'
_CONNECTION_SERVICE = b'ssh-connection'

# Default file names in .ssh directory to read private keys from
_DEFAULT_KEY_FILES = ('id_ecdsa', 'id_rsa', 'id_dsa')

# Default rekey parameters
_DEFAULT_REKEY_BYTES    = 1 << 30       # 1 GB
_DEFAULT_REKEY_SECONDS  = 3600          # 1 hour

class _SSHConnection(asyncore.dispatcher, SSHPacketHandler):
    """Parent class for SSH Connection handlers"""

    def __init__(self, sock, rekey_bytes, rekey_seconds, server):
        asyncore.dispatcher.__init__(self, sock)

        self.client_version = b''
        self.server_version = b''
        self.client_kexinit = b''
        self.server_kexinit = b''
        self.server_host_key = None
        self.session_id = None

        self._server = server
        self._inpbuf = b''
        self._outbuf = b''

        self._send_seq = 0
        self._send_cipher = None
        self._send_blocksize = 8
        self._send_mac = None
        self._send_etm = False
        self._compressor = None
        self._compress_after_auth = False
        self._deferred_packets = []

        self._recv_handler = self._recv_version
        self._recv_seq = 0
        self._recv_cipher = None
        self._recv_blocksize = 8
        self._recv_mac = None
        self._recv_macsize = 0
        self._recv_etm = False
        self._decompressor = None
        self._decompress_after_auth = None
        self._next_recv_cipher = None
        self._next_recv_blocksize = 0
        self._next_recv_mac = None
        self._next_recv_macsize = 0
        self._next_recv_etm = False
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
        self._enc_keysize_cs = None
        self._enc_keysize_sc = None
        self._enc_blocksize_cs = None
        self._enc_blocksize_sc = None

        self._mac_alg_cs = None
        self._mac_alg_sc = None
        self._mac_keysize_cs = None
        self._mac_keysize_sc = None
        self._mac_hashsize_cs = None
        self._mac_hashsize_sc = None

        self._etm_cs = False
        self._etm_sc = False

        self._cmp_alg_cs = None
        self._cmp_alg_sc = None
        self._cmp_after_auth_cs = False
        self._cmp_after_auth_sc = False

        self._next_service = None

        self._auth = None
        self._auth_in_progress = False
        self._auth_complete = False
        self._auth_methods = [b'none']
        self._username = None

        self._channels = {}
        self._next_recv_chan = 0

        self._pending_callbacks = []

        self._disconnected = False
        self._closing = False

    def _cleanup(self):
        if not self._closing:
            self._closing = True

            for channel in list(self._channels.values()):
                channel._process_connection_close()

            self._inpbuf = None
            self._recv_handler = None

            if not self._outbuf:
                self.close()

    def is_client(self):
        return not self._server

    def is_server(self):
        return self._server

    def readable(self):
        return True

    def handle_connect(self):
        self._start()

    def handle_read(self):
        data = self.recv(65536)
        if data and not self._closing:
            self._inpbuf += data
            try:
                while self._inpbuf and self._recv_handler():
                    pass
            except SSHError as err:
                self._disconnected = True
                self.handle_disconnect(err.code, err.reason, err.lang)
                self.disconnect(err.code, err.reason, err.lang)

    def writable(self):
        return self._outbuf

    def handle_write(self):
        sent = self.send(self._outbuf)
        self._outbuf = self._outbuf[sent:]

        if self._closing and not self._outbuf:
            self.close()

    def handle_error(self):
        exc = sys.exc_info()[1]
        if isinstance(exc, socket.error):
            self._disconnected = True
            self.handle_disconnect(DISC_CONNECTION_LOST, exc.args[1],
                                   DEFAULT_LANG)
            self.handle_close()
        else:
            super().handle_error()

    def handle_close(self):
        if not self._disconnected:
            self._disconnected = True
            self.handle_disconnect(DISC_CONNECTION_LOST, 'Connection lost',
                                   DEFAULT_LANG)

        self._cleanup()

    def _get_recv_chan(self):
        while self._next_recv_chan in self._channels:
            self._next_recv_chan = (self._next_recv_chan + 1) & 0xffffffff

        recv_chan = self._next_recv_chan
        self._next_recv_chan = (self._next_recv_chan + 1) & 0xffffffff

        return recv_chan

    def _send(self, data):
        """Send data to the SSH connection"""

        if not self._disconnected:
            self._outbuf += data

    def _start(self):
        """Start the SSH handshake"""

        from asyncssh import __version__

        version = b'SSH-2.0-AsyncSSH_' + __version__.encode('ascii')

        if self.is_client():
            self.client_version = version
        else:
            self.server_version = version

        self._send(version + b'\r\n')

    def _recv_version(self):
        idx = self._inpbuf.find(b'\n')
        if idx < 0:
            return False

        version = self._inpbuf[:idx]
        if version.endswith(b'\r'):
            version = version[:-1]

        self._inpbuf =  self._inpbuf[idx+1:]

        if (version.startswith(b'SSH-2.0-') or
            (self.is_client() and version.startswith(b'SSH-1.99-'))):
            # Accept version 2.0, or 1.99 if we're a client
            if self.is_server():
                self.client_version = version
            else:
                self.server_version = version

            self._send_kexinit()
            self._kexinit_sent = True
            self._recv_handler = self._recv_pkthdr
        elif self.is_client() and not version.startswith(b'SSH-'):
            # As a client, ignore the line if it doesn't appear to be a version
            pass
        else:
            # Otherwise, reject the unknown version
            self._disconnected = True
            self.handle_disconnect(DISC_PROTOCOL_ERROR, 'Unknown SSH version',
                                   DEFAULT_LANG)
            self._cleanup()
            return False

        return True

    def _recv_pkthdr(self):
        if len(self._inpbuf) < self._recv_blocksize:
            return False

        self._packet = self._inpbuf[:self._recv_blocksize]
        self._inpbuf = self._inpbuf[self._recv_blocksize:]

        if self._recv_cipher and not self._recv_etm:
            self._packet = self._recv_cipher.decrypt(self._packet)

        self._pktlen = int.from_bytes(self._packet[:4], byteorder='big')
        self._recv_handler = self._recv_packet
        return True

    def _recv_packet(self):
        rem = 4 + self._pktlen + self._recv_macsize - self._recv_blocksize
        if len(self._inpbuf) < rem:
            return False

        rest = self._inpbuf[:rem-self._recv_macsize]

        if self._recv_etm:
            self._packet += rest
            mac = self._inpbuf[rem-self._recv_macsize:rem]

            if self._recv_mac:
                if not self._recv_mac.verify(UInt32(self._recv_seq) +
                                             self._packet, mac):
                    raise SSHError(DISC_MAC_ERROR, 'MAC verification failed')

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
                    raise SSHError(DISC_MAC_ERROR, 'MAC verification failed')

            payload = self._packet[5:-self._packet[4]]

        self._inpbuf = self._inpbuf[rem:]

        if self._decompressor and (self._auth_complete or
                                   not self._decompress_after_auth):
            payload = self._decompressor.decompress(payload)

        packet = SSHPacket(payload)
        pkttype = packet.get_byte()

        if self._kex and MSG_KEX_FIRST <= pkttype <= MSG_KEX_LAST:
            if self._ignore_first_kex:
                self._ignore_first_kex = False
                processed = True
            else:
                processed = self._kex.process_packet(pkttype, packet)
        elif self._auth and MSG_USERAUTH_FIRST <= pkttype <= MSG_USERAUTH_LAST:
            processed = self._auth.process_packet(pkttype, packet)
        else:
            processed = self.process_packet(pkttype, packet)

        if not processed:
            self._send_packet(Byte(MSG_UNIMPLEMENTED), UInt32(self._recv_seq))

        if not self._closing:
            self._recv_seq = (self._recv_seq + 1) & 0xffffffff
            self._recv_handler = self._recv_pkthdr

        return True

    def _send_packet(self, *args):
        payload = b''.join(args)
        pkttype = payload[0]

        if (self._auth_complete and self._kex_complete and
            (self._rekey_bytes_sent >= self._rekey_bytes or
             time.time() >= self._rekey_time)):
            self._send_kexinit()
            self._kexinit_sent = True
            print('Rekey!')

        if (((pkttype in {MSG_SERVICE_REQUEST, MSG_SERVICE_ACCEPT} or
              pkttype > MSG_KEX_LAST) and not self._kex_complete) or
            (pkttype == MSG_USERAUTH_BANNER and not self._auth_in_progress) or
            (pkttype > MSG_USERAUTH_LAST and not self._auth_complete)):
            self._deferred_packets.append(payload)
            return

        # If we're encrypting and we have no data outstanding, insert an
        # ignore packet into the stream
        if self._send_cipher and not self._outbuf and payload[0] != MSG_IGNORE:
            self._send_packet(Byte(MSG_IGNORE), String(b''))

        if self._compressor and (self._auth_complete or
                                 not self._compress_after_auth):
            payload = self._compressor.compress(payload)

        hdrlen = 1 if self._send_etm else 5

        padlen = -(hdrlen + len(payload)) % self._send_blocksize
        if padlen < 4:
            padlen += self._send_blocksize

        packet = Byte(padlen) + payload + urandom(padlen)
        pktlen = len(packet)

        if self._send_etm:
            if self._send_cipher:
                packet = self._send_cipher.encrypt(packet)

            packet = UInt32(pktlen) + packet

            if self._send_mac:
                mac = self._send_mac.sign(UInt32(self._send_seq) + packet)
            else:
                mac = b''
        else:
            packet = UInt32(pktlen) + packet

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
        """Send packets deferred due to kex exchange or auth"""

        deferred_packets = self._deferred_packets
        self._deferred_packets = []

        for packet in deferred_packets:
            self._send_packet(packet)

    def _send_kexinit(self):
        """Start a kex exchange"""

        self._kex_complete = False
        self._rekey_bytes_sent = 0
        self._rekey_time = time.time() + self._rekey_seconds

        cookie = urandom(16)
        kex_algs = NameList(get_kex_algs())
        host_key_algs = NameList(self._get_server_host_key_algs())
        enc_algs = NameList(get_encryption_algs())
        mac_algs = NameList(get_mac_algs())
        cmp_algs = NameList(get_compression_algs())
        langs = NameList([])

        packet = b''.join((Byte(MSG_KEXINIT), cookie, kex_algs, host_key_algs,
                           enc_algs, enc_algs, mac_algs, mac_algs, cmp_algs,
                           cmp_algs, langs, langs, Boolean(False), UInt32(0)))

        if self.is_server():
            self.server_kexinit = packet
        else:
            self.client_kexinit = packet

        self._send_packet(packet)

    def _send_newkeys(self, k, h):
        """Finish a key exchange and send a new keys message"""

        if not self.session_id:
            self.session_id = h

        iv_cs = self._kex.compute_key(k, h, b'A', self.session_id,
                                      self._enc_blocksize_cs)
        iv_sc = self._kex.compute_key(k, h, b'B', self.session_id,
                                      self._enc_blocksize_sc)
        enc_key_cs = self._kex.compute_key(k, h, b'C', self.session_id,
                                           self._enc_keysize_cs)
        enc_key_sc = self._kex.compute_key(k, h, b'D', self.session_id,
                                           self._enc_keysize_sc)
        mac_key_cs = self._kex.compute_key(k, h, b'E', self.session_id,
                                           self._mac_keysize_cs)
        mac_key_sc = self._kex.compute_key(k, h, b'F', self.session_id,
                                           self._mac_keysize_sc)
        self._kex = None

        next_cipher_cs = get_cipher(self._enc_alg_cs, enc_key_cs, iv_cs)
        next_cipher_sc = get_cipher(self._enc_alg_sc, enc_key_sc, iv_sc)

        next_mac_cs = get_mac(self._mac_alg_cs, mac_key_cs)
        next_mac_sc = get_mac(self._mac_alg_sc, mac_key_sc)

        self._send_packet(Byte(MSG_NEWKEYS))

        if self.is_client():
            self._send_cipher = next_cipher_cs
            self._send_blocksize = max(8, self._enc_blocksize_cs)
            self._send_mac = next_mac_cs
            self._send_etm = self._etm_cs
            self._compressor = get_compressor(self._cmp_alg_cs)
            self._compress_after_auth = self._cmp_after_auth_cs

            self._next_recv_cipher = next_cipher_sc
            self._next_recv_blocksize = max(8, self._enc_blocksize_sc)
            self._next_recv_mac = next_mac_sc
            self._next_recv_macsize = self._mac_hashsize_sc
            self._next_recv_etm = self._etm_sc
            self._next_decompressor = get_decompressor(self._cmp_alg_sc)
            self._next_decompress_after_auth = self._cmp_after_auth_sc
        else:
            self._send_cipher = next_cipher_sc
            self._send_blocksize = max(8, self._enc_blocksize_sc)
            self._send_mac = next_mac_sc
            self._send_etm = self._etm_sc
            self._compressor = get_compressor(self._cmp_alg_sc)
            self._compress_after_auth = self._cmp_after_auth_sc

            self._next_recv_cipher = next_cipher_cs
            self._next_recv_blocksize = max(8, self._enc_blocksize_cs)
            self._next_recv_mac = next_mac_cs
            self._next_recv_macsize = self._mac_hashsize_cs
            self._next_recv_etm = self._etm_cs
            self._next_decompressor = get_decompressor(self._cmp_alg_cs)
            self._next_decompress_after_auth = self._cmp_after_auth_cs

            self._next_service = _USERAUTH_SERVICE

        self._kex_complete = True
        self._send_deferred_packets()

    def _send_service_request(self, service):
        self._next_service = service
        self._send_packet(Byte(MSG_SERVICE_REQUEST), String(service))

    def _send_userauth_request(self, method, *args, key=None):
        packet = b''.join((Byte(MSG_USERAUTH_REQUEST), String(self._username),
                           String(_CONNECTION_SERVICE), String(method)) + args)

        if key:
            packet += String(key.sign(String(self.session_id) + packet))

        self._send_packet(packet)

    def _send_userauth_failure(self, partial_success):
        self._auth = None
        self._send_packet(Byte(MSG_USERAUTH_FAILURE),
                          NameList(get_server_auth_methods(self)),
                          Boolean(partial_success))

    def _send_userauth_success(self):
        self._send_packet(Byte(MSG_USERAUTH_SUCCESS))
        self._auth = None
        self._auth_in_progress = False
        self._auth_complete = True

    def _send_global_request(self, request, *args, callback=None):
        """Send a global request"""

        if callback:
            self._pending_callbacks.append(callback)

        self._send_packet(Byte(MSG_GLOBAL_REQUEST), String(request),
                          Boolean(callback != None), *args)

    def _process_disconnect(self, pkttype, packet):
        """Process a disconnect message"""

        code = packet.get_uint32()
        reason = packet.get_string()
        lang = packet.get_string()
        packet.check_end()

        try:
            reason = reason.decode('utf-8')
            lang = lang.decode('ascii')
        except UnicodeDecodeError:
            raise SSHError(DISC_PROTOCOL_ERROR, 'Invalid disconnect message')

        self._disconnected = True
        self.handle_disconnect(code, reason, lang)
        self._cleanup()

    def _process_ignore(self, pkttype, packet):
        """Process an ignore message"""

        data = packet.get_string()
        packet.check_end()

        # Do nothing

    def _process_unimplemented(self, packet):
        """Process an unimplemented message response"""

        seq = packet.get_uint32()
        packet.check_end()

        # Ignore this

    def _process_debug(self, pkttype, packet):
        """Process a debug message"""

        always_display = packet.get_boolean()
        msg = packet.get_string()
        lang = packet.get_string()
        packet.check_end()

        try:
            msg = msg.decode('utf-8')
            lang = lang.decode('ascii')
        except UnicodeDecodeError:
            raise SSHError(DISC_PROTOCOL_ERROR, 'Invalid debug message')

        self.handle_debug(msg, lang, always_display)

    def _process_service_request(self, pkttype, packet):
        """Process a service request"""

        service = packet.get_string()
        packet.check_end()

        if service == self._next_service:
            self._next_service = None
            self._send_packet(Byte(MSG_SERVICE_ACCEPT), String(service))

            if self.is_server() and service == _USERAUTH_SERVICE:
                self._auth_in_progress = True
                self._send_deferred_packets()
        else:
            raise SSHError(DISC_SERVICE_NOT_AVAILABLE,
                           'Unexpected service request received')

    def _process_service_accept(self, pkttype, packet):
        """Process a service accept response"""

        service = packet.get_string()
        packet.check_end()

        if service == self._next_service:
            self._next_service = None

            if self.is_client() and service == _USERAUTH_SERVICE:
                self._auth_in_progress = True
                self._try_next_auth()
        else:
            raise SSHError(DISC_SERVICE_NOT_AVAILABLE,
                           'Unexpected service accept received')

    def _process_kexinit(self, pkttype, packet):
        """Process a key exchange request"""

        if self._kex:
            raise SSHError(DISC_PROTOCOL_ERROR,
                           'Key exchange already in progress')

        cookie = packet.get_bytes(16)
        kex_algs = packet.get_namelist()
        server_host_key_algs = packet.get_namelist()
        enc_algs_cs = packet.get_namelist()
        enc_algs_sc = packet.get_namelist()
        mac_algs_cs = packet.get_namelist()
        mac_algs_sc = packet.get_namelist()
        cmp_algs_cs = packet.get_namelist()
        cmp_algs_sc = packet.get_namelist()
        lang_cs = packet.get_namelist()
        lang_sc = packet.get_namelist()
        first_kex_follows = packet.get_boolean()
        reserved = packet.get_uint32()
        packet.check_end()

        if self.is_server():
            self.client_kexinit = packet.get_consumed_payload()

            if not self._choose_server_host_key(server_host_key_algs):
                raise SSHError(DISC_KEY_EXCHANGE_FAILED,
                               'Unable to find compatible server host key')
        else:
            self.server_kexinit = packet.get_consumed_payload()

        if self._kexinit_sent:
            self._kexinit_sent = False
        else:
            self._send_kexinit()

        self._kex = choose_kex_algorithm(self, kex_algs)
        self._ignore_first_kex = (first_kex_follows and
                                  self._kex.algorithm != kex_algs[0])

        self._enc_alg_cs, self._enc_keysize_cs, self._enc_blocksize_cs = \
            choose_encryption_algorithm(self, enc_algs_cs)
        self._enc_alg_sc, self._enc_keysize_sc, self._enc_blocksize_sc = \
            choose_encryption_algorithm(self, enc_algs_sc)

        self._mac_alg_cs, self._mac_keysize_cs, self._mac_hashsize_cs, \
            self._etm_cs = choose_mac_algorithm(self, mac_algs_cs)
        self._mac_alg_sc, self._mac_keysize_sc, self._mac_hashsize_sc, \
            self._etm_sc = choose_mac_algorithm(self, mac_algs_sc)

        self._cmp_alg_cs, self._cmp_after_auth_cs = \
            choose_compression_algorithm(self, cmp_algs_cs)
        self._cmp_alg_sc, self._cmp_after_auth_sc = \
            choose_compression_algorithm(self, cmp_algs_sc)

    def _process_newkeys(self, pkttype, packet):
        """Process a new keys message, finishing a key exchange"""

        packet.check_end()

        if self._next_recv_cipher:
            self._recv_cipher = self._next_recv_cipher
            self._recv_blocksize = self._next_recv_blocksize
            self._recv_mac = self._next_recv_mac
            self._recv_etm = self._next_recv_etm
            self._recv_macsize = self._next_recv_macsize
            self._decompressor = self._next_decompressor
            self._decompress_after_auth = self._next_decompress_after_auth

            self._next_recv_cipher = None
        else:
            raise SSHError(DISC_PROTOCOL_ERROR, 'New keys not negotiated')

        if self.is_client() and not (self._auth_in_progress or
                                     self._auth_complete):
            self._send_service_request(_USERAUTH_SERVICE)

    def _process_userauth_request(self, pkttype, packet):
        """Process a user authentication request"""

        username = packet.get_string()
        service = packet.get_string()
        method = packet.get_string()

        if service != _CONNECTION_SERVICE:
            raise SSHError(DISC_SERVICE_NOT_AVAILABLE,
                           'Unexpected service in auth request')

        try:
            username = saslprep(username.decode('utf-8'))
        except (UnicodeDecodeError, SASLPrepError):
            raise SSHError(DISC_PROTOCOL_ERROR, 'Invalid auth request message')

        if self.is_client():
            raise SSHError(DISC_PROTOCOL_ERROR, 'Unexpected userauth request')
        elif self._auth_complete:
            # Silent ignore requests if we're already authenticated
            pass
        else:
            if username != self._username:
                self._username = username

                if not self.begin_auth(username):
                    self._send_userauth_success()
                    return

            self._auth = lookup_server_auth(self, self._username,
                                            method, packet)

    def _process_userauth_failure(self, pkttype, packet):
        """Process a user authentication failure response"""

        self._auth_methods = packet.get_namelist()
        partial_success = packet.get_boolean()
        packet.check_end()

        if self.is_client() and self._auth:
            if partial_success:
                self._auth.handle_success()
            else:
                self._auth.handle_failure()

            self._try_next_auth()
        else:
            raise SSHError(DISC_PROTOCOL_ERROR, 'Unexpected userauth response')

    def _process_userauth_success(self, pkttype, packet):
        """Process a user authentication success response"""

        packet.check_end()

        if self.is_client() and self._auth:
            self._auth = None
            self._auth_in_progress = False
            self._auth_complete = True
            self._send_deferred_packets()
            self.handle_auth_complete()
        else:
            raise SSHError(DISC_PROTOCOL_ERROR, 'Unexpected userauth response')

    def _process_userauth_banner(self, pkttype, packet):
        """Process a user authentication banner message"""

        msg = packet.get_string()
        lang = packet.get_string()
        packet.check_end()

        try:
            msg = msg.decode('utf-8')
            lang = lang.decode('ascii')
        except UnicodeDecodeError:
            raise SSHError(DISC_PROTOCOL_ERROR, 'Invalid userauth banner')

        if self.is_client():
            self.handle_auth_banner(msg, lang)
        else:
            raise SSHError(DISC_PROTOCOL_ERROR, 'Unexpected userauth banner')

    def _process_global_request(self, pkttype, packet):
        """Process a global request"""

        request = packet.get_string()
        want_reply = packet.get_boolean()

        try:
            request = request.decode('ascii')
        except UnicodeDecodeError:
            raise SSHError(DISC_PROTOCOL_ERROR, 'Invalid global request')

        name = '_process_' + request.replace('-', '_') + '_request'
        handler = getattr(self, name, None)
        result = handler(packet) if callable(handler) else None

        if want_reply:
            if result:
                response = b'' if result == True else result
                self._send_packet(Byte(MSG_REQUEST_SUCCESS), response)
            else:
                self._send_packet(Byte(MSG_REQUEST_FAILURE))

    def _process_global_response(self, pkttype, packet):
        """Process a global response"""

        if self._pending_callbacks:
            callback = self._pending_callbacks.pop(0)
            callback(pkttype, packet)
        else:
            raise SSHError(DISC_PROTOCOL_ERROR, 'Unexpected global response')

    def _process_channel_open(self, pkttype, packet):
        """Process a channel open request"""

        chantype = packet.get_string()
        send_chan = packet.get_uint32()
        send_window = packet.get_uint32()
        send_pktsize = packet.get_uint32()

        try:
            chantype = chantype.decode('ascii')
        except UnicodeDecodeError:
            raise SSHError(DISC_PROTOCOL_ERROR, 'Invalid channel open request')

        try:
            name = '_process_' + chantype.replace('-', '_') + '_open'
            handler = getattr(self, name, None)
            if callable(handler):
                channel = handler(packet)
                channel._process_open(send_chan, send_window, send_pktsize,
                                      packet)
            else:
                raise ChannelOpenError(OPEN_UNKNOWN_CHANNEL_TYPE,
                                       'Unknown channel type')
        except ChannelOpenError as err:
            reason = err.reason.encode('utf-8')
            lang = err.lang.encode('ascii')
            self._send_packet(Byte(MSG_CHANNEL_OPEN_FAILURE), UInt32(send_chan),
                              UInt32(err.code), String(reason), String(lang))

    def _process_channel_open_confirmation(self, pkttype, packet):
        """Process a channel open confirmation response"""

        recv_chan = packet.get_uint32()
        send_chan = packet.get_uint32()
        send_window = packet.get_uint32()
        send_pktsize = packet.get_uint32()

        channel = self._channels.get(recv_chan)
        if channel:
            channel._process_open_confirmation(send_chan, send_window,
                                               send_pktsize, packet)
        else:
            raise SSHError(DISC_PROTOCOL_ERROR, 'Invalid channel number')

    def _process_channel_open_failure(self, pkttype, packet):
        """Process a channel open failure response"""

        recv_chan = packet.get_uint32()
        code = packet.get_uint32()
        reason = packet.get_string()
        lang = packet.get_string()
        packet.check_end()

        try:
            reason = reason.decode('utf-8')
            lang = lang.decode('ascii')
        except UnicodeDecodeError:
            raise SSHError(DISC_PROTOCOL_ERROR, 'Invalid channel open failure')

        channel = self._channels.get(recv_chan)
        if channel:
            channel._process_open_failure(code, reason, lang)
        else:
            raise SSHError(DISC_PROTOCOL_ERROR, 'Invalid channel number')

    def _process_channel_msg(self, pkttype, packet):
        """Process a channel-specific message"""

        recv_chan = packet.get_uint32()

        channel = self._channels.get(recv_chan)
        if channel:
            channel.process_packet(pkttype, packet)
        else:
            raise SSHError(DISC_PROTOCOL_ERROR, 'Invalid channel number')

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

    def disconnect(self, code=DISC_BY_APPLICATION,
                   reason='Disconnected by application', lang=DEFAULT_LANG):
        """Force the connection to close

           This method can be called to forcibly close the connection.

           :param integer code:
               The reason for the disconnect, from
               :ref:`disconnect reason codes <DisconnectReasons>`,
               defaulting to ``DISC_BY_APPLICATION``, indicating that it
               was an explicit disconnect by the application
           :param string reason:
               A human readable reason for the disconnect
           :param string lang:
               The language the reason is in

        """

        reason = reason.encode('utf-8')
        lang = lang.encode('ascii')
        self._send_packet(Byte(MSG_DISCONNECT), UInt32(code), String(reason),
                          String(lang))
        self._cleanup()

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
        self._send_packet(Byte(MSG_DEBUG), _Boolean(always_display),
                          String(msg), String(lang))

    def handle_disconnect(self, code, reason, lang):
        """Handle when the connection is closed

           This method is called when the connection is closed.
           Applications should implement this method if they want to
           do any processing or cleanup at the time of the close.
           The reason for the close is provided and can be either
           triggered by the application at the other end or as a
           result of some kind of error during SSH packet processing.

           By default, this method does nothing.

           :param integer code:
               The reason for the disconnect, from :ref:`disconnect
               reason codes <DisconnectReasons>`
           :param string reason:
               A human readable reason for the disconnect
           :param string lang:
               The language the reason is in

           .. note:: If the local application calls :meth:`disconnect`
                     explicitly, this method will not be called when the
                     connection is closed.

        """

        pass

    def handle_debug(self, msg, lang, always_display):
        """Handle a debug message on this connection

           This method is called when the other end of the connection sends
           a debug message. Applications should implement this method if
           they wish to process these debug messages.

           By default, this method does nothing.

           :param string msg:
               The debug message sent
           :param string lang:
               The language the message is in
           :param boolean always_display:
               Whether or not to display the message

        """

        pass

class SSHClient(_SSHConnection):
    """SSH client connection handler

       Applications should subclass this when implementing an SSH client.
       The *handle* functions listed below should be overridden to define
       application-specific behavior. In particular, the method
       :meth:`handle_auth_complete` should be defined to create the
       desired SSH client sessions for this connection once authentication
       is complete.

       For simple password or public key based authentication, the default
       implementation of the auth handlers here will probably suffice, as
       long as the password or client keys to use can be passed in when
       the object is created.

       If TCP connection forwarding is needed, calls should be made to the
       :meth:`listen` method to set up the listeners, and the
       :meth:`handle_listen`, :meth:`handle_listen_error`, and
       :meth:`handle_forwarded_connection` methods should be defined
       to process the results.

       :param addr:
           The server hostname/address and port to connect to. For
           convenience, this can be just a string containing the
           hostname or address when connecting to the default SSH port.
       :param server_host_keys: (optional)
           A list of public keys which will be accepted as a host key
           from the server. If this parameter is not provided, host
           keys for the server will be looked up in
           :file:`.ssh/known_hosts`.  If this is explicitly set to
           ``None``, server host key validation will be disabled.
       :param string username: (optional)
           Username to authenticate as on the server. If not specified,
           the currently logged in user on the local machine will be used.
       :param client_keys: (optional)
           A list of private keys which will be used to authenticate
           this client. If no client keys are specified, an attempt will
           be made to load them from the files :file:`.ssh/id_ecdsa`,
           :file:`.ssh/id_rsa`, and :file:`.ssh/id_dsa`. If this is
           explicitly set to ``None``, client public key authentication
           will not be performed.
       :param string password: (optional)
           The password to use for client password authentication or
           keyboard-interactive authentication which prompts for a password.
           If this is not specified, client password authentication will
           not be performed.
       :param integer rekey_bytes: (optional)
           The number of bytes which can be sent before the SSH session
           key is renegotiated. This defaults to 1 GB.
       :param integer rekey_seconds: (optional)
           The maximum time in seconds before the SSH session key is
           renegotiated. This defaults to 1 hour.
       :type addr: tuple of string and integer
       :type server_host_keys: *list of* :class:`SSHKey` *public keys*
       :type client_keys: *list of* :class:`SSHKey` *private keys*

    """

    def __init__(self, addr, server_host_keys=(), username=None,
                 client_keys=(), password=None,
                 rekey_bytes=_DEFAULT_REKEY_BYTES,
                 rekey_seconds=_DEFAULT_REKEY_SECONDS):
        if isinstance(addr, str):
            addr = (addr, _DEFAULT_PORT)

        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        super().__init__(sock, rekey_bytes, rekey_seconds, server=False)

        try:
            self.connect(addr)
        except socket.error as exc:
            self._disconnected = True
            self.handle_disconnect(DISC_CONNECTION_LOST, exc.args[1],
                                   DEFAULT_LANG)
            self.handle_close()
            return

        if server_host_keys is None:
            self._server_host_keys = None
        else:
            if server_host_keys is ():
                server_host_keys = self._parse_known_hosts(addr)

            self._server_host_keys = set()
            self._server_host_key_algs = []

            for key in server_host_keys:
                self._server_host_keys.add(key)
                if key.algorithm not in self._server_host_key_algs:
                    self._server_host_key_algs.append(key.algorithm)

        if username is None:
            username = getpass.getuser()

        self._username = saslprep(username)

        if client_keys:
            self._client_keys = list(client_keys)
        else:
            self._client_keys = []

            if client_keys is ():
                for file in _DEFAULT_KEY_FILES:
                    file = os.path.join(os.environ['HOME'], '.ssh', file)

                    try:
                        self._client_keys.append(read_private_key(file))
                    except (IOError, KeyImportError):
                        pass

        self._password = password
        self._pending_listen_requests = []

    def _parse_known_hosts(self, addr):
        server_host_keys = []

        try:
            lines = open(os.path.join(os.environ['HOME'], '.ssh',
                                      'known_hosts'), 'rb').readlines()
        except IOError:
            return []

        dest_host, dest_port = addr
        dest_host = dest_host.encode()

        for line in lines:
            hosts, key = line.split(None, 1)
            hosts = hosts.split(b',')
            for host in hosts:
                if b':' in host:
                    host, port = host.rsplit(b':', 1)
                    try:
                        port = int(port)
                    except ValueError:
                        continue
                else:
                    port = 22

                if host.startswith(b'[') and host.endswith(b']'):
                    host = host[1:-1]

                if host.lower() == dest_host.lower() and port == dest_port:
                    try:
                        server_host_keys.append(import_public_key(key))
                    except KeyImportError:
                        pass

                    break

        return server_host_keys

    def _get_server_host_key_algs(self):
        """Return the list of acceptable server host key algorithms"""

        if self._server_host_keys:
            return self._server_host_key_algs
        else:
            return get_public_key_algs()

    def _verify_server_host_key(self, server_host_key):
        """Verify the server's host key is in the server host key list"""

        if self._server_host_keys is None:
            return True
        else:
            return server_host_key in self._server_host_keys

    def _try_next_auth(self):
        """Attempt client authentication using the next compatible method"""

        self._auth = choose_client_auth(self)
        if not self._auth:
            raise SSHError(DISC_NO_MORE_AUTH_METHODS_AVAILABLE,
                           'Permission denied')

    def _process_session_open(self, packet):
        """Process an inbound session open request

           These requests are disallowed on an SSH client.

        """

        raise ChannelOpenError(OPEN_ADMINISTRATIVELY_PROHIBITED,
                               'Session open forbidden on client')

    def _process_direct_tcpip_open(self, packet):
        """Process an inbound direct TCP/IP channel open request

           These requests are disallowed on an SSH client.

        """

        raise ChannelOpenError(OPEN_ADMINISTRATIVELY_PROHIBITED,
                               'Direct TCP/IP open forbidden on client')

    def _process_tcpip_forward_response(self, pkttype, packet):
        """Process a response to a global TCP/IP forward request"""

        bind_addr, bind_port = self._pending_listen_requests.pop(0)

        if pkttype == MSG_REQUEST_SUCCESS:
            if not bind_port:
                bind_port = packet.get_uint32()

            packet.check_end()

            self.handle_listen(bind_addr, bind_port)
        else:
            packet.check_end()

            self.handle_listen_error(bind_addr, bind_port)

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
            raise SSHError(DISC_PROTOCOL_ERROR, 'Invalid channel open request')

        return self.handle_forwarded_connection(dest_host, dest_port,
                                                orig_host, orig_port)

    def handle_auth_banner(self, msg, lang):
        """Handle an incoming authentication banner

           This method is called when the server sends a banner to display
           during authentication. Applications should implement this method
           if they wish to do something with the banner.

           By default, this function ignores authentication banners.

           :param string msg:
               The message the server wanted to display
           :param string lang:
               The language the message is in

        """

        pass

    def handle_auth_complete(self):
        """Handle successful completion of authentication

           This method is called when authentication has completed
           succesfully. Applications should use this method to create
           whatever client sessions and direct TCP/IP connections are
           needed, and set up listeners for incoming TCP/IP connections
           needed from the server.

           By default, this function does nothing.

        """

        pass

    def handle_public_key_auth(self):
        """Handle public key authentication

           This method should return a client private key corresponding
           to the user that authentication is being attempted for. It
           may be called multiple times and can return a different key
           to try each time it is called. When there are no client keys
           left to try, it should return ``None`` to indicate that some
           other authentication method should be tried.

           By default, this will return each of the keys passed in the
           ``client_keys`` parameter provided when the :class:`SSHClient`
           object was created (if any) and return ``None`` when the list
           is exhausted.

           :rtype: :class:`SSHKey` private key or ``None``

        """

        if self._client_keys:
            return self._client_keys.pop(0)
        else:
            return None

    def handle_password_auth(self):
        """Handle password authentication

           This method should return a string containing the password
           corresponding to the user that authentication is being
           attempted for. It may be called multiple times and can
           return a different password to try each time, but most
           servers have a limit on the number of attempts allowed.
           When there's no password left to try, this method should
           return ``None`` to indicate that some other authentication
           method should be tried.

           By default, this will return the password passed in the
           ``password`` parameter provided when the :class:`SSHClient`
           object was created (if any) and then return ``None`` if it
           is called again.

           :rtype: string or ``None``

        """

        password = self._password
        self._password = None
        return password

    def handle_password_change_request(self, prompt, lang):
        """Handle a password change request

           This method is called when password authentication was
           attempted and the user's password was expired on the
           server. To request a password change, this method should
           return a tuple or two strings containing the old and new
           passwords. Otherwise, it should return ``NotImplemented``.

           By default, this method returns ``NotImplemented``.

           :param string prompt:
               The prompt requesting that the user enter a new password
           :param string lang:
               the language that the prompt is in

           :rtype: tuple of two strings or ``NotImplemented``

        """

        return NotImplemented

    def handle_password_change_successful(self):
        """Handle a successful password change

           This method is called to indicate that a requested password
           change was successful. It is generally followed by a call to
           :meth:`handle_auth_complete` since this means authentication
           was also successful.

           By default, this method does nothing.

        """

        pass

    def handle_password_change_failed(self):
        """Handle a failed password change

           This method is called to indicate that a requested password
           change failed, generally because the requested new password
           doesn't meet the password criteria on the remote system.
           After this method is called, other forms of authentication
           will automatically be attempted.

           By default, this method does nothing.

        """

        pass

    def handle_kbdint_auth(self):
        """Handle keyboard-interactive authentication

           This method should return a string containing a comma-separated
           list of submethods that the server should use for
           keyboard-interactive authentication. An empty string can be
           returned to let the server pick the type of keyboard-interactive
           authentication. If keyboard-interactive authentication is not
           supported, ``None`` should be returned.

           By default, keyboard-interactive authentication is supported
           if a password was provided when the :class:`SSHClient` was
           created and it hasn't been sent yet. If the challenge is not
           a password challenge, this authentication will fail. This
           method and the :meth:`handle_kbdint_challenge` method can be
           overridden if other forms of challenge should be supported.

           :rtype: string or ``None``

        """

        if self._password:
            return ''
        else:
            return None

    def handle_kbdint_challenge(self, name, instruction, lang, prompts):
        """Handle keyboard-interactive auth challenge

           This method is called when the server sends a keyboard-interactive
           authentication challenge.

           The return value should be a list of strings of the same length
           as the number of prompts provided if the challenge can be
           answered, or ``None`` to indicate that some other form of
           authentication should be attempted.

           By default, this method will look for a challenge consisting
           of a single 'Password:' prompt, and respond with whatever
           password was provided when the :class:`SSHClient` was created.
           It will also ignore challenges with no prompts (generally used
           to just provide instructions). Any other form of challenge will
           cause this method to return ``None``.

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

           :rtype: List of strings or ``None``

        """

        if len(prompts) == 0:
            # Silently drop any empty challenges used to print messages
            return []
        elif len(prompts) == 1 and prompts[0][0] == 'Password:':
            password = self.handle_password_auth()
            return [password] if password is not None else None
        else:
            return None

    def listen(self, bind_addr, bind_port):
        """Listen on a remote TCP/IP address and port

           This method can be called to request that the server listen
           on the specified remote address and port for incoming TCP
           connections. Once set up, connections received by the server
           will result in a call to the :meth:`handle_forwarded_connection`
           method to decide whether or not to accept them.

           If the listen request is successful, :meth:`handle_listen`
           will be called with the address and port the listener was
           opened on. If it fails, :meth:`handle_listen_error` will be
           called.

           :param string bind_addr:
               The address the server should listen on
           :param integer bind_port:
               The port the server should listen on, or the value ``0``
               to request that the server dynamically select a port

        """

        self._pending_listen_requests.append((bind_addr, bind_port))

        bind_addr = bind_addr.encode('utf-8')

        self._send_global_request(b'tcpip-forward',
                                  String(bind_addr), UInt32(bind_port),
                                  callback=self._process_tcpip_forward_response)

    def cancel_listen(self, bind_addr, bind_port):
        """Stop listening on a remote TCP/IP address and port

           This method can be called to request that the server shut down
           a listener previously set up on the specified remote address
           and port.

           :param string bind_addr:
               The address the server should stop listening on
           :param integer bind_port:
               The port the server should stop listening on

        """

        bind_addr = bind_addr.encode('utf-8')

        self._send_global_request(b'cancel-tcpip-forward',
                                  String(bind_addr), UInt32(bind_port))

    def handle_listen(self, bind_addr, bind_port):
        """Handle a successfully opened remote listener

           This method is called when a remote listener is successfully
           opened, reporting the address and port the remote listener
           was opened on.

           By default, this method does nothing.

           :param string bind_addr:
               The address the server is now listening on
           :param integer bind_port:
               The port the server is now listening on. If a ``0`` was
               passed in the :meth:`listen` call, the dynamically
               selected port will be provided here

        """

        pass

    def handle_listen_error(self, bind_addr, bind_port):
        """Handle a failure opening a remote listener

           This method is called when an attempt to open a remote
           listener fails, reporting back the requested address and
           port of the listener which wasn't opened.

           By default, this method does nothing.

           :param string bind_addr:
               The address the server was unable to listen on
           :param integer bind_port:
               The port the server was unable to listen on

        """

        pass

    def handle_forwarded_connection(self, dest_host, dest_port,
                                    orig_host, orig_port):
        """Handle a forwarded TCP/IP connection request

           This method is called when a forwarded TCP/IP connection
           request is received by the client. Applications wishing
           to accept such connections must override this method and have
           it return a class derived from :class:`SSHTCPConnection`
           which can process the data received on the channel.
           Otherwise, they should raise :exc:`ChannelOpenError` with
           the reason they are rejecting the connection. Connections
           can be selectively rejected based on the host and port
           information provided here.

           By default, all connections are rejected with an error code
           of ``OPEN_CONNECT_FAILED`` and a reason of "Connection
           refused".

           :param string dest_host:
               The address the connection was destined to
           :param integer dest_port:
               The port the connection was destined to
           :param string orig_host:
               The address the connection was originated from
           :param integer orig_port:
               The port the connection was originated from

           :rtype: subclass of :class:`SSHTCPConnection`

           :raises: :exc:`ChannelOpenError` if the connection shouldn't
                    be accepted

        """

        raise ChannelOpenError(OPEN_CONNECT_FAILED, 'Connection refused')


class SSHServer(_SSHConnection):
    """SSH server connection handler

       Applications should subclass this when implementing an SSH server.
       At a minimum, one or more of the authentication handlers will need
       to be overridden to perform authentication, or :meth:`begin_auth`
       should be overridden to return ``False`` to indicate that no
       authentication is required. In addition, one or more of the
       :meth:`handle_session`, :meth:`handle_direct_connection`, or
       :meth:`handle_listen` and :meth:`handle_cancel_listen`
       methods will need to be overridden to handle requests to open
       sessions or direct TCP/IP connections or set up listeners for
       forwarded TCP/IP connections.

       :param socket sock:
           An established TCP connection to begin an SSH server handshake on
       :param addr:
           A tuple containing IPv6 client address information, if available
       :param server_host_keys:
           A list of private keys which can be presented as host keys
           during the SSH handshake
       :param integer rekey_bytes: (optional)
           The number of bytes which can be sent before the SSH session
           key is renegotiated
       :param integer rekey_seconds: (optional)
           The maximum time in seconds before the SSH session key is
           renegotiated
       :type addr: *tuple of string and three integers or* ``None``
       :type server_host_keys: *list of* :class:`SSHKey` *private keys*

    """

    def __init__(self, sock, server_host_keys,
                 rekey_bytes=_DEFAULT_REKEY_BYTES,
                 rekey_seconds=_DEFAULT_REKEY_SECONDS):
        self._server_host_keys = OrderedDict()
        for key in server_host_keys:
            if key.algorithm in self._server_host_keys:
                raise ValueError('Multiple keys of type %s found' %
                                     key.algorithm.decode())

            self._server_host_keys[key.algorithm] = key

        if not self._server_host_keys:
            raise ValueError('No server host keys provided')

        super().__init__(sock, rekey_bytes, rekey_seconds, server=True)
        self._start()

    def _get_server_host_key_algs(self):
        """Return the list of acceptable server host key algorithms

           Return the algorithms which correspond to the available server
           host keys.

        """

        return self._server_host_keys.keys()

    def _choose_server_host_key(self, peer_host_key_algs):
        """Choose the server host key to use

           Given a list of host key algorithms supported by the client,
           select the first compatible server host key we have and return
           whether or not we were able to find a match.

        """

        for alg in peer_host_key_algs:
            if alg in self._server_host_keys:
                self.server_host_key = self._server_host_keys[alg]
                return True

        return False

    def _process_session_open(self, packet):
        packet.check_end()

        channel = self.handle_session()

        if not isinstance(channel, SSHServerSession):
            raise ValueError('Session must be subclass of SSHServerSession')

        return channel

    def _process_direct_tcpip_open(self, packet):
        dest_host = packet.get_string()
        dest_port = packet.get_uint32()
        orig_host = packet.get_string()
        orig_port = packet.get_uint32()
        packet.check_end()

        try:
            dest_host = dest_host.decode('utf-8')
            orig_host = orig_host.decode('utf-8')
        except UnicodeDecodeError:
            raise SSHError(DISC_PROTOCOL_ERROR, 'Invalid channel open request')

        channel = self.handle_direct_connection(dest_host, dest_port,
                                                orig_host, orig_port)

        if not isinstance(channel, SSHTCPConnection):
            raise ValueError('Session must be subclass of SSHTCPConnection')

        return channel

    def _process_tcpip_forward_request(self, packet):
        bind_addr = packet.get_string()
        bind_port = packet.get_uint32()
        packet.check_end()

        try:
            bind_addr = bind_addr.decode('utf-8')
        except UnicodeDecodeError:
            raise SSHError(DISC_PROTOCOL_ERROR, 'Invalid TCP forward request')

        result = self.handle_listen(bind_addr, bind_port)
        if result:
            result = UInt32(result) if bind_port == 0 else True

        return result

    def _process_cancel_tcpip_forward_request(self, packet):
        bind_addr = packet.get_string()
        bind_port = packet.get_uint32()
        packet.check_end()

        try:
            bind_addr = bind_addr.decode('utf-8')
        except UnicodeDecodeError:
            raise SSHError(DISC_PROTOCOL_ERROR, 'Invalid TCP forward request')

        return self.handle_cancel_listen(bind_addr, bind_port)

    def get_username(self):
        """Return the authenticated username, if any

           If authentication was performed successfully on this connection,
           this method returns the authenticated username. Otherwise, it
           returns ``None``.

           :rtype: string or ``None``

        """

        return self._username if self._auth_complete else None

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

           :raises: :exc:`IOError` if authentication is already completed

        """

        if self._auth_complete:
            raise IOError('Authentication already completed')

        msg = msg.encode('utf-8')
        lang = lang.encode('ascii')
        self._send_packet(Byte(MSG_USERAUTH_BANNER), String(msg), String(lang))

    def begin_auth(self, username):
        """Begin authentication of a user

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

           :rtype: boolean

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

           :rtype: boolean

        """

        return False

    def validate_public_key(self, username, key):
        """Return whether key is an authorized client key for this user

           This method should return ``True`` if the specified key is a
           valid client key for the user being authenticated. It must
           be overridden by applications wishing to support client public
           key authentication.

           This method may be called multiple times with different keys
           provided by the client. Applications should determine the list
           of valid client keys in the :meth:`begin_auth` method so that
           this function can quickly return whether the key provided is
           in the list.

           By default, this method returns ``False`` for all client keys.

           :param string username:
               The user being authenticated
           :param key:
               The public key sent by the client
           :type key: :class:`SSHKey` *public key*

           :rtype: boolean

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

           :rtype: boolean

        """

        return False

    def validate_password(self, username, password):
        """Return whether password is valid for this user

           This method should return ``True`` if the specified password
           is a valid password for the user being authenticated. It must
           be overridden by applications wishing to support password
           authentication.

           This method may be called multiple times with different
           passwords provided by the client. Applications may wish
           to limit the number of attempts which are allowed. This
           can be done by having :meth:`password_auth_supported` begin
           returning ``False`` after the maximum number of attempts is
           exceeded.

           By default, this method returns ``False`` for all passwords.

           :param string username:
               The user being authenticated
           :param string password:
               The password sent by the client

           :rtype: boolean

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

           By default, keyboard-interactive authentication is supported if
           password authentication is supported, with the default challenge
           being a single prompt for 'Password:' and the validation based
           on :meth:`validate_password`. If an application already supports
           password authentication, they'll automatically support this
           authentication as well unless they explicitly disable it by
           overriding this method.

           :rtype: boolean

        """

        return self.password_auth_supported()

    def get_kbdint_challenge(self, username, lang, submethods):
        """Return a keyboard-interactive auth challenge

           This method should return ``True`` if authentication should
           succeed without any challenge, ``False`` if authentication
           should fail without any challenge, or an auth challenge
           consisting of a challenge name, instructions, a language tag,
           and a list of tuples containing prompt strings and booleans
           indicating whether input should be echoed when a value is
           entered for that prompt.

           By default, this method will return a single 'Password:'
           prompt if password authentication is supported. Otherwise, it
           will return ``False`` causing the authentication to fail.

           :param string username:
               The user being authenticated
           :param string lang:
               The language requested by the client for the challenge
           :param string submethods:
               A comma-separated list of the types of challenges the client
               can support, or the empty string if the server should choose

           :rtype: See above

        """

        if self.password_auth_supported():
            return '', '', DEFAULT_LANG, (('Password:', False),)
        else:
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

           By default, this method will attempt to do password validation
           on the response returned.

           :param string username:
               The user being authenticated
           :param responses:
               A list of responses to the last challenge
           :type responses: list of strings

           :rtype: ``True``, ``False``, or another challenge

        """

        return len(responses) == 1 and \
               self.validate_password(username, responses[0])

    def handle_session(self):
        """Handle an incoming session request

           This method is called when a session open request is received
           from the client, indicating it wishes to open a channel to be
           used for running a shell, executing a command, or connecting
           to a subsystem. If they wish to accept the session,
           applications must override this method and return a class
           derived from :class:`SSHServerSession` which can be used to
           process the data received on the channel Otherwise, they
           should raise :exc:`ChannelOpenError` with the reason they
           are rejecting the session.

           The details of what the client wants to start on the channel
           will be delivered to methods on the :class:`SSHServerSession`
           object which is returned, along with other information such
           as environment vairables, terminal type, and window size.

           By default, all sessions are rejected with an error code
           of ``OPEN_CONNECT_FAILED`` and a reason of "Connection
           refused".

           :rtype: subclass of :class:`SSHServerSession`

           :raises: :exc:`ChannelOpenError` if the session shouldn't
                    be accepted

        """

        raise ChannelOpenError(OPEN_CONNECT_FAILED, 'Connection refused')

    def handle_direct_connection(self, dest_host, dest_port,
                                 orig_host, orig_port):
        """Handle a direct TCP/IP connection request

           This method is called when a direct TCP/IP connection
           request is received by the server. Applications wishing
           to accept such connections must override this method and have
           it return a class derived from :class:`SSHTCPConnection`
           which can process the data received on the channel.
           Otherwise, they should raise :exc:`ChannelOpenError` with
           the reason they are rejecting the connection. Connections
           can be selectively rejected based on the host and port
           information provided here.

           By default, all connections are rejected with an error code
           of ``OPEN_CONNECT_FAILED`` and a reason of "Connection
           refused".

           :param string dest_host:
               The address the client wishes to connect to
           :param integer dest_port:
               The port the client wishes to connect to
           :param string orig_host:
               The address the connection was originated from
           :param integer orig_port:
               The port the connection was originated from

           :rtype: subclass of :class:`SSHTCPConnection`

           :raises: :exc:`ChannelOpenError` if the connection shouldn't
                    be accepted

        """

        raise ChannelOpenError(OPEN_CONNECT_FAILED, 'Connection refused')

    def handle_listen(self, bind_addr, bind_port):
        """Handle a request to listen on a TCP/IP address and port

           This method is called when a client makes a request to
           listen on an address and port for incoming TCP connections.
           Applications wishing to allow TCP/IP forwarding must
           override this method and return ``True`` to accept or
           ``False`` to reject such requests.

           Once set up, the application can create objects derived
           from :class:`SSHTCPConnection` for each connection it wishes
           to forward and call :meth:`accept() <SSHTCPConnection.accept>`
           on them to deliver data back to the client.

           By default, this method rejects all listen requests.

           :param string bind_addr:
               The address the server should listen on
           :param integer bind_port:
               The port the server should listen on, or the value ``0``
               to request that the server dynamically select a port

           :rtype: boolean

        """

        return False

    def handle_cancel_listen(self, bind_addr, bind_port):
        """Handle a request to stop listening on a TCP/IP address and port

           This method is called when a client makes a request to stop
           listening on an address and port for incoming TCP connections.
           Applications wishing to allow TCP/IP forwarding must
           override this method and return ``True`` to acknowledge
           the request to stop listening or ``False`` to indicate that
           there was no listener to stop.

           By default, this method rejects all requests to stop listening.

           :param string bind_addr:
               The address the application should stop listening on
           :param integer bind_port:
               The port the application should stop listening on

        """

        return False


class SSHListener(asyncore.dispatcher):
    """SSH listener

       This is a helper class which can be wrapped around subclasses of
       :class:`SSHServer` to listen for incoming connections and
       automatically instantiate a new instance of the server as each
       connection arrives. The listen address can be either an address
       and port tuple or just the port to listen on all interfaces.

       :param listen_addr:
           The address and port to listen on
       :param class server_class:
           The server class to instantiate when new connections arrive
       :type listen_addr: tuple of string and integer, or just integer

       .. note:: The arguments passed to the server class are a socket
                 and the client address, which are not the same as the
                 arguments expected by :class:`SSHServer`. Programs
                 using SSHListener will need to provide an __init__
                 method in their class which removes the address and
                 adds the server host keys to use along with any other
                 appropriate arguments.

    """

    def __init__(self, listen_addr, server_class, *args, **kwargs):
        asyncore.dispatcher.__init__(self)

        if not issubclass(server_class, SSHServer):
            raise ValueError('Server class must be a subclass of SSHServer')

        if isinstance(listen_addr, int):
            listen_addr = ('', listen_addr)

        self._server_class = server_class
        self._server_args = args
        self._server_kwargs = kwargs

        self.create_socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind(listen_addr)
        self.listen(5)

    def handle_accepted(self, sock, addr):
        """Handle a new incoming SSH connection"""

        self._server_class(sock, addr)
