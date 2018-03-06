# Copyright (c) 2013-2018 by Ron Frederick <ronf@timeheart.net>.
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

"""SSH packet encoding and decoding functions"""

from .misc import plural


class PacketDecodeError(ValueError):
    """Packet decoding error"""


def Byte(value):
    """Encode a single byte"""

    return bytes((value,))


def Boolean(value):
    """Encode a boolean value"""

    return Byte(bool(value))


def UInt32(value):
    """Encode a 32-bit integer value"""

    return value.to_bytes(4, 'big')


def UInt64(value):
    """Encode a 64-bit integer value"""

    return value.to_bytes(8, 'big')


def String(value):
    """Encode a byte string or UTF-8 string value"""

    if isinstance(value, str):
        value = value.encode('utf-8', errors='strict')

    return len(value).to_bytes(4, 'big') + value


def MPInt(value):
    """Encode a multiple precision integer value"""

    l = value.bit_length()
    l += (l % 8 == 0 and value != 0 and value != -1 << (l - 1))
    l = (l + 7) // 8

    return l.to_bytes(4, 'big') + value.to_bytes(l, 'big', signed=True)


def NameList(value):
    """Encode a comma-separated list of byte strings"""

    return String(b','.join(value))


class SSHPacket:
    """Decoder class for SSH packets"""

    def __init__(self, packet):
        self._packet = packet
        self._idx = 0
        self._len = len(packet)

    def __bool__(self):
        return self._idx != self._len

    def check_end(self):
        """Confirm that all of the data in the packet has been consumed"""

        if self:
            raise PacketDecodeError('Unexpected data at end of packet')

    def get_consumed_payload(self):
        """Return the portion of the packet consumed so far"""

        return self._packet[:self._idx]

    def get_remaining_payload(self):
        """Return the portion of the packet not yet consumed"""

        return self._packet[self._idx:]

    def get_full_payload(self):
        """Return the full packet"""

        return self._packet

    def get_bytes(self, size):
        """Extract the requested number of bytes from the packet"""

        if self._idx + size > self._len:
            raise PacketDecodeError('Incomplete packet')

        value = self._packet[self._idx:self._idx+size]
        self._idx += size
        return value

    def get_byte(self):
        """Extract a single byte from the packet"""

        return self.get_bytes(1)[0]

    def get_boolean(self):
        """Extract a boolean from the packet"""

        return bool(self.get_byte())

    def get_uint32(self):
        """Extract a 32-bit integer from the packet"""

        return int.from_bytes(self.get_bytes(4), 'big')

    def get_uint64(self):
        """Extract a 64-bit integer from the packet"""

        return int.from_bytes(self.get_bytes(8), 'big')

    def get_string(self):
        """Extract a UTF-8 string from the packet"""

        return self.get_bytes(self.get_uint32())

    def get_mpint(self):
        """Extract a multiple precision integer from the packet"""

        return int.from_bytes(self.get_string(), 'big', signed=True)

    def get_namelist(self):
        """Extract a comma-separated list of byte strings from the packet"""

        namelist = self.get_string()
        return namelist.split(b',') if namelist else []


class SSHPacketLogger:
    """Parent class for SSH packet loggers"""

    _handler_names = {}

    @property
    def logger(self):
        """The logger to use for packet logging"""

        raise NotImplementedError

    def _log_packet(self, msg, pkttype, pktid, packet, note):
        """Log a sent/received packet"""

        if isinstance(packet, SSHPacket):
            packet = packet.get_full_payload()

        try:
            name = '%s (%d)' % (self._handler_names[pkttype], pkttype)
        except KeyError:
            name = 'packet type %d' % pkttype

        count = plural(len(packet), 'byte')

        if note:
            note = ' (%s)' % note

        self.logger.packet(pktid, packet, '%s %s, %s%s',
                           msg, name, count, note)

    def log_sent_packet(self, pkttype, pktid, packet, note=''):
        """Log a sent packet"""

        self._log_packet('Sent', pkttype, pktid, packet, note)


    def log_received_packet(self, pkttype, pktid, packet, note=''):
        """Log a received packet"""

        self._log_packet('Received', pkttype, pktid, packet, note)


class SSHPacketHandler(SSHPacketLogger):
    """Parent class for SSH packet handlers"""

    _packet_handlers = {}

    @property
    def logger(self):
        """The logger associated with this packet handler"""

        raise NotImplementedError

    def process_packet(self, pkttype, pktid, packet):
        """Log and process a received packet"""

        if pkttype in self._packet_handlers:
            self._packet_handlers[pkttype](self, pkttype, pktid, packet)
            return True
        else:
            return False
