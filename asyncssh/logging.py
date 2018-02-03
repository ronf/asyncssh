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
#     Sam Crooks - initial implementation
#     Ron Frederick - minor cleanup

"""Logging functions"""

import logging


class _SSHLogger(logging.LoggerAdapter):
    """Adapter to add context to AsyncSSH log messages"""

    _debug_level = 1
    _pkg_logger = logging.getLogger(__package__)

    def __init__(self, parent=_pkg_logger, child=None, context=''):
        self._context = context
        self._logger = parent.getChild(child) if child else parent

        super().__init__(self._logger, {})

    def _extend_context(self, context):
        """Extend context provided by this logger"""

        if context:
            if self._context:
                context = self._context + ', ' + context
        else:
            context = self._context

        return context

    def get_child(self, child=None, context=None):
        """Return child logger with optional added context"""

        return type(self)(self._logger, child, self._extend_context(context))

    def log(self, level, msg, *args, **kwargs):
        """Log a message to the underlying logger"""

        def _text(arg):
            """Convert a log argument to text"""

            if isinstance(arg, list):
                sep = b',' if arg and isinstance(arg[0], bytes) else ','
                arg = sep.join(arg)

            if isinstance(arg, tuple):
                host, port = arg

                if host:
                    return '%s, port %d' % (host, port) if port else host
                else:
                    return 'port %d' % port if port else 'dynamic port'
            elif isinstance(arg, bytes):
                arg = arg.decode('ascii', errors='replace')

            return arg

        args = [_text(arg) for arg in args]

        return super().log(level, msg, *args, **kwargs)

    def process(self, msg, kwargs):
        """Add context to log message"""

        extra = kwargs.get('extra', {})

        context = self._extend_context(extra.get('context'))
        context = '[' + context + '] ' if context else ''

        packet = extra.get('packet')
        pktdata = ''
        offset = 0

        while packet:
            line = '\n  %08x:' % offset

            for b in packet[:16]:
                line += ' %02x' % b

            line += (62 - len(line)) * ' '

            for b in packet[:16]:
                if b < 0x20 or b >= 0x80:
                    c = '.'
                elif b == ord('%'):
                    c = '%%'
                else:
                    c = chr(b)

                line += c

            pktdata += line

            packet = packet[16:]
            offset += 16

        return context + msg + pktdata, kwargs

    @classmethod
    def set_debug_level(cls, level):
        """Set AsyncSSH debug log level"""

        if level < 1 or level > 3:
            raise ValueError('Debug log level must be between 1 and 3')

        cls._debug_level = level

    def debug1(self, msg, *args, **kwargs):
        """Write a level 1 debug log message"""

        self.debug(msg, *args, **kwargs)

    def debug2(self, msg, *args, **kwargs):
        """Write a level 2 debug log message"""

        if self._debug_level >= 2:
            self.debug(msg, *args, **kwargs)

    def packet(self, pktid, packet, msg, *args, **kwargs):
        """Write a control packet debug log message"""

        if self._debug_level >= 3:
            kwargs.setdefault('extra', {})

            if pktid is not None:
                kwargs['extra'].update(context='pktid=%d' % pktid)

            kwargs['extra'].update(packet=packet)

            self.debug(msg, *args, **kwargs)


def set_log_level(level):
    """Set the AsyncSSH log level

       This function sets the log level of the AsyncSSH logger. It
       defaults to `'NOTSET`', meaning that it will track the debug
       level set on the root Python logger.

       For additional control over the level of debug logging, see the
       function :func:`set_debug_level` for additional information.

       :param level:
           The log level to set, as defined by the `logging` module
       :type level: `int` or `str`

    """

    logger.setLevel(level)


def set_sftp_log_level(level):
    """Set the AsyncSSH SFTP/SCP log level

       This function sets the log level of the AsyncSSH SFTP/SCP logger.
       It defaults to `'NOTSET`', meaning that it will track the debug
       level set on the main AsyncSSH logger.

       For additional control over the level of debug logging, see the
       function :func:`set_debug_level` for additional information.

       :param level:
           The log level to set, as defined by the `logging` module
       :type level: `int` or `str`

    """

    sftp_logger.setLevel(level)


def set_debug_level(level):
    """Set the AsyncSSH debug log level

       This function sets the level of debugging logging done by the
       AsyncSSH logger, from the following options:

           ===== ====================================
           Level Description
           ===== ====================================
           1     Minimal debug logging
           2     Full debug logging
           3     Full debug logging with packet dumps
           ===== ====================================

       The debug level defaults to level 1 (minimal debug logging).

       .. note:: For this setting to have any effect, the effective log
                 level of the AsyncSSH logger must be set to DEBUG.

       .. warning:: Extreme caution should be used when setting debug
                    level to 3, as this can expose user passwords in
                    clear text. This level should generally only be
                    needed when tracking down issues with malformed
                    or incomplete packets.

       :param level:
           The debug level to set, as defined above.
       :type level: `int`

    """

    logger.set_debug_level(level)


logger = _SSHLogger()
sftp_logger = logger.get_child('sftp')
