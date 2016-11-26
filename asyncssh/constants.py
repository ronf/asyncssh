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

"""SSH constants"""

# pylint: disable=bad-whitespace

# Default language for error messages
DEFAULT_LANG                        = 'en-US'

# SSH message codes
MSG_DISCONNECT                      = 1
MSG_IGNORE                          = 2
MSG_UNIMPLEMENTED                   = 3
MSG_DEBUG                           = 4
MSG_SERVICE_REQUEST                 = 5
MSG_SERVICE_ACCEPT                  = 6
MSG_EXT_INFO                        = 7

MSG_KEXINIT                         = 20
MSG_NEWKEYS                         = 21

MSG_KEX_FIRST                       = 30
MSG_KEX_LAST                        = 49

MSG_USERAUTH_REQUEST                = 50
MSG_USERAUTH_FAILURE                = 51
MSG_USERAUTH_SUCCESS                = 52
MSG_USERAUTH_BANNER                 = 53

MSG_USERAUTH_FIRST                  = 60
MSG_USERAUTH_LAST                   = 79

MSG_GLOBAL_REQUEST                  = 80
MSG_REQUEST_SUCCESS                 = 81
MSG_REQUEST_FAILURE                 = 82

MSG_CHANNEL_OPEN                    = 90
MSG_CHANNEL_OPEN_CONFIRMATION       = 91
MSG_CHANNEL_OPEN_FAILURE            = 92
MSG_CHANNEL_WINDOW_ADJUST           = 93
MSG_CHANNEL_DATA                    = 94
MSG_CHANNEL_EXTENDED_DATA           = 95
MSG_CHANNEL_EOF                     = 96
MSG_CHANNEL_CLOSE                   = 97
MSG_CHANNEL_REQUEST                 = 98
MSG_CHANNEL_SUCCESS                 = 99
MSG_CHANNEL_FAILURE                 = 100

# SSH disconnect reason codes
DISC_HOST_NOT_ALLOWED_TO_CONNECT    = 1
DISC_PROTOCOL_ERROR                 = 2
DISC_KEY_EXCHANGE_FAILED            = 3
DISC_RESERVED                       = 4
DISC_MAC_ERROR                      = 5
DISC_COMPRESSION_ERROR              = 6
DISC_SERVICE_NOT_AVAILABLE          = 7
DISC_PROTOCOL_VERSION_NOT_SUPPORTED = 8
DISC_HOST_KEY_NOT_VERIFYABLE        = 9
DISC_CONNECTION_LOST                = 10
DISC_BY_APPLICATION                 = 11
DISC_TOO_MANY_CONNECTIONS           = 12
DISC_AUTH_CANCELLED_BY_USER         = 13
DISC_NO_MORE_AUTH_METHODS_AVAILABLE = 14
DISC_ILLEGAL_USER_NAME              = 15

# SSH channel open failure reason codes
OPEN_ADMINISTRATIVELY_PROHIBITED    = 1
OPEN_CONNECT_FAILED                 = 2
OPEN_UNKNOWN_CHANNEL_TYPE           = 3
OPEN_RESOURCE_SHORTAGE              = 4

# Internal failure reason codes
OPEN_REQUEST_X11_FORWARDING_FAILED  = 0xfffffffd
OPEN_REQUEST_PTY_FAILED             = 0xfffffffe
OPEN_REQUEST_SESSION_FAILED         = 0xffffffff

# SSH file transfer packet types
FXP_INIT                            = 1
FXP_VERSION                         = 2
FXP_OPEN                            = 3
FXP_CLOSE                           = 4
FXP_READ                            = 5
FXP_WRITE                           = 6
FXP_LSTAT                           = 7
FXP_FSTAT                           = 8
FXP_SETSTAT                         = 9
FXP_FSETSTAT                        = 10
FXP_OPENDIR                         = 11
FXP_READDIR                         = 12
FXP_REMOVE                          = 13
FXP_MKDIR                           = 14
FXP_RMDIR                           = 15
FXP_REALPATH                        = 16
FXP_STAT                            = 17
FXP_RENAME                          = 18
FXP_READLINK                        = 19
FXP_SYMLINK                         = 20
FXP_STATUS                          = 101
FXP_HANDLE                          = 102
FXP_DATA                            = 103
FXP_NAME                            = 104
FXP_ATTRS                           = 105
FXP_EXTENDED                        = 200
FXP_EXTENDED_REPLY                  = 201

# SSH file transfer open flags
FXF_READ                            = 0x00000001
FXF_WRITE                           = 0x00000002
FXF_APPEND                          = 0x00000004
FXF_CREAT                           = 0x00000008
FXF_TRUNC                           = 0x00000010
FXF_EXCL                            = 0x00000020

# SSH file transfer attribute flags
FILEXFER_ATTR_SIZE                  = 0x00000001
FILEXFER_ATTR_UIDGID                = 0x00000002
FILEXFER_ATTR_PERMISSIONS           = 0x00000004
FILEXFER_ATTR_ACMODTIME             = 0x00000008
FILEXFER_ATTR_EXTENDED              = 0x80000000
FILEXFER_ATTR_UNDEFINED             = 0x7ffffff0

# OpenSSH statvfs attribute flags
FXE_STATVFS_ST_RDONLY               = 0x1
FXE_STATVFS_ST_NOSUID               = 0x2

# SSH file transfer error codes
FX_OK                               = 0
FX_EOF                              = 1
FX_NO_SUCH_FILE                     = 2
FX_PERMISSION_DENIED                = 3
FX_FAILURE                          = 4
FX_BAD_MESSAGE                      = 5
FX_NO_CONNECTION                    = 6
FX_CONNECTION_LOST                  = 7
FX_OP_UNSUPPORTED                   = 8

# SSH channel data type codes
EXTENDED_DATA_STDERR                = 1

# SSH pty mode opcodes
PTY_OP_END                          = 0
PTY_VINTR                           = 1
PTY_VQUIT                           = 2
PTY_VERASE                          = 3
PTY_VKILL                           = 4
PTY_VEOF                            = 5
PTY_VEOL                            = 6
PTY_VEOL2                           = 7
PTY_VSTART                          = 8
PTY_VSTOP                           = 9
PTY_VSUSP                           = 10
PTY_VDSUSP                          = 11
PTY_VREPRINT                        = 12
PTY_WERASE                          = 13
PTY_VLNEXT                          = 14
PTY_VFLUSH                          = 15
PTY_VSWTCH                          = 16
PTY_VSTATUS                         = 17
PTY_VDISCARD                        = 18
PTY_IGNPAR                          = 30
PTY_PARMRK                          = 31
PTY_INPCK                           = 32
PTY_ISTRIP                          = 33
PTY_INLCR                           = 34
PTY_IGNCR                           = 35
PTY_ICRNL                           = 36
PTY_IUCLC                           = 37
PTY_IXON                            = 38
PTY_IXANY                           = 39
PTY_IXOFF                           = 40
PTY_IMAXBEL                         = 41
PTY_IUTF8                           = 42
PTY_ISIG                            = 50
PTY_ICANON                          = 51
PTY_XCASE                           = 52
PTY_ECHO                            = 53
PTY_ECHOE                           = 54
PTY_ECHOK                           = 55
PTY_ECHONL                          = 56
PTY_NOFLSH                          = 57
PTY_TOSTOP                          = 58
PTY_IEXTEN                          = 59
PTY_ECHOCTL                         = 60
PTY_ECHOKE                          = 61
PTY_PENDIN                          = 62
PTY_OPOST                           = 70
PTY_OLCUC                           = 71
PTY_ONLCR                           = 72
PTY_OCRNL                           = 73
PTY_ONOCR                           = 74
PTY_ONLRET                          = 75
PTY_CS7                             = 90
PTY_CS8                             = 91
PTY_PARENB                          = 92
PTY_PARODD                          = 93
PTY_OP_ISPEED                       = 128
PTY_OP_OSPEED                       = 129
PTY_OP_RESERVED                     = 160
