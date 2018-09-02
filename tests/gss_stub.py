# Copyright (c) 2017-2018 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Stub GSS module for unit tests"""


def step(host, token):
    """Perform next step in GSS authentication"""

    complete = False

    if token == b'errtok':
        return token, complete
    elif ((token is None and 'empty_init' in host) or
          (token == b'1' and 'empty_continue' in host)):
        return b'', complete
    elif token == b'0':
        if 'continue_token' in host:
            token = b'continue'
        else:
            complete = True
            token = b'extra' if 'extra_token' in host else None
    elif token:
        token = bytes((token[0]-1,))
    else:
        token = host[0].encode('ascii')

    if token == b'0':
        if 'step_error' in host:
            return (b'errtok' if 'errtok' in host else b'error'), complete

        complete = True

    return token, complete
