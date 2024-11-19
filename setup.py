#!/usr/bin/env python3.6

# Copyright (c) 2013-2022 by Ron Frederick <ronf@timeheart.net> and others.
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

from os import path
from setuptools import setup

base_dir = path.abspath(path.dirname(__file__))

with open(path.join(base_dir, 'asyncssh', 'version.py')) as version:
    exec(version.read())

setup(author = __author__,
      author_email = __author_email__,
      url = __url__)
