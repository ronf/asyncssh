#!/usr/bin/env python3.4

# Copyright (c) 2013-2014 by Ron Frederick <ronf@timeheart.net>.
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

"""AsyncSSH: Asynchronous SSHv2 client and server library

This package provides an asynchronous client and server implementation of
the SSHv2 protocol, based on the Python asyncio framework. It depends on
Python 3.4 or later and the PyCrypto library for some cryptographic functions.

"""

from setuptools import setup, find_packages
import asyncssh

doclines = __doc__.split("\n", 1)

setup(name = 'asyncssh',
      version = asyncssh.__version__,
      author = asyncssh.__author__,
      author_email = asyncssh.__author_email__,
      url = asyncssh.__url__,
      download_url = asyncssh.__url__ + 'asyncssh-%s.tar.gz' %
                         asyncssh.__version__,
      license = 'Eclipse Public License v1.0',
      description = doclines[0],
      long_description = doclines[1],
      platforms = 'Any',
      requires = ['Crypto (>= 2.6)'],
      packages = ['asyncssh'],
      scripts = [],
      test_suite = 'tests',
      classifiers = [
          'Development Status :: 3 - Alpha',
          'Environment :: Console',
          'Intended Audience :: Developers',
          'License :: OSI Approved',
          'Operating System :: MacOS :: MacOS X',
          'Operating System :: POSIX',
          'Programming Language :: Python :: 3.4',
          'Topic :: Internet',
          'Topic :: Security :: Cryptography',
          'Topic :: Software Development :: Libraries :: Python Modules',
          'Topic :: System :: Networking'])
