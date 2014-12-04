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

AsyncSSH is a Python package which provides an asynchronous client and
server implementation of the SSHv2 protocol on top of the Python asyncio
framework. It requires Python 3.4 or later and either the PyCA library or
the PyCrypto library for some cryptographic functions.

"""

from os import path
from setuptools import setup, find_packages

from version import __author__, __author_email__, __url__, __version__

doclines = __doc__.split('\n', 1)
readme = path.join(path.abspath(path.dirname(__file__)), 'README.rst')

with open(readme) as desc:
    long_description = desc.read()

setup(name = 'asyncssh',
      version = __version__,
      author = __author__,
      author_email = __author_email__,
      url = __url__,
      download_url = __url__ + 'asyncssh-%s.tar.gz' % __version__,
      license = 'Eclipse Public License v1.0',
      description = doclines[0],
      long_description = long_description,
      platforms = 'Any',
      extras_require = {
          'pycrypto': ['pycrypto >= 2.6'],
          'pyca':     ['cryptography >= 0.6.1']
      },
      packages = ['asyncssh', 'asyncssh.crypto', 'asyncssh.crypto.pyca',
                  'asyncssh.crypto.pycrypto'],
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
