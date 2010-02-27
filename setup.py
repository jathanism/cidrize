#!/usr/bin/env python
# -*- coding: utf-8 -*-

from distutils.core import setup
import os
import sys

from cidrize import __version__

if sys.version_info[:2] < (2, 4):
    print "This package requires Python 2.4+. Sorry!"
    sys.exit(-11)

setup(
    name = 'cidrize',
    version = __version__,
    url = 'http://bitbucket.org/jathanism/cidrize',
    download_url = 'http://bitbucket.org/jespern/django-piston/downloads/',
    license = 'BSD',
    description = "Cidrize takes IP addresses, CIDRs, ranges, and wildcard matches & attempts return a valid list of IP addresses that can be worked with.",
    author = 'Jathan McCollum',
    author_email = 'jathan+bitbucket@gmail.com',
    py_modules = ['cidrize'],
    keywords = [
            'Networking', 'Systems Administration', 'IANA', 'IEEE', 'CIDR', 'IP',
            'IPv4', 'IP Address', 'Firewalls', 'Security',
    ],
    classifiers = [
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Environment :: Plugins',
        'Intended Audience :: Developers',
        'Intended Audience :: Education',
        'Intended Audience :: Information Technology',
        'Intended Audience :: Science/Research',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Telecommunications Industry',
        'Natural Language :: English',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Education :: Testing',
        'Topic :: Internet',
        'Topic :: Internet :: Name Service (DNS)',
        'Topic :: Software Development',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Networking',
        'Topic :: System :: Networking :: Firewalls',
        'Topic :: System :: Networking :: Monitoring',
        'Topic :: System :: Operating System',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ]
)
