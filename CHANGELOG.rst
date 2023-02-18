=========
Changelog
=========

2.1.0 - 2023-02-17
==================

- Dropped Python 3.7 support
- Fix #16 - Bumped max loose prefix length to /16
- Fix #12 - Added `-s/--strict` argument to CLI command
- Fix #11 - Added v6 wildcard support

2.0.0 - 2021-03-03
==================

- Python3 required
- Python2 dropped
- Implemented black and pytest and pylint
- Switched from setuptools + ``setup.py`` to Poetry + ``pyproject.toml``

0.6.5 - 2015-08-11
==================

- Fixed a bug with IPv6 and large netmasks like /64. The cidrize function
  now returns immediately with the correct result rather than looping
  eternally. Added test case.
- Also fixed the failing ipv6 test case

0.6.4 - 2013-02-12
==================

- Fixed a bug when calling socket.inet_pton on Windows machines, which is not
  available. For Windows we'll just fallback to the "last resort" IPv6 parsing
  using netaddr.IPNetwork.

0.6.3 - 2012-06-22
==================

- Fixed a bug when using optimize_network_range on wildcard patterns (issue #1)

0.6.2 - 2012-04-18
==================

- Version is currently stored in setup.py and cidrize.py now, because if
  netaddr wasn't installed, cidrize install actually fails. How novel!

0.6.1 - 2012-04-11
==================

- Added LICENSE.rst (BSD 3-clause)
- Updated requirement to netaddr>=0.7.6
- Removed download_url from setup.py
- Other housekeeping within setup.py

0.6 - 2012-04-10
================

- IPv6 addresses are now supported!
- Enhanced dump output to display IP version
- Cleaned up formatting in README.rst
- All debug printing replaced with logging module (hint: set environment
  variable DEBUG=1)
- Bugfix to bracket-style in which patterns with brackets not in 4th octet were
  sometimes matching.
- Bugfix when returning strict results on parse styles that return IPRange
  objects (bracket, hyphen styles). If an IPRange is larger than the hard-coded
  limit of a /18, then it will always be strict.
- All changes covered by tests.

0.5.6 - 2011-10-19
==================

- Optimization to range style parsing to improve speed on parsing large ranges
  (such as /8).

0.5.5 - 2011-09-08
==================

- Add ValueError to exceptions caught in cidrize() for wrapping with CidrizeError
- removed `ip = IPAddress` assignment when 'ip' was only used twice. unnecessary.
- Grammer ficks to docstrings
- Remove copyright

0.5.4 - 2011-06-07
==================

- Add ValueError to exceptions caught in cidrize() for wrapping with CidrizeError

0.5.3 - 2011-06-01
==================

- Collapsed bracket parsing RE into same pattern
- More descriptive var name in parse_commas()

0.5.2 - 2011-05-17
==================

- Reworked the way bracket parsing works; removed PyParsing as a dependency
  (too slow)
- Broke hyphenated (4th octect only) parsing into its own function

0.5.1 - 2011-05-03
==================

- Fixed a bug in cidrize() when hostnames were passed in.  Now explicitly
  checking for hostnames and raising an exception. 
- Added a test for this.

0.5 - 2011-04-29
================

- Added a feature to parse a comma-separted input string. New parse_commas()
  function to do this.
- Modified most parsing methods to accept strict vs. loose parsing except where
  it doesn't make sense (e.g. CIDR will always be strict).
- Added optimize_network_range() to do exactly that based on a specified usage
  ratio.

0.4.1 - 2010-09-21
==================

- Re-arranged parsing order inside of cidrize(); will now parse EVERYTHING FIRST.
- Added '0.0.0.0-255.255.255.255' to EVERYTHING

0.4 - 2010-07-15
================

- Added normalize_address() to cleanup non-standard IP strings (e.g. unicode).
- Added normalize_address to __all__.
- Added netaddr_to_ipy() to turn a list of netaddr objects into IPy objects.
- cidrize() can now translate keywords such as "any" or "internet" into 0.0.0.0/0.
- cidrize() now defaults to loose parsing & will return a spanning CIDR; you may 
  negate this behavior by passing strict=True.

0.3.1 - 2010-05-01
==================

- Added unittests, however weak they may be.

0.3 - 2010-05-01
================

- Added real argument parsing using optparse.
- Added dump() function for use with verbose output display.
- main() can be imported as easy command-line interface to cidrize functionality.
- Added command-line tool 'cidr' as proof-of-concept for main().
- General cleanup.

0.2 - 2010-02-26
================

- cidrize() always returns a list upon successful parsing.
- CidrError exception raised on errors by default. (modular=True).
- Exceptions can be silenced and returned as a list of errors (modular=False).
- Added CidrizeError to __all__
- No longer importing * from netaddr/pyparsing.
- Added examples/ipaddr.py which I am using in a web app for strict validation.
- Improved docstrings.
- Implemented setup.py.

0.1 - 2010-02-19
================

- Initial release       
