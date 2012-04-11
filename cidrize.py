#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'Jathan McCollum'
__email__ = 'jathan@gmail.com'
__version__ = '0.6'

"""
Intelligently parse IPv4/IPv6 addresses, CIDRs, ranges, and wildcard matches to
attempt return a valid list of IP addresses. It's smart enough to fix bad
network boundaries for you.

The cidrize() function is the public interface. The module may also be run
interactively for debugging purposes.
"""

import itertools
import logging
from netaddr import (AddrFormatError, IPAddress, IPGlob, IPNetwork, IPRange,
        IPSet, spanning_cidr)
import os
import re
import socket
import sys

# Globals
EVERYTHING = ['internet at large', '*', 'all', 'any', 'internet', '0.0.0.0',
              '0.0.0.0/0', '0.0.0.0-255.255.255.255']
MAX_RANGE_LEN = 16384 # This is a /18

# Setup logging
DEBUG = os.getenv('DEBUG', False)
LOG_LEVEL = logging.INFO
LOG_FORMAT = "%(asctime)s [%(levelname)s]: %(message)s"
if DEBUG:
    LOG_LEVEL = logging.DEBUG

logging.basicConfig(level=LOG_LEVEL, format=LOG_FORMAT)
log = logging

# Pre-compiled re patterns. You know, for speed!
cidr_re = re.compile(r"\d+\.\d+\.\d+\.\d+(?:\/\d+)?$")
range_re = re.compile(r"\d+\.\d+\.\d+\.\d+\-\d+\.\d+\.\d+\.\d+$")
glob_re = re.compile(r"\d+\.\d+\.\d+\.\*$")
bracket_re = re.compile(r"(.*?)\.(\d+)[\[\{\(](.*)[\)\}\]]$") # parses '1.2.3.4[5-9]' or '1.2.3.[57]'
hyphen_re = re.compile(r"(.*?)\.(\d+)\-(\d+)$")
hostname_re = re.compile(r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?)', re.IGNORECASE)


# Exports
__all__ = ('cidrize', 'CidrizeError', 'dump', 'normalize_address',
           'optimize_network_usage', 'parse_range', 'is_ipv6')


# Exceptions
class CidrizeError(AddrFormatError): pass
class NotCIDRStyleError(CidrizeError): pass
class NotRangeStyleError(CidrizeError): pass
class NotGlobStyleError(CidrizeError): pass
class NotBracketStyleError(CidrizeError): pass


# Functions
def parse_brackets(text):
    """
    Best effort to break down UNIX wildcard style ranges like
    "1.2.3.1[18-21]" into octets append use first & last numbers of
    bracketed range as the min/max of the 4th octet.

    This is assuming we'll only ever see [x-y] style ranges in the 4th octet.

    Returns an IPRange object.

    :param text: The string to parse
    """
    match = bracket_re.match(text)
    if match is None:
        return None

    parts = match.groups()
    # '1.2.3.4[5-9] style
    log.debug('parse_brackets() parts: %r' % (parts,))
    if len(parts) == 3:
        prefix, subnet, enders = parts
        network = '.'.join((prefix, subnet))

    # '1.2.3.[5-9] style
    elif len(parts) == 2:
        prefix, enders = parts
        network = prefix + '.'

    else:
        raise NotBracketStyleError("Bracketed style not parseable: '%s'" % text)

    # Split hyphenated [x-y]
    if '-' in enders:
        first, last = enders.split('-')

    # Get first/last from [xy] - This really only works with single
    # digits
    elif len(enders) >= 2:
        # Creating a set and sorting to ensure that [987] won't throw
        # an exception. Might be too inclusive, but screw it.
        uniques = sorted(set(enders))
        first = uniques[0]
        last = uniques[-1]

    return IPRange(network + first, network + last)

def parse_hyphen(text):
    """
    Parses a hyphen in the last octet, e.g. '1.2.3.4-70'

    :param text: The string to parse
    """
    match = hyphen_re.match(text)
    if match is None:
        return None

    parts = match.groups()
    prefix, start, finish = parts
    network = prefix + '.'

    return IPRange(network + start, network + finish)

def parse_range(ipstr):
    """
    Given a hyphenated range of IPs, return an IPRange object

    :param ipstr: The hyphenated IP range
    """

    start, finish = ipstr.split('-')
    ip = IPRange(start, finish)
    log.debug('parse_range_style() start: %r' % start)
    log.debug('parse_range_style() finish: %r' % finish)
    log.debug('parse_range_style() ip: %r' % ip)

    return ip

def parse_commas(ipstr, **kwargs):
    """
    This will break up a comma-separated input string of assorted inputs, run them through
    cidrize(), flatten the list, and return the list. If any item in the list
    fails, it will allow the exception to pass through as if it were parsed
    individually. All objects must parse or nothing is returned.

    Example:

    :param ipstr: A comma-separated string of IP address patterns.
    """
    # Clean whitespace before we process
    ipstr = ipstr.replace(' ', '').strip()
    items = ipstr.split(',')

    # Possibly nested depending on input, so we'll run it thru itertools.chain
    # to flatten it. Then we make it a IPSet to optimize adjacencies and finally
    # return the list of CIDRs within the IPSet
    ipiter = (cidrize(ip, **kwargs) for ip in items)
    flatiter = itertools.chain.from_iterable(ipiter)
    ipset = IPSet(flatiter)

    return ipset.iter_cidrs()

def is_ipv6(ipstr):
    """
    Checks whether a string is IPv6 or not. Doesn't handle addresses with
    CIDR notation, but that's ok.

    Credit: Joe Hildebrand
    Ref: http://stackoverflow.com/a/81899/194311

    :param ipstr: A suspected IPv6 address
    """
    log.debug('is_ipv6() got: %r' % ipstr)
    try:
        socket.inet_pton(socket.AF_INET6, ipstr)
        return True
    except socket.error:
        return False

def cidrize(ipstr, strict=False, modular=True):
    """
    This function tries to determine the best way to parse IP addresses correctly & has
    all the logic for trying to do the right thing!

    Input can be several formats:
        '192.0.2.18'
        '192.0.2.64/26'
        '192.0.2.80-192.0.2.85'
        '192.0.2.170-175'
        '192.0.2.8[0-5]'
        '192.0.2.[0-29]'
        '192.168.4.6[1234]'
        '1.2.3.*'
        '192.0.2.170-175, 192.0.2.80-192.0.2.85, 192.0.2.64/26'

    Hyphenated ranges do not need to form a CIDR block. Netaddr does most of
    the heavy lifting for us here.

    Input can NOT be:
        192.0.2.0 0.0.0.255 (hostmask)
        192.0.2.0 255.255.255.0 (netmask)

    Does NOT accept network or host mask notation at this time!

    Returns a list of consolidated netaddr objects.

    Defaults:
        * parsing exceptions will raise a CidrizeError (modular=True).
        * results will be returned as a spanning CIDR (strict=False).

    :param ipstr: IP string to be parsed.
    :param modular: Set to False to cause exceptions to be stripped & the error text will be
    returned as a list. This is intended for use with scripts or APIs out-of-the box.

    Example:
        >>> import cidrize as c
        >>> c.cidrize('1.2.3.4-1.2.3.1099')
        Traceback (most recent call last):
          File "<stdin>", line 1, in <module>
          File "/home/j/jathan/sandbox/cidrize.py", line 153, in cidrize
            raise CidrizeError(err)
        cidrize.CidrizeError: base address '1.2.3.1099' is not IPv4

        >>> c.cidrize('1.2.3.4-1.2.3.1099', modular=False)
        ["base address '1.2.3.1099' is not IPv4"]

    :param strict: Set to True to return explicit networks based on start/end addresses.

    Example:
        >>> import cidrize as c
        >>> c.cidrize('1.2.3.4-1.2.3.10')
        [IPNetwork('1.2.3.0/28')]

        >>> c.cidrize('1.2.3.4-1.2.3.10', strict=True)
        [IPNetwork('1.2.3.4/30'), IPNetwork('1.2.3.8/31'), IPNetwork('1.2.3.10/32')]

    """
    ip = None

    # Short-circuit to parse commas since it calls back here anyway
    if ',' in ipstr:
        return parse_commas(ipstr, strict=strict, modular=modular)

    # Short-circuit for hostnames (we're assuming first char is alpha)
    if hostname_re.match(ipstr):
        raise CidrizeError('Cannot parse hostnames!')

    # Otherwise try everything else
    result = None
    try:
        # Parse "everything" & immediately return; strict/loose doesn't apply
        if ipstr in EVERYTHING:
            log.debug("Trying everything style...")
            return [IPNetwork('0.0.0.0/0')]

        # Parse old-fashioned CIDR notation & immediately return; strict/loose doesn't apply
        # Now with IPv6!
        elif cidr_re.match(ipstr) or is_ipv6(ipstr):
            log.debug("Trying CIDR style...")
            ip = IPNetwork(ipstr)
            return [ip.cidr]

        # Parse 1.2.3.118-1.2.3.121 range style
        elif range_re.match(ipstr):
            log.debug("Trying range style...")
            result = parse_range(ipstr)

        # Parse 1.2.3.4-70 hyphen style
        elif hyphen_re.match(ipstr):
            log.debug("Trying hyphen style...")
            result = parse_hyphen(ipstr)

        # Parse 1.2.3.* glob style
        elif glob_re.match(ipstr):
            log.debug("Trying glob style...")
            ipglob = IPGlob(ipstr)
            result = spanning_cidr(ipglob)

        # Parse 1.2.3.4[5-9] or 1.2.3.[49] bracket style as a last resort
        elif bracket_re.match(ipstr):
            log.debug("Trying bracket style...")
            result = parse_brackets(ipstr)

        # If result still isn't set, let's see if it's IPv6??
        elif result is None:
            log.debug("Trying bare IPv6 parse...")
            result  = IPNetwork(ipstr)

        # This will probably fail 100% of the time. By design.
        else:
            raise CidrizeError("Could not determine parse style for '%s'" % ipstr)

        # If it's a single host, just return it wrapped in a list
        if result.size == 1:
            log.debug("Returning a single host!")
            return [result.cidr]

        # Logic to honor strict/loose, except IPRange. Doing a spanning_cidr on
        # an IPRange can be super slow if the range is large (such as a /8), so
        # IPRange objects larger than MAX_RANGE_LEN will always be strict.
        if not strict:
            if isinstance(result, IPRange) and result.size >= MAX_RANGE_LEN:
                log.debug('IPRange objects larger than /18 will always be strict.')
                return result.cidrs()
            return [spanning_cidr(result)]
        else:
            try:
                return result.cidrs() # IPGlob and IPRange have .cidrs()
            except AttributeError as err:
                #return result.cidr    # IPNetwork has .cidr
                return result.cidrs()  # PyLint thinks this is IPRange

    except (AddrFormatError, TypeError, ValueError) as err:
        if modular:
            raise CidrizeError(err)
        return [str(err)]

def optimize_network_range(ipstr, threshold=0.9, verbose=DEBUG):
    """
    Parses the input string and then calculates the subnet usage percentage. If over
    the threshold it will return a loose result, otherwise it returns strict.

    :param ipstr: IP string to be parsed.
    :param threshold: The percentage of the network usage required to return a
    loose result.
    :param verbose: Toggle verbosity.

    Example of default behavior using 0.9 (90% usage) threshold:
        >>> import cidrize
        >>> cidrize.optimize_network_range('10.20.30.40-50', verbose=True)
        Subnet usage ratio: 0.34375; Threshold: 0.9
        Under threshold, IP Parse Mode: STRICT
        [IPNetwork('10.20.30.40/29'), IPNetwork('10.20.30.48/31'), IPNetwork('10.20.30.50/32')]

    Example using a 0.3 (30% threshold):
        >>> import cidrize
        >>> cidrize.optimize_network_range('10.20.30.40-50', threshold=0.3, verbose=True)
        Subnet usage ratio: 0.34375; Threshold: 0.3
        Over threshold, IP Parse Mode: LOOSE
        [IPNetwork('10.20.30.32/27')]

    """
    if threshold > 1 or threshold < 0:
        raise CidrizeError('Threshold must be from 0.0 to 1.0')

    # Can't optimize 0.0.0.0/0!
    if ipstr in EVERYTHING:
        return cidrize(ipstr)

    loose = IPSet(cidrize(ipstr))
    strict = IPSet(cidrize(ipstr, strict=True))
    ratio = float(len(strict)) / float(len(loose))

    if verbose:
        print 'Subnet usage ratio: %s; Threshold: %s' % (ratio, threshold)

    if ratio >= threshold:
        if verbose:
            print 'Over threshold, IP Parse Mode: LOOSE'
        result = loose.iter_cidrs()
    else:
        if verbose:
            print 'Under threshold, IP Parse Mode: STRICT'
        result = strict.iter_cidrs()

    return result

def output_str(ipobj, sep=', '):
    """
    Returns a character-separated string of constituent CIDR blocks for a given
    IP object (should support both IPy and netaddr objects).

    :param ipobj: An IP address object
    :param sep: The separator used to join the string together
    """
    return sep.join([str(x) for x in ipobj])

def normalize_address(ipstr):
    """
    Attempts to cleanup an IP address that is in a non-standard format such
    as u'092.123.154.009', so that it can be properly parsed by netaddr or
    IPy.

    :param ipstr: An IP address string
    """
    data = ipstr.split('/')
    cidr = '32'
    if len(data) == 1:
        myip = data[0]
    elif len(data) == 2:
        myip, cidr = data
    else:
        return ipstr

    octets = (int(i) for i in myip.split('.'))
    ip = '.'.join([str(o) for o in octets])
    return '{0}/{1}'.format(ip, cidr)

def netaddr_to_ipy(iplist):
    """
    Turns a list of netaddr.IPNetwork objects into IPy.IP objects. Useful
    for interoperation with old code. If IPy is not available, the input is
    returned as-is.

    :param iplist: A list of netaddr.IPNetwork objects
    """
    try:
        import IPy
    except ImportError:
        return iplist

    if not isinstance(iplist, list):
        return iplist

    return [IPy.IP(str(x)) for x in iplist]

def dump(cidr):
    """
    Dumps a lot of info about a CIDR.
    """
    # Copy original cidr for usage later
    orig_cidr = cidr[:]

    # Flatten it for ops
    if len(cidr) == 1:
        cidr = cidr[0]
    else:
        cidr = spanning_cidr(cidr)

    # Is this a /32 or /128?
    single = (cidr.size == 1)

    log.debug('dump(): Single? %r' % single)
    log.debug('dump(): Got? %r' % cidr)

    ip_first = IPAddress(cidr.first)
    ip_firsthost = ip_first if single else cidr.iter_hosts().next()
    ip_gateway = IPAddress(cidr.last - 1)
    ip_bcast = cidr.broadcast
    ip_netmask = cidr.netmask
    ip_hostmask = cidr.hostmask
    num_hosts = 1 if single else (cidr.last - 1) - cidr.first

    out  = ''
    out += "Information for %s\n\n" % cidr
    out += "IP Version:\t\t%s\n" %  cidr.version
    out += "Spanning CIDR:\t\t%s\n" % cidr
    out += "Block Start/Network:\t%s\n" % ip_first
    out += "1st host:\t\t%s\n" % ip_firsthost
    out += "Gateway:\t\t%s\n" % ip_gateway
    out += "Block End/Broadcast:\t%s\n" % ip_bcast
    out += "DQ Mask:\t\t%s\n" % ip_netmask
    out += "Cisco ACL Mask:\t\t%s\n" % ip_hostmask
    out += "# of hosts:\t\t%s\n" % num_hosts
    out += "Explicit CIDR blocks:\t%s\n" % output_str(orig_cidr)

    return out

def parse_args(argv):
    """Parses args."""
    from optparse import OptionParser
    parser = OptionParser(usage='%prog [-v] [-d] [ip network]', add_help_option=0, description='''\
Cidrize parses IP address notation and returns valid CIDR blocks. If you want
debug output set the DEBUG environment variable.''')

    parser.add_option('-h', '--help', action="store_false")
    parser.add_option('-v', '--verbose', action='store_true',
        help='Be verbose with user-friendly output. Lots of detail.')

    notes = """
    Intelligently take IPv4 addresses, CIDRs, ranges, and wildcard matches to attempt
    return a valid list of IP addresses that can be worked with. Will automatically
    fix bad network boundries if it can.

    Input can be several formats:

        '192.0.2.18'
        '192.0.2.64/26'
        '192.0.2.80-192.0.2.85'
        '192.0.2.170-175'
        '192.0.2.8[0-5]'
        '192.0.2.[0-29]'
        '192.168.4.6[1234]'
        '1.2.3.*'
        '192.0.2.170-175, 192.0.2.80-192.0.2.85, 192.0.2.64/26'

    Hyphenated ranges do not need to form a CIDR block. Netaddr does most of
    the heavy lifting for us here.

    Input can NOT be (yet):

        192.0.2.0 0.0.0.255 (hostmask)
        192.0.2.0 255.255.255.0 (netmask)

    Does NOT accept network or host mask notation.
    """
    opts, args = parser.parse_args(argv)

    def phelp():
        """I help."""
        parser.print_help()
        print notes

    if opts.help or len(args) == 1:
        phelp()
        sys.exit('ERROR: You must specify an ip address. See usage information above!!')
    else:
        opts.ip = args[1]

    if ',' in opts.ip:
        phelp()
        sys.exit("ERROR: Comma-separated arguments aren't supported!")

    return opts, args

def main():
    """
    Used by the 'cidr' command that is bundled with the package.
    """
    opts, args = parse_args(sys.argv)

    log.debug('OPTS: %r' % opts)
    log.debug('ARGS: %r' % args)

    ipstr = opts.ip

    try:
        cidr = cidrize(ipstr, modular=False)
        if cidr:
            if opts.verbose:
                print dump(cidr),
            else:
                print output_str(cidr)
    except IndexError:
        return -1

if __name__ == '__main__':
    sys.exit(main())
