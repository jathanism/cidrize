#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'Jathan McCollum'
__email__ = 'jathan+github@gmail.com'
__version__ = '0.5.6'

"""
Intelligently take IPv4 addresses, CIDRs, ranges, and wildcard matches to
attempt return a valid list of IP addresses that can be worked with. Will
automatically fix bad network boundries if it can.

The cidrize() function is the public interface. The module may also be run
interactively for debugging purposes.
"""

import itertools
from netaddr import (AddrFormatError, IPAddress, IPGlob, IPNetwork, IPRange,
        IPSet, spanning_cidr)
import re
import sys

# Setup
DEBUG = False
EVERYTHING = ['internet at large', '*', 'all', 'any', 'internet', '0.0.0.0',
              '0.0.0.0/0', '0.0.0.0-255.255.255.255']

# Pre-compiled re patterns. You know, for speed!
cidr_re = re.compile(r"\d+\.\d+\.\d+\.\d+(?:\/\d+)?$")
range_re = re.compile(r"\d+\.\d+\.\d+\.\d+\-\d+\.\d+\.\d+\.\d+$")
glob_re = re.compile(r"\d+\.\d+\.\d+\.\*$")
bracket_re = re.compile(r"(.*?)\.(\d+)[\[\{\(](.*)[\)\}\]]") # parses '1.2.3.4[5-9]' or '1.2.3.[57]'
hyphen_re = re.compile(r"(.*?)\.(\d+)\-(\d+)$")
hostname_re = re.compile(r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?)', re.IGNORECASE)

# Exports
__all__ = ('cidrize', 'CidrizeError', 'dump', 'normalize_address',
           'optimize_network_usage')


# Awesome exceptions
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
    """
    match = bracket_re.match(text)
    if match is None:
        return None

    parts = match.groups()
    # '1.2.3.4[5-9] style
    if len(parts) == 3:
        if DEBUG:
            print parts

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
    """
    match = hyphen_re.match(text)
    if match is None:
        return

    parts = match.groups()
    prefix, start, finish = parts
    network = prefix + '.'

    return IPRange(network + start, network + finish)

def parse_commas(ipstr, **kwargs):
    """
    This will break up a comma-separated input string of assorted inputs, run them through
    cidrize(), flatten the list, and return the list. If any item in the list
    fails, it will allow the exception to pass through as if it were parsed
    individually. All objects must parse or nothing is returned.

    Example:

    @param ipstr: A comma-separated string of IP address patterns.
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

    @param ipstr: IP string to be parsed.
    @param modular: Set to False to cause exceptions to be stripped & the error text will be
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

    @param strict: Set to True to return explicit networks based on start/end addresses.

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
    try:
        # Parse "everything" & immediately return; strict/loose doesn't apply
        if ipstr in EVERYTHING:
            if DEBUG:
                print "Trying everything style..."

            return [IPNetwork('0.0.0.0/0')]

        # Parse old-fashioned CIDR notation & immediately return; strict/loose doesn't apply
        elif cidr_re.match(ipstr):
            if DEBUG:
                print "Trying CIDR style..."

            ip = IPNetwork(ipstr)
            return [ip.cidr]

        # Parse 1.2.3.118-1.2.3.121 range style
        elif range_re.match(ipstr):
            if DEBUG:
                print "Trying range style..."

            start, finish = ipstr.split('-')
            ip = IPRange(start, finish)
            if DEBUG:
                print ' start:', start
                print 'finish:', finish
                print ip

            result = ip

        # Parse 1.2.3.4-70 hyphen style
        elif hyphen_re.match(ipstr):
            if DEBUG:
                print "Trying hypnen style..."
            result = parse_hyphen(ipstr)

        # Parse 1.2.3.* glob style
        elif glob_re.match(ipstr):
            if DEBUG:
                print "Trying glob style..."
            ipglob = IPGlob(ipstr)
            result = spanning_cidr(ipglob)

        # Parse 1.2.3.4[5-9] or 1.2.3.[49] bracket style as a last resort
        elif bracket_re.match(ipstr):
            if DEBUG:
                print "Trying bracket style..."
            result = parse_brackets(ipstr)

        # This will probably fail 100% of the time. By design.
        else:
            raise CidrizeError("Could not determine parse style for '%s'" % ipstr)

        # Logic to honor strict/loose, except IPRange. Doing a spanning_cidr on
        # an IPRange can be super slow if the range is large (such as a /8).
        if not strict and not isinstance(result, IPRange):
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

    @param ipstr: IP string to be parsed.
    @param threshold: The percentage of the network usage required to return a
    loose result.
    @param verbose: Toggle verbosity.

    Example of default behavior using 0.9 (90% usage) threshold:
        >>> import cidrize
        >>> cidrize.optimize_network_range('10.20.30.40-50', verbose=True)
        Subnet usage ratio: 0.34375; Threshold: 0.9
        Under threshold, IP Parse Mode: STRICT
        [IPNetwork('10.20.30.40/29'), IPNetwork('10.20.30.48/31'), IPNetwork('10.20.30.50/32')]

    Excample using a 0.3 (30% threshold):
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

def output_str(cidr, sep=', '):
    """Returns @sep separated string of constituent CIDR blocks."""
    return sep.join([str(x) for x in cidr])

def normalize_address(ipstr):
    """
    Attempts to cleanup an IP address that is in a non-standard format such
    as u'092.123.154.009', so that it can be properly parsed by netaddr or
    IPy.
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
    for interoperation with old code. If IPy is not available, @iplist is
    returned as-is.
    """
    try:
        import IPy
    except ImportError:
        return iplist

    if not isinstance(iplist, list):
        return iplist
    return [IPy.IP(str(x)) for x in iplist]

def dump(cidr):
    """Dumps a lot of info about a CIDR."""
    # Copy original cidr for usage later
    orig_cidr = cidr[:]

    # Flatten it for ops
    if len(cidr) == 1:
        cidr = cidr[0]
    else:
        cidr = spanning_cidr(cidr)

    # Is this a /32?
    single = (cidr.size == 1)

    if DEBUG:
        print 'Single?', single
        print 'Got: ', cidr
        print '-' * 50 + '\n'

    ip_first = IPAddress(cidr.first)
    ip_firsthost = ip_first if single else cidr.iter_hosts().next()
    ip_gateway = IPAddress(cidr.last - 1)
    ip_bcast = cidr.broadcast
    ip_netmask = cidr.netmask
    ip_hostmask = cidr.hostmask
    num_hosts = 1 if single else (cidr.last - 1) - cidr.first

    out  = ''
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
Cidrize parses IP address notation and returns valid CIDR blocks.''')

    parser.add_option('-h', '--help', action="store_false")
    parser.add_option('-v', '--verbose', action='store_true',
        help='Be verbose with user-friendly output. Lots of detail.')
    parser.add_option('-d', '--debug', action='store_true',
        help='Print debug output. You know, for the kids!')

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

    if opts.debug:
        global DEBUG
        DEBUG = True

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

    if opts.debug:
        print "OPTS:"
        print opts
        print "ARGS:"
        print args

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
