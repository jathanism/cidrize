#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# module cidrize.py
#
# Copyright (c) 2010 Jathan McCollum
#


"""
Intelligently take IPv4 addresses, CIDRs, ranges, and wildcard matches to attempt
return a valid list of IP addresses that can be worked with. Will automatically 
fix bad network boundries if it can.

The cidrize() function is the public interface. The module may also be run
interactively for debugging purposes.
"""


from netaddr import (AddrFormatError, IPAddress, IPGlob, IPNetwork, IPRange, IPSet, spanning_cidr,)
from pyparsing import (Group, Literal, Optional, ParseResults, Word, nestedExpr, nums,)
import re
import sys

__version__ = '0.4'
__author__ = 'Jathan McCollum <jathan+bitbucket@gmail.com>'

DEBUG = False
EVERYTHING = ['internet at large', '*', 'all', 'any', 'internet', '0.0.0.0']

# Exports
__all__ = ('cidrize', 'CidrizeError', 'dump', 'normalize_address',)


# Awesome exceptions
class CidrizeError(AddrFormatError): pass
class NotCIDRStyleError(CidrizeError): pass
class NotRangeStyleError(CidrizeError): pass
class NotGlobStyleError(CidrizeError): pass
class NotBracketStyleError(CidrizeError): pass


def parse_brackets(_input):
    """
    Best effort to break down UNIX wildcard style ranges like
    "1.2.3.1[18-21]" into octets append use first & last numbers of
    bracketed range as the min/max of the 4th octet. 

    This is assuming we'll only ever see [x-y] style ranges in the 4th octet.

    Returns an IPRange object.
    """
    # pyparsing setup
    integer = Word(nums)
    dash = Literal("-").suppress()
    intrange = integer + dash + integer
    range_or_int = (intrange ^ integer)
    sequence = Group(intrange) | range_or_int | nestedExpr("[", "]", range_or_int)
    octet = Optional(sequence) + Optional(integer) + Optional(sequence) + Optional(integer)
    address = octet + "." + octet + "." + octet + "." + octet

    if DEBUG: print "    IN:", _input
    parsed = address.searchString(_input)[0]
    if DEBUG: print "PARSED:", parsed

    prefix = ''
    enders = []

    if type(parsed[-1]) == ParseResults:
        prefix = ''.join(parsed[:-1])
        enders = parsed[-1]
        if DEBUG:
            print "PREFIX:", prefix
            print "ENDERS:", enders

    first, last = enders[0], enders[1]
    return IPRange(prefix + first, prefix + last)

def cidrize(ipaddr, strict=False, modular=True):
    """
    This function tries to determine the best way to parse IP addresses correctly & has
    all the logic for trying to do the right thing!

    Input can be several formats:
        192.0.2.18     
        192.0.2.64/26  
        192.0.2.80-192.0.2.85
        192.0.2.170-175
        192.0.2.8[0-5]

    Hyphenated ranges do not need to form a CIDR block. Netaddr does most of 
    the heavy lifting for us here.

    Input can NOT be:
        192.0.2.0 0.0.0.255 (hostmask)
        192.0.2.0 255.255.255.0 (netmask)

    Does NOT accept network or host mask notation, so don't bother trying.

    Returns a list of consolidated netaddr objects. 

    Defaults:
        * parsing exceptions will raise a CidrizeError (modular=True).
        * results will be returned as a spanning CIDR (strict=False).

    @modular - Set to False to cause exceptions to be stripped & the error text will be 
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

    @strict - Set to True to return explicit networks based on start/end addresses.

    Example:
        >>> import cidrize as c
        >>> c.cidrize('1.2.3.4-1.2.3.10')
        [IPNetwork('1.2.3.0/28')]

        >>> c.cidrize('1.2.3.4-1.2.3.10', strict=True)
        [IPNetwork('1.2.3.4/30'), IPNetwork('1.2.3.8/31'), IPNetwork('1.2.3.10/32')]
    
    """
    ip = None
    try:
        # Parse old-fashioned CIDR notation
        if re.match("\d+\.\d+\.\d+\.\d+(?:\/\d+)?$", ipaddr):
            if DEBUG: print "Trying CIDR style..."
            ip = IPNetwork(ipaddr)
            return [ip.cidr]

        # Parse 1.2.3.118-1.2.3.121 range style
        elif re.match("\d+\.\d+\.\d+\.\d+\-\d+\.\d+\.\d+\.\d+$", ipaddr):
            if DEBUG: print "Trying range style..."
        
            start, finish = ipaddr.split('-')
            ip = IPRange(start, finish)
            if DEBUG:
                print ' start:', start
                print 'finish:', finish
                print ip

            # Expand ranges like 1.2.3.1-1.2.3.254 to entire network. For some
            # reason people do this thinking they are being smart so you end up
            # with lots of subnets instead of one big supernet.
            #if IPAddress(ip.first).words[-1] == 1 and IPAddress(ip.last).words[-1] == 254:
            if not strict:
                return [spanning_cidr(ip)]
            else:
                return ip.cidrs()

        # Parse 1.2.3.* glob style 
        elif re.match("\d+\.\d+\.\d+\.\*$", ipaddr):
            if DEBUG: print "Trying glob style..."
            return [spanning_cidr(IPGlob(ipaddr))]
        
        # Parse 1.2.3.4[5-9] bracket style as a last resort
        elif re.match("(.*?)\.(\d+)[\[\{\(](.*)[\)\}\]]", ipaddr) or re.match("(.*?)\.(\d+)\-(\d+)$", ipaddr):
            if DEBUG: print "Trying bracket style..."
            return parse_brackets(ipaddr).cidrs()

        # Parse "everything"
        elif ipaddr in EVERYTHING:
            if DEBUG: print "Trying everything style..."
            return [IPNetwork('0.0.0.0/0')]

    except (AddrFormatError, TypeError), err:
        if modular:
            raise CidrizeError(err)
        return [str(err)]

def output_str(cidr, sep=', '):
    """Returns @sep separated string of constituent CIDR blocks."""
    return sep.join([str(x) for x in cidr])

def normalize_address(ipstr):
    """Attempts to cleanup an IP address that is in a non-standard format such
    as u'092.123.154.009', so that it can be properly parsed by netaddr or
    IPy."""
    data = ipstr.split('/')
    cidr = '32'
    if len(data) == 1:
        myip = data[0]
    elif len(data) == 2:
        myip, cidr = data
    else:
        return ipstr

    octets = map(int, myip.split('.'))
    ip = '.'.join(map(str, octets))
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
    return map(IPy.IP, (str(x) for x in iplist))

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
    single = True if cidr.size == 1 else False
    
    if DEBUG:
        print 'Single?', single
        print 'Got: ', cidr
        print '-' * 50 + '\n'

    ip = IPAddress
    ip_first = ip(cidr.first)
    ip_firsthost = ip_first if single else cidr.iter_hosts().next()
    ip_gateway = ip(cidr.last - 1)
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
    """
    out += "# Class C networks:\t", $num_classc, "\n";
    out += "# Class B networks:\t", $num_classb, "\n";
    out += "# Class A networks:\t", $num_classa, "\n";
    """

    return out

def parse_args(argv):
    from optparse import OptionParser
    parser = OptionParser(usage='%prog [-v] [-d] [ip network]', add_help_option=0, description='''\
Cidrize parses IP address notation and returns valid CIDR blocks.''')

    parser.add_option('-h','--help', action="store_false")
    parser.add_option('-v', '--verbose', action='store_true',
        help='Be verbose with user-friendly output. Lots of detail.')
    parser.add_option('-d', '--debug', action='store_true',
        help='Print debug output. You know, for the kids!')

    notes = """
    Intelligently take IPv4 addresses, CIDRs, ranges, and wildcard matches to attempt
    return a valid list of IP addresses that can be worked with. Will automatically 
    fix bad network boundries if it can.

    Input can be several formats:

        192.0.2.18     
        192.0.2.64/26  
        192.0.2.80-192.0.2.85
        192.0.2.170-175
        192.0.2.8[0-5]

    Hyphenated ranges do not need to form a CIDR block. Netaddr does most of 
    the heavy lifting for us here.

    Input can NOT be:

        192.0.2.0 0.0.0.255 (hostmask)
        192.0.2.0 255.255.255.0 (netmask)

    Does NOT accept network or host mask notation, so don't bother trying.
    """

    opts, args = parser.parse_args(argv)

    if opts.debug:
        global DEBUG
        DEBUG = True

    def phelp():
        parser.print_help()
        print notes

    if opts.help or len(args) == 1:
        phelp()
        print 'ERROR: You must specify an ip address. See usage information above!!'
        sys.exit(-1)
    else:
        opts.ip = args[1]

    return opts, args

def main():
    global opts
    opts, args = parse_args(sys.argv)

    if opts.debug:
        print "OPTS:"
        print opts
        print "ARGS:"
        print args

    ipaddr = opts.ip

    try:
        cidr = cidrize(ipaddr, modular=False)
        if cidr:
            if opts.verbose:
                print dump(cidr),
            else:
                print output_str(cidr)
    except IndexError, err:
        return -1
    
if __name__ == '__main__':
    sys.exit(main())
