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

__version__ = '0.2'
__author__ = 'Jathan McCollum <jathan+bitbucket@gmail.com>'

from netaddr import (AddrFormatError, IPAddress, IPGlob, IPNetwork, IPRange, spanning_cidr,)
from pyparsing import (Group, Literal, Optional, ParseResults, Word, nestedExpr, nums,)
import re
import sys

_SELF = sys.argv[0]
DEBUG = False


__all__ = ['cidrize', 'CidrizeError']


class CidrizeError(AddrFormatError): pass
class NotCIDRStyleError(CidrizeError): pass
class NotRangeStyleError(CidrizeError): pass
class NotGlobStyleError(CidrizeError): pass
class NotBracketStyleError(CidrizeError): pass


def parse_brackets(_input):
    """
    Best effort to break down UNIX wildcard style ranges like
    "205.188.135.1[18-21]" into octects append use first & last numbers of
    bracketed range as the min/max of the 4th octect. 

    This is assuming we'll only ever see [x-y] style ranges in the 4th octet.

    Returns an IPRange object.
    """
    ## pyparsing setup
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

def cidrize(ipaddr, modular=True):
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

    By default parsing exceptions will raise a CidrizeError (modular=True).

    You may pass modular=False to cause exceptions to be stripped & the error text will be 
    returned as a list. This is intended for use with scripts or APIs out-of-the box.
    """
    ip = None
    try:
        ## Parse old-fashioned CIDR notation
        if re.match("\d+\.\d+\.\d+\.\d+(?:\/\d+)?$", ipaddr):
            if DEBUG: print "Trying CIDR style..."
            ip = IPNetwork(ipaddr)
            return [ip.cidr]

        ## Parse 1.2.3.118-1.2.3.121 range style
        elif re.match("\d+\.\d+\.\d+\.\d+\-\d+\.\d+\.\d+\.\d+$", ipaddr):
            if DEBUG: print "Trying range style..."
        
            start, finish = ipaddr.split('-')
            ip = IPRange(start, finish)
            if DEBUG:
                print ' start:', start
                print 'finish:', finish
                print ip

            ## Expand ranges like 1.2.3.1-1.2.3.254 to entire network. For some
            ## reason people do this thinking they are being smart so you end up
            ## with lots of subnets instead of one big supernet.
            if IPAddress(ip.first).words[-1] == 1 and IPAddress(ip.last).words[-1] == 254:
                return [spanning_cidr(ip)]
            else:
                return ip.cidrs()

        ## Parse 1.2.3.* glob style 
        elif re.match("\d+\.\d+\.\d+\.\*$", ipaddr):
            if DEBUG: print "Trying glob style..."
            return [spanning_cidr(IPGlob(ipaddr))]
        
        ## Parse 1.2.3.4[5-9] bracket style as a last resort
        elif re.match("(.*?)\.(\d+)[\[\{\(](.*)[\)\}\]]", ipaddr) or re.match("(.*?)\.(\d+)\-(\d+)$", ipaddr):
            if DEBUG: print "Trying bracket style..."
            return parse_brackets(ipaddr).cidrs()

    except (AddrFormatError, TypeError), err:
        if modular:
            raise CidrizeError(err)
        return [str(err)]

def output_str(cidr):
    return ', '.join([str(x) for x in cidr])

def main():
    ipaddr = []
    try:
        ipaddr = sys.argv[1]
    except IndexError:
        print "usage: %s 1.2.3.4/32" % _SELF
        sys.exit(-1)

    try:
        cidr = cidrize(ipaddr, modular=False)
        if cidr:
            print output_str(cidr)
    except IndexError, err:
        sys.exit(-1)
    
if __name__ == '__main__':
    main()
