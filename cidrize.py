#!/usr/bin/env python
# -*- coding: utf-8 -*-
# module cidrize.py
#
# Copyright (c) 2010 Jathan McCollum

"""
Intelligently take IP addresses, CIDRs, ranges, and wildcard matches to attempt
return a valid list of IP addresses that can be worked with. Will automatically 
fix bad network boundries if it can.

The cidrize() function is the workhorse. The module may also be run
interactively for debugging purposes.
"""

__version__ = '0.1'
__author__ = 'Jathan McCollum <jathan+bitbucket@gmail.com>'

from netaddr import *
from pyparsing import *
import re
import sys

DEBUG = False


__all__ = ['cidrize']


## NYI but here for solidarity
class AddrError(AddrFormatError): pass
class NotCIDRStyleError(AddrError): pass
class NotRangeStyleError(AddrError): pass
class NotGlobStyleError(AddrError): pass
class NotBracketStyleError(AddrError): pass


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

def cidrize(ipaddr):
    """
    The function that does all the work trying to parse IP addresses correctly.
    All the logic for parsing to try to do the right thing!

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
    ip = None
    try:
        ## Parse old-fashioned CIDR notation
        if re.match("\d+.\d+.\d+.\d+(?:\/\d+)?$", ipaddr):
            if DEBUG: print "Trying CIDR style..."
            ip = IPNetwork(ipaddr)
            return ip.cidr

        ## Parse 1.2.3.118-1.2.3.121 range style
        elif re.match("\d+.\d+.\d+.\d+\-\d+.\d+.\d+.\d+$", ipaddr):
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
                return spanning_cidr(ip)
            else:
                return ip.cidrs()

        ## Parse 1.2.3.* glob style 
        elif re.match("\d+.\d+.\d+.\*$", ipaddr):
            if DEBUG: print "Trying glob style..."
            return spanning_cidr(IPGlob(ipaddr))
        
        ## Parse 1.2.3.4[5-9] bracket style as a last resort
        #elif re.match("(.*?)\.(\d+)[\[\{\(](.*)[\)\}\]]", ipaddr):
        else:
            if DEBUG: print "Trying bracket style..."
            return parse_brackets(ipaddr).cidrs()

    except (AddrFormatError, TypeError) as err:
        print err
        pass

def main():
    try:
        ipaddr = sys.argv[1]
        #print '    IN:', ipaddr
        cidr = cidrize(ipaddr)
        #print 'PARSED:', cidr
        #if cidr: print '------>', spanning_cidr(cidr)
        if cidr is not None: 
            print cidr
            #print spanning_cidr(cidr)
    except IndexError:
        sys.exit("usage: cidr 1.2.3.4/32")
    
if __name__ == '__main__':
    main()

    """
    tests = (
        '205.188.135.1[18-21]',
        '5.5.5.5-7',
        '1.2.3.1-1.2.3.254',
    )

    for t in tests:
        print
        ipr = parse_brackets(t)
        print ipr.cidrs()
        print list(ipr)
    """
