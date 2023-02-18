#!/usr/bin/env python

"""
IP address parsing for humans.

Cidrize takes IP address inputs that people tend to use in practice, validates
them, and converts them to objects.

It will intelligently parse IPv4/IPv6 addresses, CIDRs, ranges, and wildcard
matches to attempt return a valid list of IP addresses. It's smart enough to fix
bad network boundaries for you.

The ``cidrize()`` function is the public interface. The module may also be run
interactively for debugging purposes.
"""

import itertools
import logging
from optparse import OptionParser  # pylint: disable=deprecated-module
import os
import re
import socket
from string import Template
import sys

from netaddr import (
    AddrFormatError,
    IPAddress,
    IPGlob,
    IPNetwork,
    IPRange,
    IPSet,
    spanning_cidr,
)


# Globals

# Patterns for matching v4 wildcards
EVERYTHING_V4 = [
    "*",
    "0.0.0.0",
    "0.0.0.0/0",
    "0.0.0.0-255.255.255.255",
    "all",
    "any",
    "internet",
    "internet at large",
]
EVERYTHING = EVERYTHING_V4  # Backwards compatibility (just in case)

# Patterns for matching v6 wildcards
EVERYTHING_V6 = [
    "::",
    "[::]",
]

# IPRange objects larger than MAX_RANGE_LEN will always be strict.
# This is an IPv4 /16
MAX_RANGE_LEN = 65535

# Setup logging
DEBUG = os.getenv("DEBUG")
LOG_LEVEL = logging.INFO
LOG_FORMAT = "%(asctime)s [%(levelname)s]: %(message)s"
if DEBUG:
    LOG_LEVEL = logging.DEBUG

logging.basicConfig(level=LOG_LEVEL, format=LOG_FORMAT)
log = logging.getLogger(__name__)

#
# Pre-compiled re patterns. You know, for speed!
#

# Old-fashioned CIDR notation (192.168.1.0/24)
RE_CIDR = re.compile(r"\d+\.\d+\.\d+\.\d+(?:\/\d+)?$")

# 1.2.3.118-1.2.3.121 range style
RE_RANGE = re.compile(r"\d+\.\d+\.\d+\.\d+\-\d+\.\d+\.\d+\.\d+$")

# 2001::14-2002::1.2.3.121 range style
RE_RANGE6 = re.compile(
    r"[0-9a-fA-F]+:[0-9A-Fa-f:.]+\-[0-9a-fA-F]+:[0-9A-Fa-f:.]+$"
)

# 1.2.3.* glob style
RE_GLOB = re.compile(r"\d+\.\d+\.\d+\.\*$")

# 1.2.3.4[5-9] or 1.2.3.[49] bracket style as a last resort
RE_BRACKET = re.compile(r"(.*?)\.(\d+)[\[\{\(](.*)[\)\}\]]$")

# 1.2.3.4-70 hyphen style
RE_HYPHEN = re.compile(r"(.*?)\.(\d+)\-(\d+)$")

# Hostnames (we're assuming first char is alpha)
RE_HOSTNAME = re.compile(
    r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?)",
    re.IGNORECASE,
)


# Exports
__all__ = (
    "cidrize",
    "CidrizeError",
    "dump",
    "normalize_address",
    "optimize_network_range",
    "parse_range",
    "is_ipv6",
)


# Exceptions
class CidrizeError(AddrFormatError):
    """Generic Cidrize error."""


class NotCIDRStyle(CidrizeError):
    """Not CIDR style?"""


class NotRangeStyle(CidrizeError):
    """Not range style?"""


class NotGlobStyle(CidrizeError):
    """Not glob style?"""


class NotBracketStyle(CidrizeError):
    """Not bracket style?"""


# Functions
def parse_brackets(text):
    """
    Best effort to break down UNIX wildcard style ranges like
    "1.2.3.1[18-21]" into octets append use first & last numbers of
    bracketed range as the min/max of the 4th octet.

    This is assuming we'll only ever see [x-y] style ranges in the 4th octet.

    Returns an IPRange object.

    :param text:
        The string to parse.
    """

    match = RE_BRACKET.match(text)

    if match is None:
        return None

    parts = match.groups()

    # '1.2.3.4[5-9] style
    log.debug("parse_brackets() parts: %r", (parts,))
    if len(parts) == 3:
        prefix, subnet, enders = parts
        network = ".".join((prefix, subnet))

    # '1.2.3.[5-9] style
    elif len(parts) == 2:
        prefix, enders = parts
        network = prefix + "."

    else:
        raise NotBracketStyle(f"Bracketed style not parseable: {next}")

    # Split hyphenated [x-y]
    if "-" in enders:
        first, last = enders.split("-")

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

    :param text:
        The string to parse
    """
    match = RE_HYPHEN.match(text)
    if match is None:
        return None

    parts = match.groups()
    prefix, start, finish = parts
    network = prefix + "."

    return IPRange(network + start, network + finish)


def parse_range(ipstr):
    """
    Given a hyphenated range of IPs, return an IPRange object.

    :param ipstr:
        The hyphenated IP range.
    """
    start, finish = ipstr.split("-")
    ip_range = IPRange(start, finish)
    log.debug("parse_range_style() start: %r", start)
    log.debug("parse_range_style() finish: %r", finish)
    log.debug("parse_range_style() ip: %r", ip_range)

    return ip_range


def parse_commas(ipstr, **kwargs):
    """
    This will break up a comma-separated input string of assorted inputs, run them through
    cidrize(), flatten the list, and return the list. If any item in the list
    fails, it will allow the exception to pass through as if it were parsed
    individually. All objects must parse or nothing is returned.

    Example:

    :param ipstr:
        A comma-separated string of IP address patterns.
    """
    # Clean whitespace before we process
    ipstr = ipstr.replace(" ", "").strip()
    items = ipstr.split(",")

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

    :param ipstr:
        A suspected IPv6 address
    """
    log.debug("is_ipv6() got: %r", ipstr)
    try:
        socket.inet_pton(socket.AF_INET6, ipstr)
        return True
    except (socket.error, AttributeError):
        return False


def cidrize(
    ipstr, strict=False, raise_errors=True
):  # pylint: disable=too-many-return-statements, too-many-branches
    """
    This function tries to determine the best way to parse IP addresses correctly & has
    all the logic for trying to do the right thing!

    Returns a list of consolidated netaddr objects.

    Input can be several formats::

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

    Input can NOT be::

        192.0.2.0 0.0.0.255 (hostmask)
        192.0.2.0 255.255.255.0 (netmask)

    Does NOT accept network or host mask notation at this time!

    Defaults:

        * parsing exceptions will raise a CidrizeError (raise_errors=True).
        * results will be returned as a spanning CIDR (strict=False).

    :param ipstr:
        IP string to be parsed.

    :param raise_errors:
        Set to False to cause exceptions to be stripped & the error text will be
        returned as a list. This is intended for use with scripts or APIs
        out-of-the box.

    Example::

        >>> import cidrize as c
        >>> c.cidrize('1.2.3.4-1.2.3.1099')
        Traceback (most recent call last):
          File "<stdin>", line 1, in <module>
          File "/home/j/jathan/sandbox/cidrize.py", line 153, in cidrize
            raise CidrizeError(err)
        cidrize.CidrizeError: base address '1.2.3.1099' is not IPv4

        >>> c.cidrize('1.2.3.4-1.2.3.1099', raise_errors=False)
        ["base address '1.2.3.1099' is not IPv4"]

    :param strict:
        Set to True to return explicit networks based on start/end addresses.

    Example::

        >>> import cidrize as c
        >>> c.cidrize('1.2.3.4-1.2.3.10')
        [IPNetwork('1.2.3.0/28')]

        >>> c.cidrize('1.2.3.4-1.2.3.10', strict=True)
        [IPNetwork('1.2.3.4/30'), IPNetwork('1.2.3.8/31'), IPNetwork('1.2.3.10/32')]

    """
    ipobj = None

    # Short-circuit to parse commas since it calls back here anyway
    if "," in ipstr:
        return parse_commas(ipstr, strict=strict, raise_errors=raise_errors)

    # Short-circuit for hostnames (we're assuming first char is alpha)
    if RE_HOSTNAME.match(ipstr):
        raise CidrizeError("Cannot parse hostnames!")

    # Otherwise try everything else
    result = None
    try:
        # Parse "everything" v4 & immediately return; strict/loose doesn't apply
        if ipstr in EVERYTHING_V4:  # pylint: disable = no-else-return
            log.debug("Trying everything style...")
            return [IPNetwork("0.0.0.0/0")]

        # Parse "everything" v6 & immediately return; strict/loose doesn't apply
        elif ipstr in EVERYTHING_V6:
            log.debug("Trying everything style...")
            return [IPNetwork("::/0")]

        # Parse old-fashioned CIDR notation & immediately return; strict/loose doesn't apply
        # Now with IPv6!
        elif RE_CIDR.match(ipstr) or is_ipv6(ipstr):
            log.debug("Trying CIDR style...")
            ipobj = IPNetwork(ipstr)
            return [ipobj.cidr]

        # Parse 1.2.3.118-1.2.3.121 range style
        elif RE_RANGE.match(ipstr):
            log.debug("Trying range style...")
            result = parse_range(ipstr)

        # Parse 2001::14-2002::1.2.3.121 range style
        elif RE_RANGE6.match(ipstr):
            log.debug("Trying range6 style...")
            result = parse_range(ipstr)

        # Parse 1.2.3.4-70 hyphen style
        elif RE_HYPHEN.match(ipstr):
            log.debug("Trying hyphen style...")
            result = parse_hyphen(ipstr)

        # Parse 1.2.3.* glob style
        elif RE_GLOB.match(ipstr):
            log.debug("Trying glob style...")
            ipglob = IPGlob(ipstr)
            result = spanning_cidr(ipglob)

        # Parse 1.2.3.4[5-9] or 1.2.3.[49] bracket style as a last resort
        elif RE_BRACKET.match(ipstr):
            log.debug("Trying bracket style...")
            result = parse_brackets(ipstr)

        # If result still isn't set, let's see if it's IPv6??
        elif result is None:
            log.debug("Trying bare IPv6 parse...")
            result = IPNetwork(ipstr)

        # This will probably fail 100% of the time. By design.
        else:
            raise CidrizeError(f"Could not determine parse style for {ipstr!r}")

        # If it's a single host, just return it wrapped in a list
        if result.size == 1:
            log.debug("Returning a single host!")
            return [result.cidr]

        # Logic to honor strict/loose, except IPRange. Doing a spanning_cidr on
        # an IPRange can be super slow if the range is large (such as a /8), so
        # IPRange objects larger than MAX_RANGE_LEN will always be strict.
        if not strict:
            if isinstance(result, IPRange) and result.size >= MAX_RANGE_LEN:
                log.debug(
                    "IPRange objects larger than /16 will always be strict."
                )
                return result.cidrs()
            if isinstance(result, IPNetwork):
                return [result.cidr]
            return [spanning_cidr(result)]

        try:
            return result.cidrs()  # IPGlob and IPRange have .cidrs()
        except AttributeError:
            return [result.cidr]  # IPNetwork has .cidr

    except (AddrFormatError, TypeError, ValueError) as err:
        if raise_errors:
            raise CidrizeError(str(err)) from err
        return [str(err)]


def optimize_network_range(ipstr, threshold=0.9, verbose=DEBUG):
    """
    Parses the input string and then calculates the subnet usage percentage. If over
    the threshold it will return a loose result, otherwise it returns strict.

    :param ipstr:
        IP string to be parsed.

    :param threshold:
        The percentage of the network usage required to return a loose result.

    :param verbose:
        Toggle verbosity.

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
        raise CidrizeError("Threshold must be from 0.0 to 1.0")

    # Can't optimize 0.0.0.0/0!
    if ipstr in EVERYTHING:
        return cidrize(ipstr)

    loose = IPSet(cidrize(ipstr))
    strict = IPSet(cidrize(ipstr, strict=True))
    ratio = float(len(strict)) / float(len(loose))

    if verbose:
        print(f"Subnet usage ratio: {ratio}; Threshold: {threshold}")

    if ratio >= threshold:
        if verbose:
            print("Over threshold, IP Parse Mode: LOOSE")
        result = loose.iter_cidrs()
    else:
        if verbose:
            print("Under threshold, IP Parse Mode: STRICT")
        result = strict.iter_cidrs()

    return result


def output_str(ipobj, sep=", "):
    """
    Returns a character-separated string of constituent CIDR blocks for a given
    IP object (should support both IPy and netaddr objects).

    :param ipobj:
        An IP address object.

    :param sep:
        The separator used to join the string together.
    """
    return sep.join([str(x) for x in ipobj])


def normalize_address(ipstr):
    """
    Attempts to cleanup an IP address that is in a non-standard format such
    as u'092.123.154.009', so that it can be properly parsed by netaddr or
    IPy.

    :param ipstr:
        An IP address string.
    """
    data = ipstr.split("/")
    cidr = "32"
    if len(data) == 1:
        myip = data[0]
    elif len(data) == 2:
        myip, cidr = data
    else:
        return ipstr

    octets = (int(i) for i in myip.split("."))
    ipobj = ".".join([str(o) for o in octets])

    return f"{ipobj}/{cidr}"


def netaddr_to_ipy(iplist):
    """
    Turns a list of netaddr.IPNetwork objects into IPy.IP objects. Useful
    for interoperation with old code. If IPy is not available, the input is
    returned as-is.

    :param iplist:
        A list of netaddr.IPNetwork objects.
    """
    try:
        import IPy  # pylint: disable=import-outside-toplevel
    except ImportError:
        return iplist

    if not isinstance(iplist, list):
        return iplist

    return [IPy.IP(str(x)) for x in iplist]


DUMP_TEMPLATE = """
Information for $cidr

IP Version:\t\t$cidr_version
Spanning CIDR:\t\t$cidr
Block Start/Network:\t$ip_first
1st host:\t\t$ip_firsthost
Gateway:\t\t$ip_gateway
Block End/Broadcast:\t$ip_bcast
DQ Mask:\t\t$ip_netmask
Cisco ACL Mask:\t\t$ip_hostmask
# of hosts:\t\t$num_hosts
Explicit CIDR blocks:\t$orig_cidr_str
"""


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
    single = cidr.size == 1

    log.debug("dump(): Single? %r", single)
    log.debug("dump(): Got? %r", cidr)

    return Template(DUMP_TEMPLATE).substitute(
        cidr=cidr,
        cidr_version=cidr.version,
        ip_first=IPAddress(cidr.first),
        ip_firsthost=IPAddress(cidr.first)
        if single
        else next(cidr.iter_hosts()),
        ip_gateway=IPAddress(cidr.last - 1),
        ip_bcast=cidr.broadcast,
        ip_netmask=cidr.netmask,
        ip_hostmask=cidr.hostmask,
        num_hosts=1 if single else (cidr.last - 1) - cidr.first,
        orig_cidr_str=output_str(orig_cidr),
    )


def parse_args(argv):
    """Parses args."""

    parser = OptionParser(
        usage="%prog [-v] [-d] [ip network]",
        add_help_option=0,
        description="""\
Cidrize parses IP address notation and returns valid CIDR blocks. If you want
debug output set the DEBUG environment variable.""",
    )

    parser.add_option("-h", "--help", action="store_false")
    parser.add_option(
        "-s",
        "--strict",
        action="store_true",
        help="Enable strict parsing. (Default: loose)",
    )
    parser.add_option(
        "-v",
        "--verbose",
        action="store_true",
        help="Be verbose with user-friendly output. Lots of detail.",
    )

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
        print(notes)

    if opts.help or len(args) == 1:
        phelp()
        sys.exit(
            "ERROR: You must specify an ip address. See usage information above!!"
        )
    else:
        opts.ip = args[1]

    if "," in opts.ip:
        phelp()
        sys.exit("ERROR: Comma-separated arguments aren't supported!")

    return opts, args


def main():
    """
    Used by the 'cidr' command that is bundled with the package.
    """
    opts, args = parse_args(sys.argv)

    log.debug("OPTS: %r", opts)
    log.debug("ARGS: %r", args)

    ipstr = opts.ip

    try:
        cidr = cidrize(ipstr, raise_errors=False, strict=opts.strict)
        if cidr:
            if opts.verbose:
                print(dump(cidr))
            else:
                print(output_str(cidr))
    except IndexError:
        return -1

    return 0


if __name__ == "__main__":
    sys.exit(main())
