"""
Unit tests for ``cidrize``.
"""

import unittest

from netaddr import IPRange, IPNetwork
import pytest

import cidrize


class TestParseBrackets(unittest.TestCase):
    def test_parse_brackets(self):
        expected = IPRange("1.2.3.118", "1.2.3.121")
        _input = "1.2.3.1[18-21]"
        assert expected == cidrize.parse_brackets(_input)

    def test_parse_brackets_fail(self):
        expected = None
        _input = "10.10.1[67].0/24"
        assert expected == cidrize.parse_brackets(_input)


class TestCidrize(unittest.TestCase):
    def setUp(self):
        self.test = cidrize.cidrize

    def test_everything_style_v4(self):
        expected = set([IPNetwork("0.0.0.0/0")])
        _input = set()
        for item in cidrize.EVERYTHING_V4:
            _input.add(self.test(item)[0])
        assert expected == _input

    def test_everything_style_v6(self):
        expected = set([IPNetwork("::/0")])
        _input = set()
        for item in cidrize.EVERYTHING_V6:
            _input.add(self.test(item)[0])
        assert expected == _input

    def test_cidr_style_ipv4(self):
        expected = [IPNetwork("1.2.3.4/32")]
        _input = "1.2.3.4"
        assert expected == self.test(_input)

    def test_cidr_style_ipv6(self):
        expected = [IPNetwork("fe80:4::c62c:3ff:fe00:861e/128")]
        _input = "fe80:4::c62c:3ff:fe00:861e"
        assert expected == self.test(_input)

    def test_parse_range(self):
        expected = IPRange("1.2.3.4", "1.2.3.10")
        _input = "1.2.3.4-1.2.3.10"
        assert expected == cidrize.parse_range(_input)

    def test_parse_range6(self):
        expected = IPRange("2001::1.2.3.4", "2002:1234:abcd::ffee")
        _input = "2001::1.2.3.4-2002:1234:abcd::ffee"
        assert expected == cidrize.parse_range(_input)

    def test_range_style_strict(self):
        expected = [IPNetwork("1.2.3.118/31"), IPNetwork("1.2.3.120/31")]
        _input = "1.2.3.118-1.2.3.121"
        assert expected == self.test(_input, strict=True)

    def test_range_style_loose(self):
        expected = [IPNetwork("1.2.3.112/28")]
        _input = "1.2.3.118-1.2.3.121"
        assert expected == self.test(_input, strict=False)

    def test_glob_style(self):
        expected = [IPNetwork("1.2.3.0/24")]
        _input = "1.2.3.*"
        assert expected == self.test(_input)

    def test_hyphen_style_strict(self):
        expected = [
            IPNetwork("1.2.3.4/30"),
            IPNetwork("1.2.3.8/29"),
            IPNetwork("1.2.3.16/30"),
            IPNetwork("1.2.3.20/32"),
        ]
        _input = "1.2.3.4-20"
        assert expected == self.test(_input, strict=True)

    def test_hyphen_style_loose(self):
        expected = [IPNetwork("1.2.3.0/27")]
        _input = "1.2.3.4-20"
        assert expected == self.test(_input, strict=False)

    def test_hyphen_style_loose_toobig(self):
        # IPRange objects larger than /16 will always be strict.
        expected = [
            IPNetwork("10.0.0.0/16"),
            IPNetwork("10.1.0.0/18"),
            IPNetwork("10.1.64.0/19"),
            IPNetwork("10.1.96.0/29"),
        ]
        _input = "10.0.0.0-10.1.96.7"
        assert expected == self.test(_input, strict=False)

    def test_bracket_style_strict(self):
        expected = [IPNetwork("1.2.3.118/31"), IPNetwork("1.2.3.120/31")]
        _input = "1.2.3.1[18-21]"
        assert expected == self.test(_input, strict=True)

    def test_bracket_style_loose(self):
        expected = [IPNetwork("1.2.3.112/28")]
        _input = "1.2.3.1[18-21]"
        assert expected == self.test(_input, strict=False)

    def test_hostname(self):
        _input = "jathan.com"
        with pytest.raises(cidrize.CidrizeError):
            self.test(_input)

    def test_nocidr_ipv6(self):
        expected = [IPNetwork("2001:4b0:1668:2602::2/128")]
        _input = "2001:4b0:1668:2602::2"
        assert expected == self.test(_input)

    def test_last_resort_ipv6(self):
        expected = [IPNetwork("2001:4b0:1668:2602::2/128")]
        _input = "2001:4b0:1668:2602::2/128"
        assert expected == self.test(_input)

    def test_large_ipv6(self):
        expected = [IPNetwork("2001:4b0:1668:2602::2/64")]
        _input = "2001:4b0:1668:2602::/64"
        assert expected == self.test(_input)

    def test_failure(self):
        _input = "1.2.3.4]"
        with pytest.raises(cidrize.CidrizeError):
            self.test(_input)

    def test_bracket_failure(self):
        _input = "10.10.1[67].0/24"
        with pytest.raises(cidrize.CidrizeError):
            self.test(_input)


class TestDump(unittest.TestCase):
    def test_dump(self):
        cidr = cidrize.cidrize("1.2.3.*")
        result = cidrize.dump(cidr)
        assert isinstance(result, str)


class TestOutputStr(unittest.TestCase):
    def test_output_str(self):
        cidr = cidrize.cidrize("10.20.30.40-50", strict=True)
        sep = ", "
        expected = "10.20.30.40/29, 10.20.30.48/31, 10.20.30.50/32"
        assert expected == cidrize.output_str(cidr, sep)

    def test_range6(self):
        cidr = cidrize.cidrize("2001:1234::0.0.64.0-2001:1234::FFff")
        sep = ", "
        expected = "2001:1234::/112"
        assert expected == cidrize.output_str(cidr, sep)


class TestOptimizeNetworkRange(unittest.TestCase):
    def setUp(self):
        self.test = cidrize.optimize_network_range

    def test_glob_style(self):
        expected = [IPNetwork("10.181.25.0/24")]
        _input = "10.181.25.*"
        assert expected == self.test(_input)
