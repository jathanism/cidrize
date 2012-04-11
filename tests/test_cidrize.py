#!/usr/bin/env python

import unittest
from netaddr import (IPRange, IPAddress, IPNetwork,)
import cidrize


class TestParseBrackets(unittest.TestCase):
    def test_parse_brackets(self):
        expected = IPRange('1.2.3.118', '1.2.3.121')
        _input = '1.2.3.1[18-21]'
        self.assertEqual(expected, cidrize.parse_brackets(_input))

    def test_parse_brackets_fail(self):
        expected = None
        _input = '10.10.1[67].0/24'
        self.assertEqual(expected, cidrize.parse_brackets(_input))

class TestCidrize(unittest.TestCase):
    def setUp(self):
        self.test = cidrize.cidrize

    def test_everything_style(self):
        expected = set([IPNetwork('0.0.0.0/0')])
        _input = set()
        [_input.add(self.test(item)[0]) for item in cidrize.EVERYTHING]
        self.assertEqual(expected, _input)

    def test_cidr_style_ipv4(self):
        expected = [IPNetwork('1.2.3.4/32')]
        _input = '1.2.3.4'
        self.assertEqual(expected, self.test(_input))

    def test_cidr_style_ipv6(self):
        expected = [IPNetwork('fe80:4::c62c:3ff:fe00:861e/128')]
        _input = 'fe80::c62c:3ff:fe00:861e%en0'
        self.assertEqual(expected, self.test(_input))

    def test_parse_range(self):
        expected = IPRange('1.2.3.4', '1.2.3.10')
        _input = '1.2.3.4-1.2.3.10'
        self.assertEqual(expected, cidrize.parse_range(_input))

    def test_range_style_strict(self):
        expected = [IPNetwork('1.2.3.118/31'), IPNetwork('1.2.3.120/31')]
        _input = '1.2.3.118-1.2.3.121'
        self.assertEqual(expected, self.test(_input, strict=True))

    def test_range_style_loose(self):
        expected = [IPNetwork('1.2.3.112/28')]
        _input = '1.2.3.118-1.2.3.121'
        self.assertEqual(expected, self.test(_input, strict=False))

    def test_glob_style(self):
        expected = [IPNetwork('1.2.3.0/24')]
        _input = '1.2.3.*'
        self.assertEqual(expected, self.test(_input))

    def test_hyphen_style_strict(self):
        expected = [IPNetwork('1.2.3.4/30'), IPNetwork('1.2.3.8/29'),
                    IPNetwork('1.2.3.16/30'), IPNetwork('1.2.3.20/32')]
        _input = '1.2.3.4-20'
        self.assertEqual(expected, self.test(_input, strict=True))

    def test_hyphen_style_loose(self):
        expected = [IPNetwork('1.2.3.0/27')]
        _input = '1.2.3.4-20'
        self.assertEqual(expected, self.test(_input, strict=False))

    def test_hyphen_style_loose_toobig(self):
        # IPRange objects larger than /18 will always be strict.
        expected = [IPNetwork('10.0.0.0/18'), IPNetwork('10.0.64.0/29')]
        _input = '10.0.0.0-10.0.64.7'
        self.assertEqual(expected, self.test(_input, strict=False))

    def test_bracket_style_strict(self):
        expected = [IPNetwork('1.2.3.118/31'), IPNetwork('1.2.3.120/31')]
        _input = '1.2.3.1[18-21]'
        self.assertEqual(expected, self.test(_input, strict=True))

    def test_bracket_style_loose(self):
        expected = [IPNetwork('1.2.3.112/28')]
        _input = '1.2.3.1[18-21]'
        self.assertEqual(expected, self.test(_input, strict=False))

    def test_hostname(self):
        _input = 'jathan.com'
        self.assertRaises(cidrize.CidrizeError, self.test, _input)

    def test_last_resort_ipv6(self):
        expected = [IPNetwork('2001:4b0:1668:2602::2/128')]
        _input = '2001:4b0:1668:2602::2/128'
        self.assertEqual(expected, self.test(_input))

    def test_failure(self):
        _input = '1.2.3.4]'
        self.assertRaises(cidrize.CidrizeError, self.test, _input)

    def test_bracket_failure(self):
        _input = '10.10.1[67].0/24'
        self.assertRaises(cidrize.CidrizeError, self.test, _input)

class TestDump(unittest.TestCase):
    def test_dump(self):
        cidr = cidrize.cidrize('1.2.3.*')
        result = cidrize.dump(cidr)
        self.assertEqual(str, type(result))

class TestOutputStr(unittest.TestCase):
    def test_output_str(self):
        cidr = cidrize.cidrize('10.20.30.40-50', strict=True)
        sep = ', '
        expected = '10.20.30.40/29, 10.20.30.48/31, 10.20.30.50/32'
        self.assertEqual(expected, cidrize.output_str(cidr, sep))

'''
class TestParseArgs(unittest.TestCase):
    def test_parse_args(self):
        # self.assertEqual(expected, parse_args(argv))
        assert False # TODO: implement your test here

class TestMain(unittest.TestCase):
    def test_main(self):
        # self.assertEqual(expected, main())
        assert False # TODO: implement your test here
'''

if __name__ == '__main__':
    unittest.main()
