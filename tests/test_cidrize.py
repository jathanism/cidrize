#!/usr/bin/env python

import unittest
from netaddr import (IPRange, IPAddress, IPNetwork,)
import cidrize


class TestParseBrackets(unittest.TestCase):
    def test_parse_brackets(self):
        expected = IPRange('1.2.3.118', '1.2.3.121')
        _input = '1.2.3.1[18-21]'
        self.assertEqual(expected, cidrize.parse_brackets(_input))

class TestCidrize(unittest.TestCase):
    def setUp(self):
        self.test = cidrize.cidrize

    def test_everything_style(self):
        expected = set([IPNetwork('0.0.0.0/0')])
        _input = set()
        [_input.add(self.test(item)[0]) for item in cidrize.EVERYTHING]
        self.assertEqual(expected, _input)

    def test_cidr_style(self):
        expected = [IPNetwork('1.2.3.4/32')]
        _input = '1.2.3.4'
        self.assertEqual(expected, self.test(_input))

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
