import unittest
from typing import NamedTuple, Set

from artemis.resolvers import ip_lookup


class TestData(NamedTuple):
    src: str
    expected: Set[str]


class TestStringMethods(unittest.TestCase):
    def test_domain_lookup(self):
        data = [TestData("lebihan.pl", {"146.59.80.63"})]

        for item in data:
            self.assertEqual(ip_lookup(item.src), item.expected)
