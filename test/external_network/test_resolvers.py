import unittest
from typing import NamedTuple, Set

from artemis.resolvers import lookup


class TestData(NamedTuple):
    src: str
    expected: Set[str]


class TestResolvers(unittest.TestCase):
    def test_domain_lookup(self) -> None:
        data = [TestData("lebihan.pl", {"146.59.80.63"})]

        for item in data:
            self.assertEqual(lookup(item.src), item.expected)
