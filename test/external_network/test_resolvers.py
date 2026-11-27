import unittest
from typing import NamedTuple, Set

from artemis.resolvers import lookup


class TestData(NamedTuple):
    src: str
    expected: Set[str]


class TestResolvers(unittest.TestCase):
    def test_domain_lookup(self) -> None:
        data = [TestData("dns.google", {"8.8.8.8", "8.8.4.4"})]

        for item in data:
            result = lookup(item.src)
            self.assertTrue(result)
            self.assertLessEqual(result, item.expected)
