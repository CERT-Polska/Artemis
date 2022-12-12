import unittest

from artemis.domains import is_subdomain


class TestDomainUtils(unittest.TestCase):
    def test_is_subdomain(self) -> None:
        self.assertTrue(is_subdomain("www.google.com", "google.com"))
        self.assertTrue(is_subdomain("google.com", "google.com"))
        self.assertTrue(is_subdomain(".google.com.", "google.com"))
        self.assertFalse(is_subdomain("a.google.com.", "b.google.com."))
        self.assertFalse(is_subdomain("a.google.com.", "wp.pl."))
