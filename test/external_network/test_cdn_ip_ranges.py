import ipaddress
import socket
import unittest
from typing import Any

from artemis.cdn_ip_ranges import (
    get_azure_front_door_ips,
    get_bunnycdn_ips,
    get_cloudflare_ips,
    get_cloudfront_ips,
    get_fastly_ips,
    is_cdn_ip,
)


class CdnIpRangesTest(unittest.TestCase):
    def _assert_non_empty_ip_networks(self, networks: list[Any]) -> None:
        self.assertGreater(len(networks), 0)
        for network in networks:
            self.assertIsInstance(network, (ipaddress.IPv4Network, ipaddress.IPv6Network))

    def test_is_cdn_ip(self) -> None:
        self.assertTrue(is_cdn_ip(socket.gethostbyname("cloudflare.com")))

    def test_azure_front_door_ips(self) -> None:
        self._assert_non_empty_ip_networks(get_azure_front_door_ips())

    def test_cloudflare_ips(self) -> None:
        cloudflare_ips = get_cloudflare_ips()
        self._assert_non_empty_ip_networks(cloudflare_ips)
        cloudflare_ip = ipaddress.IPv4Address(socket.gethostbyname("cloudflare.com"))
        self.assertTrue(any(cloudflare_ip in ip_range for ip_range in cloudflare_ips))

    def test_cloudfront_ips(self) -> None:
        self._assert_non_empty_ip_networks(get_cloudfront_ips())

    def test_fastly_ips(self) -> None:
        self._assert_non_empty_ip_networks(get_fastly_ips())

    def test_bunnycdn_ips(self) -> None:
        self._assert_non_empty_ip_networks(get_bunnycdn_ips())
