from artemis.reporting.modules.wordpress_plugins.cpe_map import download_cpe_map

import unittest

class TestDownloadCPEMap(unittest.TestCase):
    def test_download_cpe_map(self) -> None:
        data = download_cpe_map()
        self.assertTrue(len(data) > 1500)
        self.assertEqual(data["woocommerce"], "cpe:2.3:a:woocommerce:woocommerce:*:*:*:*:*:wordpress:*:*")
