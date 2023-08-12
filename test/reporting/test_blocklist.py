import unittest


class BlocklistTest(unittest.TestCase):
    def test_target_matching(self):
        report1 = Report(target="http://example.com/url1/")
        report2 = Report(target="http://example.com/url2/")
        blocklist_item = BlocklistItem(
            target_should_contain="/url1")
        )
        self.assertEqual(filter_blocklist([report1, report2], [blocklist_item]), [report2])
    
    def test_ip_range_matching(self):
        report1 = Report(target="http://example.com/", target_ip="1.1.1.1")
        report2 = Report(target="http://example.com/", target_ip="1.1.1.2")
        blocklist_item1 = BlocklistItem(
            ip_range="1.1.1.1/32",
        )
        self.assertEqual(filter_blocklist([report1, report2], [blocklist_item1]), [report2])
        blocklist_item2 = BlocklistItem(
            ip_range="1.0.0.0/8",
        )
        self.assertEqual(filter_blocklist([report1, report2], [blocklist_item2]), [report2])
    
    def test_domain_matching(self):
        report1 = Report(target="http://example.com/", top_level_target="www.example.com")
        report2 = Report(target="http://example.com/", top_level_target="ftp.example.com")
        blocklist_item = BlocklistItem(
            domain="www.example.com",
        )
        self.assertEqual(filter_blocklist([report1, report2], [blocklist_item]), [report2])

        report1 = Report(target="http://example.com/", last_domain="www.example.com", top_level_target="example.com")
        report2 = Report(target="http://example.com/", last_domain="ftp.example.com", top_level_target="example.com")
        blocklist_item = BlocklistItem(
            domain="www.example.com",
        )
        self.assertEqual(filter_blocklist([report1, report2], [blocklist_item]), [report2])
    
    def test_report_type_matching(self):
        report1 = Report(target="example.com", top_level_target="www.example.com", report_type="zone_transfer_possible")
        report2 = Report(target="http://example.com/", top_level_target="ftp.example.com", report_type="exposed_configuration_file")
        blocklist_item = BlocklistItem(
            report_type="zone_transfer_possible",
        )
        self.assertEqual(filter_blocklist([report1, report2], [blocklist_item]), [report2])
    
    def test_expiry(self):
        report1 = Report(target="http://example.com/1", timestamp=datetime.datetime(2023, 1, 1), report_type="exposed_configuration_file"))
        report2 = Report(target="http://example.com/2", timestamp=datetime.datetime(2023, 1, 10), report_type="exposed_configuration_file"))
        blocklist_item = BlocklistItem(
            report_type="exposed_configuration_file",
            until=datetime.datetime(2023, 1, 9),
        )
        self.assertEqual(filter_blocklist([report1, report2], [blocklist_item]), [report2])
