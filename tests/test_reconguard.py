import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

import reconguard

FIXTURES = Path(__file__).parent / "fixtures"


def read_xml(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


def record_from(parsed, timestamp):
    return {
        "target": "192.0.2.10",
        "scan_ip": "192.0.2.10",
        "timestamp": timestamp,
        "results": parsed["results"],
        "coverage": {
            "coverage_known": True,
            "ports_scanned_ranges": parsed["port_ranges"],
            "ports_checked": parsed["ports_checked"],
        },
    }


class ParseNmapXMLTests(unittest.TestCase):
    def test_parses_open_closed_and_extraports(self):
        parsed = reconguard.parse_nmap_xml(read_xml("nmap_same_coverage_old.xml"))
        self.assertEqual(parsed["ports_checked"], 3)
        self.assertEqual(parsed["port_ranges"], "22,80,443")
        self.assertEqual(parsed["counts"]["OPEN"], 1)
        self.assertEqual(parsed["counts"]["CLOSED"], 2)
        self.assertEqual(parsed["results"][0]["port"], 22)
        self.assertEqual(parsed["results"][0]["status"], "OPEN")

    def test_invalid_xml_raises_parse_error(self):
        with self.assertRaises(ET.ParseError):
            reconguard.parse_nmap_xml("<nmaprun>")

    def test_coverage_metadata_records_ranges_and_flags(self):
        parsed = reconguard.parse_nmap_xml(read_xml("nmap_same_coverage_old.xml"))
        parsed["nmap_flags"] = ["-sT", "-Pn", "-p", "22,80,443"]
        coverage = reconguard.port_selection_metadata(
            "22,80,443", "Custom ports", parsed, False
        )
        self.assertTrue(coverage["coverage_known"])
        self.assertEqual(coverage["ports_scanned_ranges"], "22,80,443")
        self.assertEqual(coverage["nmap_flags"], ["-sT", "-Pn", "-p", "22,80,443"])


class ScanComparisonTests(unittest.TestCase):
    def test_reports_changes_only_in_shared_coverage(self):
        old = record_from(reconguard.parse_nmap_xml(read_xml("nmap_same_coverage_old.xml")), "old")
        new = record_from(reconguard.parse_nmap_xml(read_xml("nmap_same_coverage_new.xml")), "new")
        result = reconguard.compare_scan_records(old, new)
        self.assertTrue(result["coverage_comparable"])
        self.assertEqual(result["common_coverage_count"], 3)
        self.assertEqual([item["port"] for item in result["newly_open"]], [80])
        self.assertEqual([item["port"] for item in result["no_longer_open"]], [22])

    def test_unknown_coverage_does_not_claim_open_port_changes(self):
        old = {"results": [{"port": 22, "protocol": "tcp", "status": "OPEN"}], "coverage": {}}
        new = {"results": [], "coverage": {}}
        result = reconguard.compare_scan_records(old, new)
        self.assertFalse(result["coverage_comparable"])
        self.assertEqual(result["newly_open"], [])
        self.assertEqual(result["no_longer_open"], [])
        self.assertIsNotNone(result["coverage_warning"])

    def test_different_coverage_limits_comparison_to_intersection(self):
        old = {
            "results": [{"port": 22, "protocol": "tcp", "status": "OPEN"}],
            "coverage": {"coverage_known": True, "ports_scanned_ranges": "22,80", "ports_checked": 2},
        }
        new = {
            "results": [{"port": 22, "protocol": "tcp", "status": "OPEN"}, {"port": 443, "protocol": "tcp", "status": "OPEN"}],
            "coverage": {"coverage_known": True, "ports_scanned_ranges": "22,443", "ports_checked": 2},
        }
        result = reconguard.compare_scan_records(old, new)
        self.assertTrue(result["coverage_comparable"])
        self.assertEqual(result["common_coverage_count"], 1)
        self.assertEqual(result["newly_open"], [])
        self.assertIsNotNone(result["coverage_warning"])


class InputValidationTests(unittest.TestCase):
    def test_rejects_full_urls_invalid_hosts_and_option_like_targets(self):
        invalid_targets = (
            "https://example.com",
            "example.com/path",
            "127.0.0.1:80",
            "bad..host",
            "-oN /tmp/x",
            "-F",
            "-example.com",
            "",
        )

        for value in invalid_targets:
            with self.subTest(value=value):
                self.assertFalse(reconguard.validate_target(value))

    def test_port_range_parser(self):
        self.assertEqual(reconguard.parse_port_ranges("22,80,443-444"), {22, 80, 443, 444})
        self.assertEqual(reconguard.parse_port_ranges("22,,80"), set())
        self.assertEqual(reconguard.parse_port_ranges("0,80"), set())


if __name__ == "__main__":
    unittest.main()
