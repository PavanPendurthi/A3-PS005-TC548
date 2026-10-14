"""
Team PRISM — PS-005
Unit tests for the rule-based detector.

Run: python -m pytest tests/ -v
"""

import sys
import datetime
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.roa_loader import ROATable, ROAEntry
from src.bgp_parser import BGPUpdate
from src.detector import BGPHijackDetector


def make_update(prefix, origin_asn, as_path=None, ts=None):
    return BGPUpdate(
        timestamp  = ts or datetime.datetime(2024, 6, 1),
        prefix     = prefix,
        origin_asn = origin_asn,
        as_path    = as_path or [65001, origin_asn],
        label      = None,
        source     = "test",
    )


def make_roa_table(*entries):
    """Build a ROATable from (prefix, asn, maxlen) tuples."""
    table = ROATable()
    for prefix, asn, maxlen in entries:
        table._entries.append(ROAEntry(prefix, asn, maxlen))
    return table


class TestOriginMismatch(unittest.TestCase):

    def setUp(self):
        # ROA: 192.0.2.0/24 belongs to AS65001
        self.roa_table = make_roa_table(("192.0.2.0/24", 65001, 24))
        self.detector  = BGPHijackDetector(self.roa_table)

    def test_valid_announcement_no_alert(self):
        update = make_update("192.0.2.0/24", 65001)
        alert  = self.detector.check(update)
        self.assertIsNone(alert, "Valid announcement should not fire an alert")

    def test_origin_mismatch_fires_alert(self):
        update = make_update("192.0.2.0/24", 99999)   # wrong ASN
        alert  = self.detector.check(update)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.rule, "ORIGIN_MISMATCH")
        self.assertEqual(alert.severity, "HIGH")
        self.assertEqual(alert.origin_asn, 99999)

    def test_unknown_prefix_no_roa(self):
        update = make_update("10.0.0.0/8", 65001)     # no ROA for this prefix
        alert  = self.detector.check(update)
        # Should not fire HIGH alert (no operator filter in test)
        # Since operator_asns is empty, _is_operator_prefix returns True → UNKNOWN_PREFIX
        if alert:
            self.assertEqual(alert.rule, "UNKNOWN_PREFIX")


class TestSubprefixHijack(unittest.TestCase):

    def setUp(self):
        # ROA: 103.75.0.0/16 belongs to AS9498
        self.roa_table = make_roa_table(("103.75.0.0/16", 9498, 16))
        self.detector  = BGPHijackDetector(self.roa_table)

    def test_subprefix_from_wrong_asn_fires_alert(self):
        # More specific /24 from a different ASN
        update = make_update("103.75.4.0/24", 64512)
        alert  = self.detector.check(update)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.rule, "SUBPREFIX_HIJACK")
        self.assertEqual(alert.severity, "HIGH")

    def test_subprefix_from_correct_asn_no_alert(self):
        # ROA maxlen = 16 only, so /24 from right ASN is still invalid per RPKI
        # but our rule-based check only fires SUBPREFIX_HIJACK on wrong ASN
        roa_table = make_roa_table(("103.75.0.0/16", 9498, 24))  # maxlen=24 ok
        detector  = BGPHijackDetector(roa_table)
        update    = make_update("103.75.4.0/24", 9498)
        alert     = detector.check(update)
        self.assertIsNone(alert)

    def test_exact_prefix_from_correct_asn_no_alert(self):
        update = make_update("103.75.0.0/16", 9498)
        alert  = self.detector.check(update)
        self.assertIsNone(alert)


class TestAlertAccumulation(unittest.TestCase):

    def test_multiple_alerts_accumulated(self):
        roa_table = make_roa_table(("192.168.0.0/16", 65001, 16))
        detector  = BGPHijackDetector(roa_table)

        updates = [
            make_update("192.168.0.0/16", 99001),   # mismatch
            make_update("192.168.0.0/16", 65001),   # valid
            make_update("192.168.1.0/24", 99002),   # subprefix hijack
        ]
        for u in updates:
            detector.check(u)

        self.assertEqual(len(detector.alerts), 2)   # 2 hijacks, 1 legit
        rules = {a.rule for a in detector.alerts}
        self.assertIn("ORIGIN_MISMATCH",   rules)
        self.assertIn("SUBPREFIX_HIJACK",  rules)


if __name__ == "__main__":
    unittest.main(verbosity=2)
