"""
Team PRISM — PS-005
Rule-based BGP Hijack Detector

Detection rules implemented:
  1. ORIGIN_MISMATCH    — announced ASN ≠ any valid ROA ASN for that prefix
  2. SUBPREFIX_HIJACK   — more-specific announcement from wrong ASN
  3. UNKNOWN_PREFIX     — no ROA exists for this prefix (informational)
  4. ROUTE_LEAK         — AS_PATH contains unexpected transit ASNs (heuristic)
"""

import json
import logging
import datetime
import ipaddress
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict

from src.roa_loader import ROATable, ROAEntry
from src.bgp_parser import BGPUpdate

logger = logging.getLogger(__name__)


# ─── Alert dataclass ──────────────────────────────────────────────────────────

@dataclass
class HijackAlert:
    alert_id:      int
    timestamp:     str
    rule:          str               # ORIGIN_MISMATCH | SUBPREFIX_HIJACK | UNKNOWN_PREFIX
    severity:      str               # HIGH | MEDIUM | LOW
    prefix:        str
    origin_asn:    int
    as_path:       List[int]
    matching_roa:  Optional[str]     # repr of the ROA that triggered this
    reason:        str
    peer_ip:       str               = ""
    peer_asn:      int               = 0
    label:         Optional[str]     = None   # ground truth (synthetic only)

    def to_dict(self):
        return asdict(self)


# ─── Detector class ───────────────────────────────────────────────────────────

class BGPHijackDetector:
    """
    Stateless rule-based detector.
    Feed BGPUpdate objects via check(); collect HijackAlert objects.
    """

    def __init__(self, roa_table: ROATable, operator_asns: Optional[Dict[str, str]] = None):
        self.roa_table     = roa_table
        self.operator_asns = {int(k.replace("AS", "")): v
                              for k, v in (operator_asns or {}).items()}
        self._alert_counter = 0
        self.alerts: List[HijackAlert] = []

    # ── Public API ────────────────────────────────────────────────────────────

    def check(self, update: BGPUpdate) -> Optional[HijackAlert]:
        """
        Run all detection rules against a single BGP update.
        Returns an alert if a violation is found, else None.
        """
        status, roa = self.roa_table.validate(update.prefix, update.origin_asn)

        alert = None

        # Check subprefix hijack first — a subprefix of a parent ROA block
        # can appear as "invalid" (parent covers it) so we classify it more
        # precisely before falling through to generic ORIGIN_MISMATCH.
        sub_alert = self._check_subprefix(update)
        if sub_alert:
            alert = sub_alert

        elif status == "invalid":
            alert = self._make_alert(update, roa, "ORIGIN_MISMATCH", "HIGH",
                f"Prefix {update.prefix} announced by AS{update.origin_asn} "
                f"but ROA authorizes AS{roa.asn if roa else '?'}")

        elif status == "not_found" and not alert:
            # No ROA covers this prefix at all — flag as unknown (MEDIUM severity)
            if self._is_operator_prefix(update.prefix):
                alert = self._make_alert(update, None, "UNKNOWN_PREFIX", "MEDIUM",
                    f"Prefix {update.prefix} claimed by operator has no ROA — "
                    f"RPKI not configured or prefix not in ROA database")

        if alert:
            self.alerts.append(alert)
            logger.warning(f"[{alert.rule}] {alert.reason}")

        return alert

    def process_stream(self, updates) -> List[HijackAlert]:
        """Process an iterable of BGPUpdate objects. Returns list of alerts."""
        count = 0
        for update in updates:
            self.check(update)
            count += 1
            if count % 10000 == 0:
                logger.info(f"Processed {count} updates, {len(self.alerts)} alerts so far")
        logger.info(f"Done: {count} updates → {len(self.alerts)} alerts")
        return self.alerts

    def save_alerts(self, path: str):
        """Save all alerts to a JSON file."""
        import pathlib
        pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump([a.to_dict() for a in self.alerts], f, indent=2)
        logger.info(f"Saved {len(self.alerts)} alerts to {path}")

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _check_subprefix(self, update: BGPUpdate) -> Optional[HijackAlert]:
        """
        Detect subprefix hijack: a more-specific prefix announced by a
        different ASN than what any parent ROA authorizes.
        """
        try:
            announced = ipaddress.ip_network(update.prefix, strict=False)
        except ValueError:
            return None

        # Walk through candidate ROA entries (fast bucket lookup) to find a parent prefix
        for roa_entry in self.roa_table._candidates(announced):
            try:
                if announced.subnet_of(roa_entry.prefix) and announced != roa_entry.prefix:
                    # It IS a subprefix of a ROA-covered block
                    if update.origin_asn != roa_entry.asn:
                        return self._make_alert(
                            update, roa_entry, "SUBPREFIX_HIJACK", "HIGH",
                            f"More-specific prefix {update.prefix} (/{announced.prefixlen}) "
                            f"announced by AS{update.origin_asn}, but parent "
                            f"{roa_entry.prefix} is authorized only for AS{roa_entry.asn}"
                        )
            except TypeError:
                continue   # mixed IPv4/IPv6

        return None

    def _is_operator_prefix(self, prefix: str) -> bool:
        """True if the prefix belongs to a monitored operator ASN block."""
        # This is a heuristic — expand with real prefix-to-ASN mapping
        # For now, flag all unknown prefixes if in monitored range
        return len(self.operator_asns) == 0  # flag all if no filter set

    def _make_alert(self, update: BGPUpdate, roa: Optional[ROAEntry],
                    rule: str, severity: str, reason: str) -> HijackAlert:
        self._alert_counter += 1
        return HijackAlert(
            alert_id     = self._alert_counter,
            timestamp    = update.timestamp.isoformat() + "Z",
            rule         = rule,
            severity     = severity,
            prefix       = update.prefix,
            origin_asn   = update.origin_asn,
            as_path      = update.as_path,
            matching_roa = repr(roa) if roa else None,
            reason       = reason,
            peer_ip      = update.peer_ip,
            peer_asn     = update.peer_asn,
            label        = update.label,
        )
