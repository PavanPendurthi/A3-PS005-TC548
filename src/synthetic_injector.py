"""
Team PRISM — PS-005
Synthetic BGP Event Injector

Generates labeled hijack and legitimate events for detector evaluation.
Outputs a JSON file consumable by bgp_parser.parse_synthetic_file().
"""

import json
import random
import logging
import datetime
import ipaddress
from pathlib import Path
from typing import List, Dict, Tuple

from src.roa_loader import ROATable

logger = logging.getLogger(__name__)


class SyntheticInjector:
    """
    Builds a labeled dataset of BGP announcements.
    Hijack events are crafted to trigger detector rules.
    Legit events include multi-origin (anycast) edge cases.
    """

    HIJACKER_ASN_POOL = list(range(64512, 64600))  # private ASN range
    BASE_TIMESTAMP    = datetime.datetime(2024, 6, 1, 0, 0, 0)

    def __init__(self, roa_table: ROATable, seed: int = 42):
        self.roa_table = roa_table
        random.seed(seed)
        self._ts_offset = 0   # seconds from BASE_TIMESTAMP

    def _next_ts(self) -> str:
        self._ts_offset += random.randint(5, 30)
        return (self.BASE_TIMESTAMP +
                datetime.timedelta(seconds=self._ts_offset)).isoformat()

    # ── Hijack event generators ───────────────────────────────────────────────

    def _make_origin_mismatch(self, roa_prefix: str, legit_asn: int) -> dict:
        """Announce an ROA-covered prefix from a wrong ASN."""
        hijacker = random.choice(self.HIJACKER_ASN_POOL)
        return {
            "timestamp":  self._next_ts(),
            "prefix":     roa_prefix,
            "origin_asn": hijacker,
            "as_path":    [65001, 65002, hijacker],
            "label":      "HIJACK",
            "attack_type": "ORIGIN_MISMATCH",
            "note":       f"Legit ASN={legit_asn}, hijacker ASN={hijacker}"
        }

    def _make_subprefix_hijack(self, parent_prefix: str, legit_asn: int) -> dict:
        """Announce a more-specific sub-prefix from a hijacker ASN."""
        try:
            net = ipaddress.ip_network(parent_prefix, strict=False)
            subnets = list(net.subnets())
            if not subnets:
                return None
            sub = str(random.choice(subnets))
        except Exception:
            return None

        hijacker = random.choice(self.HIJACKER_ASN_POOL)
        return {
            "timestamp":   self._next_ts(),
            "prefix":      sub,
            "origin_asn":  hijacker,
            "as_path":     [65010, hijacker],
            "label":       "HIJACK",
            "attack_type": "SUBPREFIX_HIJACK",
            "note":        f"Parent={parent_prefix}, legit ASN={legit_asn}"
        }

    # ── Legit event generators ────────────────────────────────────────────────

    def _make_legit_announcement(self, roa_prefix: str, legit_asn: int) -> dict:
        """Valid announcement — correct ASN, correct prefix."""
        return {
            "timestamp":  self._next_ts(),
            "prefix":     roa_prefix,
            "origin_asn": legit_asn,
            "as_path":    [65100, 65101, legit_asn],
            "label":      "LEGIT",
            "attack_type": None,
            "note":       "Normal valid announcement"
        }

    def _make_anycast_legit(self, roa_prefix: str, legit_asn: int) -> dict:
        """
        Multi-origin anycast announcement — same prefix, multiple valid ASNs.
        This is a known false-positive trap for naive detectors.
        """
        # Simulate a CDN that has multiple ASNs authorized via multiple ROAs
        # (In production, both ASNs would appear in the ROA table)
        return {
            "timestamp":  self._next_ts(),
            "prefix":     roa_prefix,
            "origin_asn": legit_asn,
            "as_path":    [65200, legit_asn],
            "label":      "LEGIT",
            "attack_type": None,
            "note":       "Anycast — multiple ASNs serving same prefix (edge case)"
        }

    # ── Main generation method ────────────────────────────────────────────────

    def generate(self, hijack_count: int = 100, legit_count: int = 100,
                 output_path: Path = None) -> List[dict]:
        """
        Generate a balanced labeled dataset.
        Returns list of event dicts; optionally saves to JSON.
        """
        # Pull sample ROAs to build events around
        sample_roas = random.sample(
            self.roa_table._entries,
            min(200, len(self.roa_table._entries))
        )

        events = []

        # ── Hijack events ──────────────────────────────────────────────────
        per_type = hijack_count // 2
        for roa in random.choices(sample_roas, k=per_type):
            ev = self._make_origin_mismatch(str(roa.prefix), roa.asn)
            events.append(ev)

        for roa in random.choices(sample_roas, k=hijack_count - per_type):
            ev = self._make_subprefix_hijack(str(roa.prefix), roa.asn)
            if ev:
                events.append(ev)

        # ── Legit events ───────────────────────────────────────────────────
        anycast_count = legit_count // 5   # 20% are anycast edge cases
        plain_count   = legit_count - anycast_count

        for roa in random.choices(sample_roas, k=plain_count):
            ev = self._make_legit_announcement(str(roa.prefix), roa.asn)
            events.append(ev)

        for roa in random.choices(sample_roas, k=anycast_count):
            ev = self._make_anycast_legit(str(roa.prefix), roa.asn)
            events.append(ev)

        # Shuffle so hijacks and legits are interleaved
        random.shuffle(events)

        logger.info(f"Generated {len(events)} synthetic events "
                    f"({hijack_count} hijacks, {legit_count} legit)")

        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps(events, indent=2))
            logger.info(f"Saved synthetic events to {output_path}")

        return events
