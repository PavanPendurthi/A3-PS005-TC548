"""
Team PRISM — PS-005
ROA (Route Origin Authorization) loader
Fetches and indexes RPKI ROA data for prefix-origin validation.
"""

import json
import logging
import ipaddress
import requests
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ROAEntry:
    """A single ROA record: prefix, allowed origin ASN, max-length."""

    def __init__(self, prefix: str, asn: int, max_length: int, ta: str = ""):
        self.prefix     = ipaddress.ip_network(prefix, strict=False)
        self.asn        = asn
        self.max_length = max_length
        self.ta         = ta          # Trust Anchor (ARIN, RIPE, APNIC …)

    def covers(self, announced: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
        """True if this ROA's prefix contains the announced prefix."""
        if announced.version != self.prefix.version:
            return False
        return announced.subnet_of(self.prefix)

    def validates(self, announced_prefix: str, origin_asn: int) -> str:
        """
        Returns:
          'valid'   — covered + ASN matches + length ok
          'invalid' — covered but ASN mismatch OR too-specific
          'not_found' — not covered (caller checks other ROAs)
        """
        try:
            net = ipaddress.ip_network(announced_prefix, strict=False)
        except ValueError:
            return "not_found"

        if not self.covers(net):
            return "not_found"

        if origin_asn != self.asn:
            return "invalid"

        if net.prefixlen > self.max_length:
            return "invalid"

        return "valid"

    def __repr__(self):
        return f"ROA({self.prefix}, ASN{self.asn}, maxlen={self.max_length})"


class ROATable:
    """
    In-memory index of all ROA entries with fast prefix lookup.
    Uses a dict bucketed by /8 for IPv4 and /32 for IPv6 to avoid
    a full linear scan on every validation call.
    """

    def __init__(self):
        self._entries: List[ROAEntry] = []
        # Bucket index: first_octet (IPv4) or first_32bits (IPv6) → [ROAEntry]
        self._v4_index: dict = {}   # int (network address >> 24) → list
        self._v6_index: dict = {}   # int (top 32 bits) → list
        self._indexed = False

    def load_from_cloudflare(self, cache_path: Optional[Path] = None) -> int:
        """Fetch ROAs from Cloudflare RPKI API. Optionally cache to disk."""
        url = "https://rpki.cloudflare.com/rpki.json"
        logger.info(f"Fetching ROAs from {url}")
        try:
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            logger.error(f"ROA fetch failed: {e}")
            if cache_path and cache_path.exists():
                logger.warning("Falling back to cached ROA file.")
                return self.load_from_file(cache_path)
            raise

        roas = data.get("roas", [])
        if cache_path:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(json.dumps(data, indent=2))
            logger.info(f"ROA snapshot cached to {cache_path}")

        self._parse_roa_list(roas)
        logger.info(f"Loaded {len(self._entries)} ROA entries.")
        return len(self._entries)

    def load_from_file(self, path: Path) -> int:
        """Load ROA snapshot from a previously cached JSON file."""
        data = json.loads(path.read_text())
        roas = data.get("roas", [])
        self._parse_roa_list(roas)
        logger.info(f"Loaded {len(self._entries)} ROA entries from {path}")
        return len(self._entries)

    def _build_index(self):
        """Build bucket index for fast supernet lookup."""
        self._v4_index.clear()
        self._v6_index.clear()
        for entry in self._entries:
            if entry.prefix.version == 4:
                # Index by each /8 supernet this prefix falls under
                key = int(entry.prefix.network_address) >> 24
                self._v4_index.setdefault(key, []).append(entry)
            else:
                key = int(entry.prefix.network_address) >> 96
                self._v6_index.setdefault(key, []).append(entry)
        self._indexed = True

    def _candidates(self, announced) -> List["ROAEntry"]:
        """Return only ROA entries that could possibly cover `announced`."""
        if not self._indexed:
            self._build_index()
        if announced.version == 4:
            key = int(announced.network_address) >> 24
            return self._v4_index.get(key, [])
        else:
            key = int(announced.network_address) >> 96
            return self._v6_index.get(key, [])

    def _parse_roa_list(self, roas: list):
        self._indexed = False
        for r in roas:
            try:
                entry = ROAEntry(
                    prefix     = r["prefix"],
                    asn        = int(str(r["asn"]).replace("AS", "")),
                    max_length = r.get("maxLength", ipaddress.ip_network(r["prefix"]).prefixlen),
                    ta         = r.get("ta", ""),
                )
                self._entries.append(entry)
            except Exception as e:
                logger.debug(f"Skipping malformed ROA {r}: {e}")

    def validate(self, prefix: str, origin_asn: int) -> Tuple[str, Optional[ROAEntry]]:
        """
        Validate a BGP announcement against all ROAs.

        Returns:
          ('valid',     matching_roa)   — at least one ROA says valid
          ('invalid',   first_invalid)  — covered but invalid
          ('not_found', None)           — no ROA covers this prefix
        """
        try:
            announced = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            return ("not_found", None)

        covering_roas = [e for e in self._candidates(announced) if e.covers(announced)]
        if not covering_roas:
            return ("not_found", None)

        for roa in covering_roas:
            result = roa.validates(prefix, origin_asn)
            if result == "valid":
                return ("valid", roa)

        # Covered but none valid → invalid
        return ("invalid", covering_roas[0])

    def get_all_prefixes_for_asn(self, asn: int) -> List[str]:
        """Return all prefixes authorized for a given ASN."""
        return [str(e.prefix) for e in self._entries if e.asn == asn]

    def __len__(self):
        return len(self._entries)
