"""
Team PRISM — PS-005
BGP Update parser — reads MRT dump files and synthetic event streams.

Supports:
  - Real MRT files via mrtparse (pip install mrtparse)
  - Synthetic JSON event files (for testing / injection)
"""

import json
import logging
import datetime
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class BGPUpdate:
    """A single BGP UPDATE announcement parsed from the feed."""
    timestamp:  datetime.datetime
    prefix:     str
    origin_asn: int
    as_path:    List[int]        = field(default_factory=list)
    peer_ip:    str              = ""
    peer_asn:   int              = 0
    label:      Optional[str]    = None   # ground-truth label for synthetic events
    source:     str              = "mrt"  # 'mrt' | 'synthetic'

    @property
    def prefix_len(self) -> int:
        try:
            return ipaddress.ip_network(self.prefix, strict=False).prefixlen
        except ValueError:
            return -1

    @property
    def is_ipv6(self) -> bool:
        try:
            return isinstance(ipaddress.ip_network(self.prefix, strict=False),
                              ipaddress.IPv6Network)
        except ValueError:
            return False


# ─── MRT parser (real RouteViews / RIPE RIS data) ────────────────────────────

def parse_mrt_file(path: Path) -> Iterator[BGPUpdate]:
    """
    Yield BGPUpdate objects from a .bz2 or raw MRT dump.
    Requires: pip install mrtparse
    """
    try:
        import mrtparse
    except ImportError:
        raise ImportError("mrtparse not installed. Run: pip install mrtparse --break-system-packages")

    reader = mrtparse.Reader(str(path))
    for entry in reader:
        try:
            data = entry.data
            ts   = datetime.datetime.utcfromtimestamp(data.get("timestamp", 0))

            # TABLE_DUMP_V2 RIB entries
            if "prefix" in data and "entries" in data:
                prefix = data["prefix"] + "/" + str(data["prefix_length"])
                for rib_entry in data["entries"]:
                    attrs   = {a["type"][1]: a for a in rib_entry.get("path_attributes", [])}
                    as_path = _extract_as_path(attrs)
                    if as_path:
                        yield BGPUpdate(
                            timestamp  = ts,
                            prefix     = prefix,
                            origin_asn = as_path[-1],
                            as_path    = as_path,
                            peer_ip    = rib_entry.get("peer_ip", ""),
                            peer_asn   = rib_entry.get("peer_as", 0),
                        )

            # BGP4MP UPDATE messages
            elif "bgp_message" in data:
                msg = data["bgp_message"]
                if msg.get("type", [None])[-1] != "UPDATE":
                    continue
                attrs   = {a["type"][1]: a for a in msg.get("path_attributes", [])}
                as_path = _extract_as_path(attrs)
                if not as_path:
                    continue
                for nlri in msg.get("nlri", []):
                    prefix = nlri["prefix"] + "/" + str(nlri["prefix_length"])
                    yield BGPUpdate(
                        timestamp  = ts,
                        prefix     = prefix,
                        origin_asn = as_path[-1],
                        as_path    = as_path,
                        peer_ip    = data.get("peer_ip", ""),
                        peer_asn   = data.get("peer_as", 0),
                    )
        except Exception as e:
            logger.debug(f"Skipping malformed MRT entry: {e}")
            continue


def _extract_as_path(attrs: dict) -> List[int]:
    """Extract the AS_PATH sequence from parsed path attributes."""
    ap = attrs.get("AS_PATH") or attrs.get("AS4_PATH")
    if not ap:
        return []
    for seg in ap.get("value", []):
        if seg.get("type", [None])[-1] in ("AS_SEQUENCE", 2):
            return [int(a) for a in seg.get("value", [])]
    return []


# ─── Synthetic event loader (JSON) ───────────────────────────────────────────

def parse_synthetic_file(path: Path) -> Iterator[BGPUpdate]:
    """
    Yield BGPUpdate objects from a synthetic JSON event file.
    Expected format: list of dicts with keys:
      timestamp (ISO string or unix), prefix, origin_asn, as_path (optional),
      label ("HIJACK" | "LEGIT")
    """
    events = json.loads(path.read_text())
    for ev in events:
        try:
            ts_raw = ev.get("timestamp", 0)
            if isinstance(ts_raw, (int, float)):
                ts = datetime.datetime.utcfromtimestamp(ts_raw)
            else:
                ts = datetime.datetime.fromisoformat(ts_raw)

            yield BGPUpdate(
                timestamp  = ts,
                prefix     = ev["prefix"],
                origin_asn = int(ev["origin_asn"]),
                as_path    = [int(a) for a in ev.get("as_path", [ev["origin_asn"]])],
                label      = ev.get("label"),
                source     = "synthetic",
            )
        except Exception as e:
            logger.debug(f"Skipping synthetic event {ev}: {e}")


# ─── Unified stream ───────────────────────────────────────────────────────────

def stream_updates(paths: List[Path]) -> Iterator[BGPUpdate]:
    """Auto-detect file type and yield BGPUpdates from multiple files in order."""
    for path in paths:
        suffix = path.suffix.lower()
        if suffix in (".json",):
            logger.info(f"Reading synthetic file: {path}")
            yield from parse_synthetic_file(path)
        elif suffix in (".mrt", ".bz2", ".gz", ""):
            logger.info(f"Reading MRT file: {path}")
            yield from parse_mrt_file(path)
        else:
            logger.warning(f"Unknown file type: {path} — attempting MRT")
            yield from parse_mrt_file(path)
