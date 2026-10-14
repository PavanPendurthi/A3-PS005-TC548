"""
Team PRISM — PS-005
Data download helper

Downloads:
  1. ROA snapshot from Cloudflare RPKI API
  2. (Optional) one BGP MRT dump from RouteViews for testing
"""

import sys
import logging
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.roa_loader import ROATable

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def download_roa(output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    cache = output_dir / "roa_snapshot.json"

    table = ROATable()
    count = table.load_from_cloudflare(cache_path=cache)
    logger.info(f"Downloaded {count} ROA entries → {cache}")


def main():
    parser = argparse.ArgumentParser(description="Download BGP/ROA data for PS-005")
    parser.add_argument("--roa-dir", default="data/roa_snapshots",
                        help="Directory to save ROA snapshot")
    args = parser.parse_args()

    logger.info("=== Team PRISM PS-005 — Data Download ===")
    download_roa(Path(args.roa_dir))
    logger.info("Done. Run scripts/run_pipeline.py next.")


if __name__ == "__main__":
    main()
