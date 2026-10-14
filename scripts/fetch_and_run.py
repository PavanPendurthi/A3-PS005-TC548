"""
Team PRISM — PS-005
One-shot: download a RouteViews MRT file + ROA snapshot, then run the full pipeline.

Usage:
  python scripts/fetch_and_run.py                  # downloads today's latest MRT
  python scripts/fetch_and_run.py --date 2024.06   # specific month
  python scripts/fetch_and_run.py --skip-ml        # skip ML training
"""

import sys
import bz2
import gzip
import logging
import argparse
import datetime
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s [%(levelname)s] %(message)s",
    handlers = [
        logging.StreamHandler(),
        logging.FileHandler("reports/fetch_and_run.log"),
    ]
)
logger = logging.getLogger(__name__)

Path("reports").mkdir(exist_ok=True)

# ─── RouteViews collector list (pick closest / most reliable) ─────────────────
ROUTEVIEWS_COLLECTORS = [
    "http://archive.routeviews.org/bgpdata",          # global mix
    "http://archive.routeviews.org/route-views.linx/bgpdata",  # London
    "http://archive.routeviews.org/route-views.sg/bgpdata",    # Singapore
]


def pick_mrt_url(year_month: str) -> str:
    """
    Build a URL for the first UPDATE file of the given month.
    year_month format: '2024.06'
    """
    base  = ROUTEVIEWS_COLLECTORS[0]
    return f"{base}/{year_month}/UPDATES/updates.{year_month.replace('.', '')[:6]}01.0000.bz2"


def download_file(url: str, dest: Path) -> Path:
    """Download url → dest, with progress logging. Returns dest path."""
    logger.info(f"Downloading: {url}")
    logger.info(f"       → to: {dest}")
    dest.parent.mkdir(parents=True, exist_ok=True)

    try:
        def report(count, block, total):
            if total > 0 and count % 50 == 0:
                pct = min(100, count * block * 100 // total)
                mb  = count * block / 1_048_576
                logger.info(f"  {pct}% ({mb:.1f} MB)")

        urllib.request.urlretrieve(url, dest, reporthook=report)
        size_mb = dest.stat().st_size / 1_048_576
        logger.info(f"Download complete: {size_mb:.1f} MB")
        return dest

    except Exception as e:
        logger.error(f"Download failed: {e}")
        logger.error("Possible reasons:")
        logger.error("  • RouteViews archive may block cloud IPs")
        logger.error("  • Try downloading manually and passing --mrt <path>")
        logger.error("  • Falling back to synthetic data mode")
        return None


def decompress_if_needed(path: Path) -> Path:
    """Decompress .bz2 or .gz file in place. Returns path to raw MRT."""
    if path.suffix == ".bz2":
        out = path.with_suffix("")
        if out.exists():
            logger.info(f"Already decompressed: {out}")
            return out
        logger.info(f"Decompressing {path.name} ...")
        with bz2.open(path, "rb") as f_in, open(out, "wb") as f_out:
            while chunk := f_in.read(1 << 20):  # 1 MB chunks
                f_out.write(chunk)
        size_mb = out.stat().st_size / 1_048_576
        logger.info(f"Decompressed: {size_mb:.1f} MB → {out}")
        return out

    elif path.suffix == ".gz":
        out = path.with_suffix("")
        if out.exists():
            return out
        logger.info(f"Decompressing {path.name} ...")
        with gzip.open(path, "rb") as f_in, open(out, "wb") as f_out:
            while chunk := f_in.read(1 << 20):
                f_out.write(chunk)
        return out

    return path   # already raw


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Team PRISM — fetch data + run pipeline")
    parser.add_argument("--date",     default=None,
                        help="Year-month to fetch, e.g. 2024.06 (default: last month)")
    parser.add_argument("--mrt",      default=None,
                        help="Skip download, use this local MRT file instead")
    parser.add_argument("--skip-ml",  action="store_true")
    parser.add_argument("--synthetic-only", action="store_true",
                        help="Skip MRT entirely, use synthetic data")
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("  Team PRISM — PS-005  |  Fetch & Run")
    logger.info("=" * 60)

    # ── Step 1: ROA snapshot ────────────────────────────────────────────────
    from src.roa_loader import ROATable
    roa_table = ROATable()
    cache     = Path("data/roa_snapshots/roa_snapshot.json")

    if cache.exists():
        logger.info(f"ROA cache found ({cache}) — loading")
        roa_table.load_from_file(cache)
    else:
        logger.info("Fetching ROA snapshot from Cloudflare RPKI...")
        roa_table.load_from_cloudflare(cache_path=cache)
    logger.info(f"ROA table: {len(roa_table)} entries loaded")

    # ── Step 2: BGP data ────────────────────────────────────────────────────
    mrt_path = None

    if args.synthetic_only:
        logger.info("--synthetic-only flag set, skipping MRT download")

    elif args.mrt:
        mrt_path = Path(args.mrt)
        logger.info(f"Using provided MRT file: {mrt_path}")

    else:
        # Determine which month to fetch
        if args.date:
            year_month = args.date
        else:
            # Default: last month (current month's archive is often incomplete)
            today      = datetime.date.today().replace(day=1)
            last_month = (today - datetime.timedelta(days=1)).replace(day=1)
            year_month = last_month.strftime("%Y.%m")

        url      = pick_mrt_url(year_month)
        filename = url.split("/")[-1]
        dest     = Path("data/bgp_feeds") / filename

        if dest.exists():
            logger.info(f"MRT archive already downloaded: {dest}")
            compressed = dest
        else:
            compressed = download_file(url, dest)

        if compressed:
            mrt_path = decompress_if_needed(compressed)
        else:
            logger.warning("MRT download failed — falling back to synthetic data")

    # ── Step 3: Run pipeline ────────────────────────────────────────────────
    from src.bgp_parser import stream_updates, parse_synthetic_file
    from src.synthetic_injector import SyntheticInjector
    from src.detector import BGPHijackDetector
    from src.evaluator import Evaluator
    from config.settings import OPERATOR_ASNS, ALERTS_OUTPUT, METRICS_OUTPUT
    from config.settings import SYNTHETIC_HIJACK_COUNT, SYNTHETIC_LEGIT_COUNT

    if mrt_path and mrt_path.exists():
        # ── Real MRT mode ────────────────────────────────────────────────
        logger.info(f"\n>>> REAL MRT MODE: {mrt_path}")
        logger.info("Streaming BGP updates (this may take 1–3 min for large files)...")
        updates    = list(stream_updates([mrt_path]))
        raw_events = None
        logger.info(f"Parsed {len(updates):,} BGP updates from MRT dump")

        detector = BGPHijackDetector(roa_table, operator_asns=OPERATOR_ASNS)
        alerts   = detector.process_stream(iter(updates))
        detector.save_alerts(ALERTS_OUTPUT)

        logger.info(f"\n{'='*50}")
        logger.info(f"Real MRT results:")
        logger.info(f"  Total updates : {len(updates):,}")
        logger.info(f"  Total alerts  : {len(alerts):,}")
        by_rule = {}
        for a in alerts:
            by_rule[a.rule] = by_rule.get(a.rule, 0) + 1
        for rule, cnt in sorted(by_rule.items(), key=lambda x: -x[1]):
            logger.info(f"  {rule:30s}: {cnt}")
        logger.info(f"{'='*50}")
        logger.info(f"Alerts saved to {ALERTS_OUTPUT}")
        logger.info("(No precision/recall available for real data — no ground truth labels)")

    else:
        # ── Synthetic mode ───────────────────────────────────────────────
        logger.info("\n>>> SYNTHETIC MODE: generating labeled test events")
        synth_path = Path("data/synthetic/events.json")

        if not synth_path.exists():
            injector = SyntheticInjector(roa_table)
            raw      = injector.generate(
                hijack_count = SYNTHETIC_HIJACK_COUNT,
                legit_count  = SYNTHETIC_LEGIT_COUNT,
                output_path  = synth_path,
            )
        else:
            import json
            raw = json.loads(synth_path.read_text())
            logger.info(f"Loaded {len(raw)} existing synthetic events")

        updates  = list(parse_synthetic_file(synth_path))
        detector = BGPHijackDetector(roa_table, operator_asns=OPERATOR_ASNS)
        alerts   = detector.process_stream(iter(updates))
        detector.save_alerts(ALERTS_OUTPUT)

        ev      = Evaluator(raw, alerts)
        metrics = ev.compute()
        ev.save_metrics(METRICS_OUTPUT, metrics)
        print(metrics)

    # ── Step 4: Optional ML ─────────────────────────────────────────────────
    if not args.skip_ml and mrt_path is None:
        logger.info("\n>>> ML PHASE")
        try:
            from sklearn.model_selection import train_test_split
            from sklearn.metrics import classification_report
            from src.ml_model import RandomForestDetector

            label_map = {"HIJACK": 1, "LEGIT": 0}
            labeled   = [(u, label_map[u.label]) for u in updates if u.label in label_map]

            if labeled:
                ul, yl = zip(*labeled)
                X_tr, X_te, y_tr, y_te = train_test_split(
                    list(ul), list(yl), train_size=0.75,
                    random_state=42, stratify=yl
                )
                clf = RandomForestDetector()
                clf.fit(X_tr, y_tr, roa_table)
                clf.save("models/rf_hijack_detector.pkl")
                y_pred = clf.predict(X_te)
                report = classification_report(y_te, y_pred,
                                               target_names=["LEGIT", "HIJACK"])
                logger.info(f"Random Forest:\n{report}")
                Path("reports/ml_report.txt").write_text(report)
                logger.info("ML report saved to reports/ml_report.txt")
        except ImportError:
            logger.warning("scikit-learn not installed. "
                           "Run: pip install scikit-learn --break-system-packages")

    logger.info("\n✓ Done. Output files:")
    logger.info(f"  Alerts  → {ALERTS_OUTPUT}")
    if Path(METRICS_OUTPUT).exists():
        logger.info(f"  Metrics → {METRICS_OUTPUT}")
    logger.info(f"  Log     → reports/fetch_and_run.log")


if __name__ == "__main__":
    main()
