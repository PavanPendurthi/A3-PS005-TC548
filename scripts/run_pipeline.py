"""
Team PRISM — PS-005
Main pipeline — end-to-end execution:

  Step 1: Load ROA table
  Step 2: Generate (or load) synthetic BGP events
  Step 3: Run rule-based detector
  Step 4: Evaluate against ground truth
  Step 5: (Optional) Train & evaluate ML model
  Step 6: Print metrics + save reports

Usage:
  python scripts/run_pipeline.py                         # full run with synthetic data
  python scripts/run_pipeline.py --mrt path/to/file.bz2 # run on real MRT dump
  python scripts/run_pipeline.py --skip-ml              # skip ML phase
"""

import sys
import logging
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config.settings import (
    OPERATOR_ASNS, ALERTS_OUTPUT, METRICS_OUTPUT,
    SYNTHETIC_HIJACK_COUNT, SYNTHETIC_LEGIT_COUNT,
    ML_MODEL_PATH, ML_RANDOM_STATE, ANOMALY_CONTAMINATION
)
from src.roa_loader import ROATable
from src.bgp_parser import stream_updates, parse_synthetic_file
from src.synthetic_injector import SyntheticInjector
from src.detector import BGPHijackDetector
from src.evaluator import Evaluator

logging.basicConfig(
    level    = logging.INFO,
    format   = "%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers = [
        logging.StreamHandler(),
        logging.FileHandler("reports/pipeline.log"),
    ]
)
logger = logging.getLogger(__name__)

Path("reports").mkdir(exist_ok=True)


# ─── Step 1: ROA table ────────────────────────────────────────────────────────

def load_roa_table() -> ROATable:
    table = ROATable()
    cache = Path("data/roa_snapshots/roa_snapshot.json")
    if cache.exists():
        logger.info(f"Loading ROA from cache: {cache}")
        table.load_from_file(cache)
    else:
        logger.info("Fetching fresh ROA snapshot from Cloudflare RPKI API...")
        table.load_from_cloudflare(cache_path=cache)
    logger.info(f"ROA table: {len(table)} entries")
    return table


# ─── Step 2: Events ───────────────────────────────────────────────────────────

def prepare_events(roa_table: ROATable, mrt_paths=None) -> tuple:
    """
    Returns (update_stream_list, raw_events_for_eval)
    raw_events_for_eval is None if using real MRT (no labels)
    """
    if mrt_paths:
        paths = [Path(p) for p in mrt_paths]
        return list(stream_updates(paths)), None

    # Synthetic mode
    synth_path = Path("data/synthetic/events.json")
    if not synth_path.exists():
        logger.info("Generating synthetic BGP events...")
        injector = SyntheticInjector(roa_table)
        raw = injector.generate(
            hijack_count = SYNTHETIC_HIJACK_COUNT,
            legit_count  = SYNTHETIC_LEGIT_COUNT,
            output_path  = synth_path,
        )
    else:
        import json
        raw = json.loads(synth_path.read_text())
        logger.info(f"Loaded {len(raw)} synthetic events from {synth_path}")

    updates = list(parse_synthetic_file(synth_path))
    return updates, raw


# ─── Step 3+4: Detect + Evaluate ─────────────────────────────────────────────

def run_detection(roa_table, updates, raw_events) -> tuple:
    detector = BGPHijackDetector(roa_table, operator_asns=OPERATOR_ASNS)
    alerts   = detector.process_stream(iter(updates))
    detector.save_alerts(ALERTS_OUTPUT)
    logger.info(f"Rule-based detector: {len(alerts)} alerts fired")

    if raw_events is not None:
        ev = Evaluator(raw_events, alerts)
        metrics = ev.compute()
        ev.save_metrics(METRICS_OUTPUT, metrics)
        print(metrics)
        return alerts, metrics

    logger.info("No ground-truth labels (real MRT mode) — skipping evaluation")
    return alerts, None


# ─── Step 5: ML ───────────────────────────────────────────────────────────────

def run_ml(roa_table, updates, raw_events, skip_ml: bool):
    if skip_ml or raw_events is None:
        logger.info("Skipping ML phase.")
        return

    logger.info("=== ML Phase: Random Forest ===")
    try:
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import classification_report
        from src.ml_model import RandomForestDetector
    except ImportError as e:
        logger.warning(f"ML skipped — missing dependency: {e}. "
                       "Run: pip install scikit-learn --break-system-packages")
        return

    label_map = {"HIJACK": 1, "LEGIT": 0}
    labeled   = [(u, label_map[u.label]) for u in updates if u.label in label_map]
    if not labeled:
        logger.warning("No labeled updates found — skipping ML")
        return

    ul, yl = zip(*labeled)
    X_train, X_test, y_train, y_test = train_test_split(
        list(ul), list(yl), train_size=0.75,
        random_state=ML_RANDOM_STATE, stratify=yl
    )

    clf = RandomForestDetector(random_state=ML_RANDOM_STATE)
    clf.fit(X_train, y_train, roa_table)
    clf.save(ML_MODEL_PATH)

    y_pred = clf.predict(X_test)
    report = classification_report(y_test, y_pred, target_names=["LEGIT", "HIJACK"])
    logger.info(f"Random Forest results:\n{report}")
    Path("reports/ml_report.txt").write_text(report)

    logger.info("=== ML Phase: Isolation Forest (unsupervised) ===")
    from src.ml_model import IsolationForestDetector

    iso = IsolationForestDetector(contamination=ANOMALY_CONTAMINATION,
                                  random_state=ML_RANDOM_STATE)
    # Train on legit only
    legit_updates = [u for u in updates if u.label == "LEGIT"]
    iso.fit(legit_updates, roa_table)

    preds  = iso.predict(list(ul))
    scores = iso.score_samples(list(ul))
    iso.save("models/iso_forest.pkl")
    logger.info("Isolation Forest model saved.")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Team PRISM PS-005 Pipeline")
    parser.add_argument("--mrt",      nargs="+", help="Real MRT dump file(s)")
    parser.add_argument("--skip-ml",  action="store_true", help="Skip ML training")
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("  Team PRISM — PS-005 BGP Hijack Detection")
    logger.info("=" * 60)

    roa_table           = load_roa_table()
    updates, raw_events = prepare_events(roa_table, mrt_paths=args.mrt)
    alerts, metrics     = run_detection(roa_table, updates, raw_events)
    run_ml(roa_table, updates, raw_events, skip_ml=args.skip_ml)

    logger.info("Pipeline complete. See reports/")


if __name__ == "__main__":
    main()
