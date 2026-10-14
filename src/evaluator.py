"""
Team PRISM — PS-005
Evaluation Engine

Computes precision, recall, F1, alert latency, and false positive rate
from detector alerts vs. ground-truth labels (synthetic events).
"""

import json
import logging
import datetime
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass

from src.detector import HijackAlert

logger = logging.getLogger(__name__)


@dataclass
class EvalMetrics:
    total_events:  int
    true_pos:      int
    false_pos:     int
    true_neg:      int
    false_neg:     int
    precision:     float
    recall:        float
    f1:            float
    fpr:           float           # False Positive Rate
    avg_latency_s: Optional[float] # Mean detection latency (synthetic only)
    alert_breakdown: Dict[str, int]  # alerts per rule type

    def __str__(self):
        return (
            f"\n{'='*55}\n"
            f"  Team PRISM — PS-005 Evaluation Results\n"
            f"{'='*55}\n"
            f"  Total events processed : {self.total_events}\n"
            f"  True  Positives (TP)   : {self.true_pos}\n"
            f"  False Positives (FP)   : {self.false_pos}\n"
            f"  True  Negatives (TN)   : {self.true_neg}\n"
            f"  False Negatives (FN)   : {self.false_neg}\n"
            f"{'─'*55}\n"
            f"  Precision              : {self.precision:.4f}\n"
            f"  Recall                 : {self.recall:.4f}\n"
            f"  F1 Score               : {self.f1:.4f}\n"
            f"  False Positive Rate    : {self.fpr:.4f}\n"
            f"  Avg Alert Latency      : "
            f"{f'{self.avg_latency_s:.2f}s' if self.avg_latency_s else 'N/A'}\n"
            f"{'─'*55}\n"
            f"  Alerts by rule:\n"
            + "".join(f"    {k:25s}: {v}\n" for k, v in self.alert_breakdown.items())
            + f"{'='*55}\n"
        )

    def to_dict(self):
        return {
            "total_events":    self.total_events,
            "true_pos":        self.true_pos,
            "false_pos":       self.false_pos,
            "true_neg":        self.true_neg,
            "false_neg":       self.false_neg,
            "precision":       round(self.precision, 6),
            "recall":          round(self.recall, 6),
            "f1":              round(self.f1, 6),
            "false_positive_rate": round(self.fpr, 6),
            "avg_latency_s":   self.avg_latency_s,
            "alert_breakdown": self.alert_breakdown,
        }


class Evaluator:
    """
    Compares detector output against labeled synthetic events.

    Usage:
        ev = Evaluator(synthetic_events, alerts)
        metrics = ev.compute()
        print(metrics)
    """

    def __init__(self, events: List[dict], alerts: List[HijackAlert]):
        """
        events : raw synthetic event dicts (with 'label' field)
        alerts : HijackAlert objects produced by the detector
        """
        self.events = events
        self.alerts = alerts

    def compute(self) -> EvalMetrics:
        # Build a lookup: (prefix, origin_asn) → alert
        alerted_keys = {
            (a.prefix, a.origin_asn): a for a in self.alerts
        }

        tp = fp = tn = fn = 0
        latencies = []

        for ev in self.events:
            key       = (ev["prefix"], int(ev["origin_asn"]))
            is_hijack = ev.get("label") == "HIJACK"
            alerted   = key in alerted_keys

            if is_hijack and alerted:
                tp += 1
                # Compute latency if timestamps available
                alert = alerted_keys[key]
                try:
                    ev_ts    = datetime.datetime.fromisoformat(ev["timestamp"])
                    alert_ts = datetime.datetime.fromisoformat(
                        alert.timestamp.rstrip("Z"))
                    latency = (alert_ts - ev_ts).total_seconds()
                    if latency >= 0:
                        latencies.append(latency)
                except Exception:
                    pass
            elif is_hijack and not alerted:
                fn += 1
            elif not is_hijack and alerted:
                fp += 1
            else:
                tn += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1        = (2 * precision * recall / (precision + recall)
                     if (precision + recall) > 0 else 0.0)
        fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        avg_latency = sum(latencies) / len(latencies) if latencies else None

        # Count alerts by rule type
        breakdown: Dict[str, int] = {}
        for a in self.alerts:
            breakdown[a.rule] = breakdown.get(a.rule, 0) + 1

        return EvalMetrics(
            total_events     = len(self.events),
            true_pos         = tp,
            false_pos        = fp,
            true_neg         = tn,
            false_neg        = fn,
            precision        = precision,
            recall           = recall,
            f1               = f1,
            fpr              = fpr,
            avg_latency_s    = avg_latency,
            alert_breakdown  = breakdown,
        )

    def save_metrics(self, path: str, metrics: EvalMetrics):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(metrics.to_dict(), f, indent=2)
        logger.info(f"Metrics saved to {path}")
