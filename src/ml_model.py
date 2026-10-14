"""
Team PRISM — PS-005
ML-based Anomaly Detector (Phase 2)

Two models:
  1. Isolation Forest  — unsupervised, no labels needed
  2. Random Forest     — supervised, uses synthetic labels

Features engineered per BGP update:
  - prefix_len         : announced prefix length
  - as_path_len        : AS path hop count
  - origin_in_roa      : 1 if origin ASN has any ROA, else 0
  - prefix_covered     : 1 if prefix is covered by any ROA
  - roa_status_code    : 0=valid, 1=invalid, 2=not_found
  - asn_is_private     : 1 if ASN is in private range (64512–65534)
  - prefix_specificity : prefix_len minus parent ROA prefix len (0 if none)
"""

import logging
import pickle
import numpy as np
from pathlib import Path
from typing import List, Tuple, Optional

from src.bgp_parser import BGPUpdate
from src.roa_loader import ROATable

logger = logging.getLogger(__name__)

PRIVATE_ASN_RANGES = [(64512, 65534), (4200000000, 4294967294)]


def asn_is_private(asn: int) -> bool:
    return any(lo <= asn <= hi for lo, hi in PRIVATE_ASN_RANGES)


def extract_features(update: BGPUpdate, roa_table: ROATable) -> List[float]:
    """Convert a BGPUpdate into a numeric feature vector."""
    status, roa = roa_table.validate(update.prefix, update.origin_asn)

    status_code = {"valid": 0, "invalid": 1, "not_found": 2}.get(status, 2)
    prefix_len  = update.prefix_len

    # Parent ROA prefix length (for specificity calculation)
    parent_len  = 0
    if roa is not None:
        parent_len = roa.prefix.prefixlen

    # Does origin ASN have ANY ROA at all?
    asn_has_roa = int(len(roa_table.get_all_prefixes_for_asn(update.origin_asn)) > 0)

    return [
        float(prefix_len),                        # 0
        float(len(update.as_path)),               # 1
        float(asn_has_roa),                       # 2
        float(1 if status != "not_found" else 0), # 3 — prefix_covered
        float(status_code),                       # 4
        float(int(asn_is_private(update.origin_asn))),  # 5
        float(prefix_len - parent_len),           # 6 — specificity delta
        float(update.peer_asn),                   # 7
    ]


FEATURE_NAMES = [
    "prefix_len",
    "as_path_len",
    "origin_has_roa",
    "prefix_covered",
    "roa_status_code",
    "asn_is_private",
    "specificity_delta",
    "peer_asn",
]


# ─── Isolation Forest (unsupervised) ─────────────────────────────────────────

class IsolationForestDetector:
    """
    Unsupervised anomaly detector using Isolation Forest.
    Train on normal traffic; anomalies score closer to -1.
    """

    def __init__(self, contamination: float = 0.1, random_state: int = 42):
        from sklearn.ensemble import IsolationForest
        self.model = IsolationForest(
            contamination  = contamination,
            random_state   = random_state,
            n_estimators   = 200,
        )
        self.roa_table: Optional[ROATable] = None

    def fit(self, updates: List[BGPUpdate], roa_table: ROATable):
        self.roa_table = roa_table
        X = np.array([extract_features(u, roa_table) for u in updates])
        self.model.fit(X)
        logger.info(f"Isolation Forest trained on {len(updates)} samples")

    def predict(self, updates: List[BGPUpdate]) -> List[int]:
        """Returns -1 (anomaly) or 1 (normal) per update."""
        X = np.array([extract_features(u, self.roa_table) for u in updates])
        return self.model.predict(X).tolist()

    def score_samples(self, updates: List[BGPUpdate]) -> List[float]:
        """Anomaly scores: more negative = more anomalous."""
        X = np.array([extract_features(u, self.roa_table) for u in updates])
        return self.model.score_samples(X).tolist()

    def save(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(self, f)
        logger.info(f"Model saved to {path}")

    @staticmethod
    def load(path: str) -> "IsolationForestDetector":
        with open(path, "rb") as f:
            return pickle.load(f)


# ─── Random Forest (supervised) ───────────────────────────────────────────────

class RandomForestDetector:
    """
    Supervised classifier using labeled synthetic data.
    Label: 1 = hijack, 0 = legit
    """

    def __init__(self, random_state: int = 42, n_estimators: int = 200):
        from sklearn.ensemble import RandomForestClassifier
        self.model = RandomForestClassifier(
            n_estimators = n_estimators,
            random_state = random_state,
            class_weight = "balanced",
            max_depth    = 12,
        )
        self.roa_table: Optional[ROATable] = None

    def fit(self, updates: List[BGPUpdate], labels: List[int], roa_table: ROATable):
        """
        labels: list of ints — 1 for hijack, 0 for legit
        """
        self.roa_table = roa_table
        X = np.array([extract_features(u, roa_table) for u in updates])
        y = np.array(labels)
        self.model.fit(X, y)
        logger.info(f"Random Forest trained on {len(updates)} samples")
        self._log_feature_importance()

    def predict(self, updates: List[BGPUpdate]) -> List[int]:
        X = np.array([extract_features(u, self.roa_table) for u in updates])
        return self.model.predict(X).tolist()

    def predict_proba(self, updates: List[BGPUpdate]) -> List[float]:
        """Returns hijack probability per update."""
        X = np.array([extract_features(u, self.roa_table) for u in updates])
        return self.model.predict_proba(X)[:, 1].tolist()

    def _log_feature_importance(self):
        importances = self.model.feature_importances_
        ranked = sorted(zip(FEATURE_NAMES, importances),
                        key=lambda x: x[1], reverse=True)
        logger.info("Feature importances:")
        for name, imp in ranked:
            logger.info(f"  {name:25s}: {imp:.4f}")

    def save(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(self, f)
        logger.info(f"Model saved to {path}")

    @staticmethod
    def load(path: str) -> "RandomForestDetector":
        with open(path, "rb") as f:
            return pickle.load(f)
