"""
Team PRISM — PS-005 BGP Hijack Detection
Global configuration and constants
"""

# ─── Data sources ────────────────────────────────────────────────────────────
ROUTEVIEWS_BASE = "http://archive.routeviews.org/bgpdata"
RIPE_RIS_BASE   = "https://data.ris.ripe.net"
RPKI_ROA_URL    = "https://rpki.cloudflare.com/rpki.json"

# ─── Target operator ASNs (extend as needed) ─────────────────────────────────
OPERATOR_ASNS = {
    "AS9498":  "Bharti Airtel",
    "AS45609": "Airtel Broadband",
    "AS24560": "Bharti Airtel (Chennai)",
    "AS55836": "Reliance Jio",
    "AS18101": "Reliance Communications",
    "AS17813": "MTNL",
    "AS9829":  "BSNL",
}

# ─── Detection thresholds ─────────────────────────────────────────────────────
# Max prefix length difference to flag as subprefix hijack
SUBPREFIX_DELTA_THRESHOLD = 1

# Minimum ROA max-length to allow (prefixes longer than this are suspicious)
ROA_MAXLEN_STRICT = True

# ─── ML model settings ───────────────────────────────────────────────────────
ML_MODEL_PATH     = "models/rf_hijack_detector.pkl"
ML_TRAIN_RATIO    = 0.75
ML_RANDOM_STATE   = 42
ANOMALY_CONTAMINATION = 0.1   # for Isolation Forest

# ─── Synthetic injection ──────────────────────────────────────────────────────
SYNTHETIC_HIJACK_COUNT = 100
SYNTHETIC_LEGIT_COUNT  = 100
FAKE_HIJACKER_ASN      = 64512   # private ASN range for testing

# ─── Output paths ────────────────────────────────────────────────────────────
ALERTS_OUTPUT   = "reports/alerts.json"
METRICS_OUTPUT  = "reports/metrics.json"
REPORT_OUTPUT   = "reports/evaluation_report.html"

# ─── Logging ─────────────────────────────────────────────────────────────────
LOG_LEVEL = "INFO"
