import json
import os
from datetime import datetime
from typing import Any, Dict, Optional

DEFAULT_TYPE_WEIGHTS = {
    "login": 1.0,
    "login_failure": 3.0,
    "password_change": 2.0,
    "mfa_enabled": -1.0,
    "mfa_disabled": 2.5,
    "permission_change": 3.0,
    "data_export": 4.0,
    "admin_action": 3.5,
}

def _load_type_weights() -> Dict[str, float]:
    raw = os.getenv("EVENT_TYPE_WEIGHTS")
    if not raw:
        return DEFAULT_TYPE_WEIGHTS
    try:
        weights = json.loads(raw)
        if not isinstance(weights, dict):
            return DEFAULT_TYPE_WEIGHTS
        return {str(k): float(v) for k, v in weights.items()}
    except Exception:
        return DEFAULT_TYPE_WEIGHTS

def _load_thresholds():
    medium = float(os.getenv("ALERT_MEDIUM_THRESHOLD", "3.0"))
    high = float(os.getenv("ALERT_HIGH_THRESHOLD", "5.0"))
    return medium, high

TYPE_WEIGHTS = _load_type_weights()
MEDIUM_THRESHOLD, HIGH_THRESHOLD = _load_thresholds()

def get_risk_config():
    return {
        "type_weights": TYPE_WEIGHTS,
        "medium_threshold": MEDIUM_THRESHOLD,
        "high_threshold": HIGH_THRESHOLD,
    }

def calculate_risk_score(
    event_type: str,
    payload: Optional[Dict[str, Any]],
    timestamp: Optional[datetime] = None,
) -> float:
    score = 0.0
    score += TYPE_WEIGHTS.get(event_type, 1.0)

    if payload:
        if "ip" in payload:
            score += 0.5

        if timestamp:
            hour = timestamp.hour
            if 0 <= hour < 6:
                score += 1.5

    return max(0.0, score)
