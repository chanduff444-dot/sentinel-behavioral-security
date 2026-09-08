from datetime import datetime
from typing import Any, Dict, Optional

def calculate_risk_score(
    event_type: str,
    payload: Optional[Dict[str, Any]],
    timestamp: Optional[datetime] = None,
) -> float:
    score = 0.0

    type_weights = {
        "login": 1.0,
        "login_failure": 3.0,
        "password_change": 2.0,
        "mfa_enabled": -1.0,
        "mfa_disabled": 2.5,
        "permission_change": 3.0,
        "data_export": 4.0,
        "admin_action": 3.5,
    }
    score += type_weights.get(event_type, 1.0)

    if payload:
        if "ip" in payload:
            score += 0.5

        if timestamp:
            hour = timestamp.hour
            if 0 <= hour < 6:
                score += 1.5

    return max(0.0, score)
