"""
Rule Specifications 
rules_spec.py
SentinelScore — Rule Specifications 

"""

from typing import Dict, Any

# =====================================================================
# Rule Definition SCHEMA
# =====================================================================
# Each rule entry contains:
#   version: "1.0.0"
#   enabled: bool
#   category: str (ATO | P2P | MERCHANT | DEVICE | SESSION | ANOMALY | HYBRID)
#   severity: "low" | "medium" | "high" | "critical"
#   score: int
#   description: short str
#   condition: function(row) to bool
#   explain: function(row) to str


# Rules:

RULES: Dict[str, Dict[str, Any]] = {

    # ------------------------------------------------------------
    # Account Take Over
    # ------------------------------------------------------------
    "RULE_ATO_NEW_DEVICE_FAST_SPEND": {
        "version": "1.0.0",
        "enabled": True,
        "category": "ATO",
        "severity": "high",
        "score": 40,
        "description": "Fast spend after login on a new device with high multiplier.",
        "condition": None,   # auto-wired
        "explain": None,
    },

    # ------------------------------------------------------------
    # Hybrid Type (ATO + APP Scam)
    # ------------------------------------------------------------
    "RULE_HYBRID_ATO_APP_SCAM": {
        "version": "1.0.0",
        "enabled": True,
        "category": "HYBRID",
        "severity": "critical",
        "score": 50,
        "description": "ATO behavior combined with first-time P2P recipient + velocity.",
        "condition": None,
        "explain": None,
    },

    # ------------------------------------------------------------
    # Velocity for P2P
    # ------------------------------------------------------------
    "RULE_P2P_HIGH_VELOCITY": {
        "version": "1.0.0",
        "enabled": True,
        "category": "P2P",
        "severity": "medium",
        "score": 20,
        "description": "P2P transfers performed at unusually high hourly velocity.",
        "condition": None,
        "explain": None,
    },

    # ------------------------------------------------------------
    # Merchant Spike
    # ------------------------------------------------------------
    "RULE_MERCHANT_SPIKE": {
        "version": "1.0.0",
        "enabled": True,
        "category": "MERCHANT",
        "severity": "high",
        "score": 35,
        "description": "Merchant spend significantly exceeds typical multiplier.",
        "condition": None,
        "explain": None,
    },

    # ------------------------------------------------------------
    # Device Mismatch
    # ------------------------------------------------------------
    "RULE_DEVICE_MISMATCH": {
        "version": "1.0.0",
        "enabled": True,
        "category": "DEVICE",
        "severity": "medium",
        "score": 15,
        "description": "Short session + new device mismatch behavior.",
        "condition": None,
        "explain": None,
    },

    # ------------------------------------------------------------
    # Session Anomaly
    # ------------------------------------------------------------
    "RULE_SESSION_SHORT_LIVED": {
        "version": "1.0.0",
        "enabled": True,
        "category": "SESSION",
        "severity": "low",
        "score": 10,
        "description": "Transaction occurred extremely early in the session.",
        "condition": None,
        "explain": None,
    },

    # ------------------------------------------------------------
    # Amount Anomaly
    # ------------------------------------------------------------
    "RULE_AMOUNT_LARGE_DEVIATION": {
        "version": "1.0.0",
        "enabled": True,
        "category": "ANOMALY",
        "severity": "high",
        "score": 30,
        "description": "Spend amount deviates massively from typical multiplier.",
        "condition": None,
        "explain": None,
    },
}

# =============================
# For auto wiring - Dont Touch!
# =============================

from rule_conditions import RULE_CONDITIONS, RULE_EXPLANATIONS

for rule_name, metadata in RULES.items():

    if rule_name in RULE_CONDITIONS:
        metadata["condition"] = RULE_CONDITIONS[rule_name]
    else:
        raise ValueError(
            f"RULE SPEC ERROR: No condition defined for rule '{rule_name}'. "
            "Make sure rule_conditions.py contains this key."
        )

    if rule_name in RULE_EXPLANATIONS:
        metadata["explain"] = RULE_EXPLANATIONS[rule_name]
    else:
        raise ValueError(
            f"RULE SPEC ERROR: No explanation function for rule '{rule_name}'."
        )
