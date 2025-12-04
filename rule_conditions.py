"""
Rule Conditions
rule_conditions.py
SentinelScore — Rule Conditions + Explainability
"""

from typing import Dict, Callable


RuleCondition = Callable[[dict], bool]
RuleExplanation = Callable[[dict], str]

RULE_CONDITIONS: Dict[str, RuleCondition] = {}
RULE_EXPLANATIONS: Dict[str, RuleExplanation] = {}


# ------------------------------------------------------------
# For Helper - Do not remove
# ------------------------------------------------------------
def _num(x, default=0.0):
    try:
        return float(x)
    except Exception:
        return default

# ============================================================
#                     RULE IMPLEMENTATIONS
# ============================================================

# ------------------------------------------------------------
# New Device with Fast Spending
# ------------------------------------------------------------
def cond_ato_new_device_fast_spend(row):
    return (
        bool(row.get("is_new_device_for_user"))
        and _num(row.get("minutes_since_session_start")) < 10
        and _num(row.get("amount_vs_user_avg_multiplier")) > 2.5
    )

def explain_ato_new_device_fast_spend(row):
    return (
        f"New device and fast-spend pattern: "
        f"{row.get('minutes_since_session_start')} minutes since login, "
        f"multiplier {row.get('amount_vs_user_avg_multiplier')}×."
    )

RULE_CONDITIONS["RULE_ATO_NEW_DEVICE_FAST_SPEND"] = cond_ato_new_device_fast_spend
RULE_EXPLANATIONS["RULE_ATO_NEW_DEVICE_FAST_SPEND"] = explain_ato_new_device_fast_spend


# ---------------------------
# Hybrid Type ATO + App Scam
# ---------------------------
def cond_hybrid_ato_app_scam(row):
    return (
        row.get("txn_type") == "p2p"
        and bool(row.get("is_first_time_recipient"))
        and _num(row.get("velocity_1h")) >= 3
        and _num(row.get("amount_vs_user_avg_multiplier")) > 1.2
    )

def explain_hybrid_ato_app_scam(row):
    return (
        f"High-velocity first-time P2P transfer: "
        f"velocity={row.get('velocity_1h')}, "
        f"multiplier={row.get('amount_vs_user_avg_multiplier')}×."
    )

RULE_CONDITIONS["RULE_HYBRID_ATO_APP_SCAM"] = cond_hybrid_ato_app_scam
RULE_EXPLANATIONS["RULE_HYBRID_ATO_APP_SCAM"] = explain_hybrid_ato_app_scam


# ----------------------------------------------------------------
# P2P High Velocity
# ----------------------------------------------------------------
def cond_p2p_high_velocity(row):
    return (
        row.get("txn_type") == "p2p"
        and _num(row.get("velocity_1h")) >= 4
    )

def explain_p2p_high_velocity(row):
    return (
        f"P2P burst velocity: {row.get('velocity_1h')} transfers in <1 hour."
    )

RULE_CONDITIONS["RULE_P2P_HIGH_VELOCITY"] = cond_p2p_high_velocity
RULE_EXPLANATIONS["RULE_P2P_HIGH_VELOCITY"] = explain_p2p_high_velocity


# ------------------------------------------------------------
# Merchant Spike
# ------------------------------------------------------------
def cond_merchant_spike(row):
    return (
        row.get("txn_type") == "merchant"
        and _num(row.get("amount_vs_user_avg_multiplier")) >= 3.0
    )

def explain_merchant_spike(row):
    return (
        f"Merchant spend spike: multiplier "
        f"{row.get('amount_vs_user_avg_multiplier')}×."
    )

RULE_CONDITIONS["RULE_MERCHANT_SPIKE"] = cond_merchant_spike
RULE_EXPLANATIONS["RULE_MERCHANT_SPIKE"] = explain_merchant_spike


# ------------------------------------------------------------
# Device Mismatch
# ------------------------------------------------------------
def cond_device_mismatch(row):
    return (
        bool(row.get("is_new_device_for_user"))
        and _num(row.get("minutes_since_session_start")) <= 5
    )

def explain_device_mismatch(row):
    return (
        f"DEVICE ALERT: User transacted within {row.get('minutes_since_session_start')} minutes "
        f"on a NEW device. This device has NEVER been used by this account before. "
        f"Recommendation: Trigger step-up authentication."
    )

RULE_CONDITIONS["RULE_DEVICE_MISMATCH"] = cond_device_mismatch
RULE_EXPLANATIONS["RULE_DEVICE_MISMATCH"] = explain_device_mismatch


# ------------------------------------------------------------
# Short Lived Sessions
# ------------------------------------------------------------
def cond_session_short_lived(row):
    return (
        _num(row.get("minutes_since_session_start")) < 2
        and (
            bool(row.get("is_new_device_for_user"))
            or _num(row.get("amount_vs_user_avg_multiplier")) > 2.0
        )
    )
def explain_session_short_lived(row):
    return (
        f"Transaction occurred {row.get('minutes_since_session_start')} minutes "
        f"after login (script-like behavior)."
    )

RULE_CONDITIONS["RULE_SESSION_SHORT_LIVED"] = cond_session_short_lived
RULE_EXPLANATIONS["RULE_SESSION_SHORT_LIVED"] = explain_session_short_lived
# ----------------------------------------------------------------
# ATO Pass Reset
# ----------------------------------------------------------------
def condition_rule_ato_password_reset(row):
    return (
        bool(row.get("session_password_reset"))
        and _num(row.get("minutes_since_session_start")) < 15
    )


def explain_rule_ato_password_reset(row):
    return (
        f" ATO ALERT: User reset password during this session, then transacted "
        f"{row.get('minutes_since_session_start')} minutes later. "
        f"This is a classic account takeover pattern. "
        f"Recommendation: DECLINE and freeze account."
    )


RULE_CONDITIONS["RULE_ATO_PASSWORD_RESET"] = condition_rule_ato_password_reset
RULE_EXPLANATIONS["RULE_ATO_PASSWORD_RESET"] = explain_rule_ato_password_reset


# ----------------------------------------------------------------
# ATO MFA Bypass
# ----------------------------------------------------------------
def condition_rule_ato_mfa_bypass(row):
    return (
        bool(row.get("session_mfa_bypassed"))
        and (
            bool(row.get("is_new_device_for_user"))
            or _num(row.get("amount_vs_user_avg_multiplier")) > 2.0
        )
    )


def explain_rule_ato_mfa_bypass(row):
    return (
        f"MFA BYPASS: Multi-factor authentication was bypassed for this session. "
        f"Transaction amount: ${row.get('amount'):.2f} "
        f"({row.get('amount_vs_user_avg_multiplier')}× normal). "
        f"Recommendation: REVIEW and contact user."
    )


RULE_CONDITIONS["RULE_ATO_MFA_BYPASS"] = condition_rule_ato_mfa_bypass
RULE_EXPLANATIONS["RULE_ATO_MFA_BYPASS"] = explain_rule_ato_mfa_bypass

# ----------------------------------------------------------------
# ATO Location Change
# ----------------------------------------------------------------
def condition_rule_ato_geo_change(row):
    return (
        bool(row.get("session_geo_change"))
        and _num(row.get("minutes_since_session_start")) < 20
    )


def explain_rule_ato_geo_change(row):
    return (
        f"GEO ANOMALY: User logged in from different geographic region than previous session. "
        f"Transaction occurred {row.get('minutes_since_session_start')} minutes after login. "
        f"Recommendation: Trigger location verification."
    )


RULE_CONDITIONS["RULE_ATO_GEO_CHANGE"] = condition_rule_ato_geo_change
RULE_EXPLANATIONS["RULE_ATO_GEO_CHANGE"] = explain_rule_ato_geo_change


# ----------------------------------------------------------------
# Rule Amount Large Dev
# ----------------------------------------------------------------
def cond_amount_large_deviation(row):
    return _num(row.get("amount_vs_user_avg_multiplier")) >= 5.0

def explain_amount_large_deviation(row):
    return (
        f"Spend multiplier {row.get('amount_vs_user_avg_multiplier')}× exceeds 5×."
    )

RULE_CONDITIONS["RULE_AMOUNT_LARGE_DEVIATION"] = cond_amount_large_deviation
RULE_EXPLANATIONS["RULE_AMOUNT_LARGE_DEVIATION"] = explain_amount_large_deviation
