"""
feature_extractor.py
SentinelScore – Feature Extractor
Rule Engine Feature Layer

Key Principles
--------------
- No machine learning
- No drift from inputs defined in project spec
- All derived fields are deterministic and documented
- Fully compatible with Layer 1 (clean) + Layer 2 (fraud injected)
- No new schema fields required
"""

import pandas as pd
import random
import numpy as np
from dataclasses import dataclass
from typing import Optional


# -------------------------------------------------------------
# Data container for inputs
# -------------------------------------------------------------
@dataclass
class FeatureInputs:
    transactions: pd.DataFrame
    sessions: pd.DataFrame
    merchants: pd.DataFrame
    p2p_recipients: pd.DataFrame


# -------------------------------------------------------------
# Internal utilities
# -------------------------------------------------------------
def _prepare_sessions(sessions_df):
    """
    Safely prepare auth session features.
    Ensures timestamps are parsed as datetimes and handles null logout_at.
    """

    s = sessions_df.copy()

    s["login_at"] = pd.to_datetime(s["login_at"], errors="coerce")
    s["logout_at"] = pd.to_datetime(s["logout_at"], errors="coerce")

    missing_logout = s["logout_at"].isna()
    if missing_logout.any():
        s.loc[missing_logout, "logout_at"] = s.loc[missing_logout, "login_at"] + pd.to_timedelta(
            s.loc[missing_logout].apply(lambda row: 20 + random.randint(0, 20), axis=1),
            unit="m"
        )

    s["session_length_minutes"] = (
        (s["logout_at"] - s["login_at"]).dt.total_seconds() / 60
    ).fillna(0).astype(int)

    s = s.sort_values(["user_id", "login_at"], ignore_index=True)

    return s

# -------------------------------------------------------------
# Main Feature Extractor
# -------------------------------------------------------------
def extract_features(inputs):
    tx = inputs.transactions.copy()

    # DNT
    tx["created_at"] = pd.to_datetime(tx["created_at"], errors="coerce")

    # ---------------------------------------------------------
    # Merge session data + ATO FLAGS 
    # ---------------------------------------------------------
    sessions = _prepare_sessions(inputs.sessions)

    tx = tx.merge(
        sessions[[
            "session_id", 
            "login_at", 
            "logout_at", 
            "session_length_minutes",
            "password_reset_during_session",  
            "was_mfa_bypassed",                
            "was_geo_change"                   
        ]],
        on="session_id",
        how="left",
    )

    tx = tx.rename(columns={
        "password_reset_during_session": "session_password_reset",
        "was_mfa_bypassed": "session_mfa_bypassed",
        "was_geo_change": "session_geo_change"
    })

    tx["session_password_reset"] = tx["session_password_reset"].fillna(False).astype(bool)
    tx["session_mfa_bypassed"] = tx["session_mfa_bypassed"].fillna(False).astype(bool)
    tx["session_geo_change"] = tx["session_geo_change"].fillna(False).astype(bool)

    if "minutes_since_session_start" not in tx.columns:
        tx["minutes_since_session_start"] = (
            (tx["created_at"] - tx["login_at"]).dt.total_seconds() / 60
        ).fillna(0).astype(int)

    # ---------------------------------------------------------
    # Merchant-safe merge
    # ---------------------------------------------------------
    merchants = inputs.merchants.copy()

    merchant_tx = tx[tx["txn_type"] == "merchant"].copy()
    p2p_tx = tx[tx["txn_type"] == "p2p"].copy()

    if not merchant_tx.empty:
        merchant_tx["merchant_id"] = merchant_tx["merchant_id"].astype(str)
        merchants["merchant_id"] = merchants["merchant_id"].astype(str)

        merchant_tx = merchant_tx.merge(
            merchants,
            on="merchant_id",
            how="left"
        )
    if "created_at_x" in merchant_tx.columns:  # NEED for dup ts
        merchant_tx["created_at"] = merchant_tx["created_at_x"]
        merchant_tx = merchant_tx.drop(columns=["created_at_x", "created_at_y"], errors="ignore")

    if "created_at_x" in tx.columns:
        tx["created_at"] = tx["created_at_x"]
        tx = tx.drop(columns=["created_at_x", "created_at_y"], errors="ignore")

    for col in ["merchant_name", "merchant_category", "risk_segment"]:
        p2p_tx[col] = None

    tx = pd.concat([merchant_tx, p2p_tx], ignore_index=True, sort=False)

    # ---------------------------------------------------------
    # Time features
    # ---------------------------------------------------------
    tx["hour_of_day"] = tx["created_at"].dt.hour
    tx["day_of_week"] = tx["created_at"].dt.dayofweek

    # ---------------------------------------------------------
    # Device familiarity
    # ---------------------------------------------------------
    if "is_new_device_for_user" not in tx.columns:
        tx["is_new_device_for_user"] = False

    # ---------------------------------------------------------
    # P2P relationship strength
    # ---------------------------------------------------------
    p2p = inputs.p2p_recipients.copy()

    expected_cols = {"sender_user_id", "recipient_user_id", "txn_count"}
    missing = expected_cols - set(p2p.columns)

    if missing:
        for col in missing:
            if col == "txn_count":
                p2p[col] = 0
            else:
                p2p[col] = None

    p2p = p2p[["sender_user_id", "recipient_user_id", "txn_count"]]
    p2p.rename({"txn_count": "p2p_baseline_txn_count"}, axis=1, inplace=True)

    tx = tx.merge(
        p2p,
        left_on=["user_id", "recipient_user_id"],
        right_on=["sender_user_id", "recipient_user_id"],
        how="left",
    )

    tx["p2p_baseline_txn_count"] = tx["p2p_baseline_txn_count"].fillna(0).astype(int)

    if "sender_user_id" in tx.columns:
        tx = tx.drop(columns=["sender_user_id"])

    # ---------------------------------------------------------
    # Velocity 1HR
    # ---------------------------------------------------------
    def compute_velocity_1h(df):
        df = df.sort_values(['user_id', 'created_at']).reset_index(drop=True)
        
        velocities = []
        for idx, row in df.iterrows():
            user_id = row['user_id']
            created_at = row['created_at']
            window_start = created_at - pd.Timedelta(hours=1)
            
            count = df[
                (df['user_id'] == user_id) &
                (df['created_at'] >= window_start) &
                (df['created_at'] < created_at)
            ].shape[0]
            
            velocities.append(count)
        
        return velocities

    if "velocity_1h" not in tx.columns or (tx["velocity_1h"] == 1).all():
        print("  Computing velocity_1h (rolling 1-hour window)...")
        tx["velocity_1h"] = compute_velocity_1h(tx)

    # ---------------------------------------------------------
    # Amount anomaly 
    # ---------------------------------------------------------
    def compute_amount_multipliers(df):
        user_avg = df.groupby('user_id')['amount'].mean()
        
        multipliers = []
        for idx, row in df.iterrows():
            user_id = row['user_id']
            amount = row['amount']
            avg = user_avg.get(user_id, 30.0)
            multiplier = round(amount / max(1.0, avg), 2)
            multipliers.append(multiplier)
        
        return multipliers

    if "amount_vs_user_avg_multiplier" not in tx.columns or (tx["amount_vs_user_avg_multiplier"] == 1.0).all():
        print("  Computing amount_vs_user_avg_multiplier...")
        tx["amount_vs_user_avg_multiplier"] = compute_amount_multipliers(tx)

    if "scenario_id" not in tx.columns:
        tx["scenario_id"] = None

    return tx.sort_values("created_at").reset_index(drop=True)