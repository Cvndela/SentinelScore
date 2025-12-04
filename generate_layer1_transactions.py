""""
Layer 1 Generator 
generate_layer1_transactions.py
SentinelScore - Transactions Generator part of core L1
"""

import uuid
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple

import pandas as pd

# Configs

RNG_SEED = 123
rng = random.Random(RNG_SEED)

GLOBAL_START = datetime(2023, 1, 1)
GLOBAL_END = datetime(2025, 1, 1)

LAYER1_CORE_DIR = Path("data_output/layer1_core")
OUTPUT_DIR = Path("data_output/layer1_tx")

# Helpers 

def gen_uuid() -> str:
    return str(uuid.uuid4())


def random_datetime_between(start: datetime, end: datetime) -> datetime:
    if end <= start:
        return start
    delta = end - start
    seconds = int(delta.total_seconds())
    offset = rng.randint(0, seconds)
    return start + timedelta(seconds=offset)


def sample_amount(kind: str = "mixed") -> float:
    if kind == "p2p":
        val = random.triangular(15, 160, 40)  # low, high, mode
        return round(val, 2)

    if kind == "merchant":
        val = random.triangular(5, 120, 25)
        return round(val, 2)

    val = random.triangular(10, 150, 35)
    return round(val, 2)

# Merchants for layer 1

def generate_merchants(n_merchants: int = 200) -> pd.DataFrame:
    categories = [
        "groceries", "restaurants", "ride_share", "online_retail",
        "subscriptions", "utilities", "travel", "entertainment",
    ]
    rows = []
    for i in range(n_merchants):
        merchant_id = gen_uuid()
        merchant_name = f"Merchant_{i+1}"
        merchant_category = rng.choice(categories)
        # Layer 1 MUST be clean → assign conservative defaults
        risk_segment = "low"          # clean baseline
        is_crypto = False             # no crypto merchants in L1
        is_p2p_like = False           # no suspicious merchants in L1
        is_exchange = False           # no exchanges in L1
        created_at = random_datetime_between(GLOBAL_START, GLOBAL_END)
        rows.append(
            {
                "merchant_id": merchant_id,
                "merchant_name": merchant_name,
                "merchant_category": merchant_category,
                "risk_segment": risk_segment,
                "is_crypto": is_crypto,
                "is_p2p_like": is_p2p_like,
                "is_exchange": is_exchange,
                "created_at": created_at,
            }
        )
    merchants_df = pd.DataFrame(rows)
    merchants_df = merchants_df.sort_values("created_at").reset_index(drop=True)
    return merchants_df

def sample_recipient_count() -> int:
    p = rng.random()
    if p < 0.20:
        return 0
    elif p < 0.55:
        return 1
    elif p < 0.80:
        return 2
    elif p < 0.95:
        return 3
    elif p < 0.99:
        return 4
    else:
        return 5


def generate_p2p_recipients(
    users_df: pd.DataFrame,
    max_recipients_per_user: int = 5
) -> pd.DataFrame:
    user_ids = list(users_df["user_id"])
    rows = []

    for _, user in users_df.iterrows():
        sender = user["user_id"]
        sender_created_at = user["created_at"]

        n_recipients = min(sample_recipient_count(), max_recipients_per_user)
        if n_recipients <= 0:
            continue

        possible_recipients = [uid for uid in user_ids if uid != sender]
        rng.shuffle(possible_recipients)
        selected = possible_recipients[:n_recipients]

        for recip in selected:
            first_at = random_datetime_between(sender_created_at, GLOBAL_END)
            last_at = random_datetime_between(first_at, GLOBAL_END)

            txn_count = rng.randint(1, 20)

            rows.append(
                {
                    "sender_user_id": sender,
                    "recipient_user_id": recip,
                    "first_interaction_at": first_at,
                    "last_interaction_at": last_at,
                    "txn_count": txn_count,
                }
            )

    df = pd.DataFrame(rows)
    return df

# Layer 1 Transactions 
def sample_tx_count_for_session() -> int:
    p = rng.random()
    if p < 0.60:
        return rng.randint(0, 2)
    elif p < 0.90:
        return rng.randint(3, 5)
    else:
        return rng.randint(6, 10)


def generate_transactions(
    users_df: pd.DataFrame,
    sessions_df: pd.DataFrame,
    user_devices_df: pd.DataFrame,
    device_enrichments_df: pd.DataFrame,
    merchants_df: pd.DataFrame,
    p2p_df: pd.DataFrame,
    target_txn_count: int = 20_000,
) -> pd.DataFrame:

    enrichment_by_device = (
        device_enrichments_df.groupby("device_id")["enrichment_id"]
        .first()
        .to_dict()
    )

    recip_by_user: Dict[str, List[str]] = (
        p2p_df.groupby("sender_user_id")["recipient_user_id"]
        .apply(list)
        .to_dict()
    )

    merchant_ids = list(merchants_df["merchant_id"])
    rows = []

    seen_pairs: set[Tuple[str, str]] = set()

    for _, sess in sessions_df.iterrows():
        user_id = sess["user_id"]
        session_id = sess["session_id"]
        device_id = sess["device_id"]
        login_at = sess["login_at"]
        logout_at = sess["logout_at"] or (login_at + timedelta(minutes=15))

        n_tx = sample_tx_count_for_session()
        if n_tx == 0:
            continue

        for _ in range(n_tx):
            created_at = random_datetime_between(login_at, logout_at)

            if rng.random() < 0.7 and merchant_ids:
                txn_type = "merchant"
                merchant_id = rng.choice(merchant_ids)
                recipient_user_id = None
                amount = sample_amount("merchant")
            else:
                txn_type = "p2p"
                merchant_id = None
                recipients = recip_by_user.get(user_id, [])
                if recipients:
                    recipient_user_id = rng.choice(recipients)
                else:
                    other_users = [u for u in users_df["user_id"] if u != user_id]
                    recipient_user_id = rng.choice(other_users) if other_users else None
                amount = sample_amount("p2p")

            minutes_since_session_start = (created_at - login_at).total_seconds() / 60.0
            minutes_since_session_start = int(max(0, minutes_since_session_start))

            velocity_1h = min(n_tx, rng.randint(1, 3))

            if txn_type == "p2p" and recipient_user_id is not None:
                key = (user_id, recipient_user_id)
                is_first_time_recipient = key not in seen_pairs
                seen_pairs.add(key)
            else:
                is_first_time_recipient = False

            is_new_device_for_user = False
            amount_vs_user_avg_multiplier = 1.0  

            rows.append(
                {
                    "txn_id": gen_uuid(),
                    "user_id": user_id,
                    "device_id": device_id,
                    "session_id": session_id,
                    "merchant_id": merchant_id,
                    "recipient_user_id": recipient_user_id,
                    "created_at": created_at,
                    "amount": amount,
                    "currency": "USD",
                    "txn_type": txn_type,
                    "channel": "in_app",
                    "status": "completed",
                    "label_is_fraud": False,
                    "scenario_id": None,
                    "device_enrichment_id": enrichment_by_device.get(device_id),
                    # denorm signals NEED
                    "is_new_device_for_user": is_new_device_for_user,
                    "is_first_time_recipient": is_first_time_recipient,
                    "amount_vs_user_avg_multiplier": amount_vs_user_avg_multiplier,
                    "velocity_1h": velocity_1h,
                    "minutes_since_session_start": minutes_since_session_start,
                }
            )

    tx_df = pd.DataFrame(rows)
    tx_df = tx_df.sort_values("created_at").reset_index(drop=True)
    return tx_df


# -----------------------------
# Orchestrator
# -----------------------------

def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # 4 load core layer1 data
    users_df = pd.read_csv(LAYER1_CORE_DIR / "users.csv", parse_dates=["created_at"])
    devices_df = pd.read_csv(LAYER1_CORE_DIR / "devices.csv", parse_dates=["first_seen_at", "last_seen_at"])
    user_devices_df = pd.read_csv(LAYER1_CORE_DIR / "user_devices.csv", parse_dates=["first_seen_at", "last_seen_at"])
    device_enrichments_df = pd.read_csv(
        LAYER1_CORE_DIR / "device_enrichments.csv", parse_dates=["snapshot_at"]
    )
    sessions_df = pd.read_csv(
        LAYER1_CORE_DIR / "auth_sessions.csv",
        parse_dates=["login_at", "logout_at"],
    )

    # 4 merchants
    merchants_df = generate_merchants()
    merchants_df.to_csv(OUTPUT_DIR / "merchants.csv", index=False)

    # 4 p2p graph
    p2p_df = generate_p2p_recipients(users_df)
    p2p_df.to_csv(OUTPUT_DIR / "p2p_recipients.csv", index=False)

    # 4 transactions
    tx_df = generate_transactions(
        users_df=users_df,
        sessions_df=sessions_df,
        user_devices_df=user_devices_df,
        device_enrichments_df=device_enrichments_df,
        merchants_df=merchants_df,
        p2p_df=p2p_df,
        target_txn_count=20_000,
    )
    tx_df.to_csv(OUTPUT_DIR / "transactions.csv", index=False)

    print(f"Layer 1 merchants, p2p_recipients, transactions written to {OUTPUT_DIR.resolve()}")


if __name__ == "__main__":
    main()
