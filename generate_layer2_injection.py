""""
Layer 2 Generator 
generate_layer2_injection.py
SentinelScore - Anomoly Injection Layer 2
"""

import uuid
import random
import numpy as np
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple

import pandas as pd


# ==========================================================
# CONFIG
# ==========================================================

RNG_SEED = 222
rng = random.Random(RNG_SEED)

L1_CORE = Path("data_output/layer1_core")
L1_TX = Path("data_output/layer1_tx")
L2_DIR = Path("data_output/layer2")

N_ATO_SCENARIOS = 40
N_ATO_APP_SCENARIOS = 25

def gen_uuid() -> str:
    return str(uuid.uuid4())


def compute_user_amount_baselines(transactions_df: pd.DataFrame) -> Dict[str, float]:

    baselines = (
        transactions_df.groupby("user_id")["amount"]
        .mean()
        .to_dict()
    )
    return baselines


def compute_user_session_count(auth_sessions_df: pd.DataFrame) -> Dict[str, int]:
    return (
        auth_sessions_df.groupby("user_id")["session_id"]
        .nunique()
        .to_dict()
    )


def compute_user_device_count(user_devices_df: pd.DataFrame) -> Dict[str, int]:
    return (
        user_devices_df.groupby("user_id")["device_id"]
        .nunique()
        .to_dict()
    )


# ---------------------------
# For Victim Weighting - R22
# ---------------------------

def compute_ato_victim_scores(
    users_df: pd.DataFrame,
    sessions_df: pd.DataFrame,
    transactions_df: pd.DataFrame,
    user_devices_df: pd.DataFrame,
) -> Dict[str, float]:

    now = datetime.utcnow()
    account_age_days = (
        (now - users_df["created_at"]).dt.total_seconds() / 86400
    )
    users_df = users_df.assign(account_age_days=account_age_days)

    session_count = compute_user_session_count(sessions_df)
    device_count = compute_user_device_count(user_devices_df)
    avg_amount = compute_user_amount_baselines(transactions_df)

    scores = {}
    for _, row in users_df.iterrows():
        u = row["user_id"]
        age_score = row["account_age_days"] / 365  

        sess_score = session_count.get(u, 1)
        dev_score = 2 if device_count.get(u, 1) == 1 else 1  
        amt_score = avg_amount.get(u, 20) / 50               

        score = (
            0.45 * age_score +
            0.25 * sess_score +
            0.20 * dev_score +
            0.10 * amt_score
        )
        scores[u] = max(score, 0.01)

    return scores


# ---------------------
# P2P Recipient - R23
# ---------------------

def update_or_create_p2p_relationship(
    p2p_df: pd.DataFrame,
    sender_id: str,
    recipient_id: str,
    created_at: datetime,
):
    """
    Correct behavior:
    - If recipient already exists for sender, increment txn_count.
    - Else create new relationship.
    """
    mask = (
        (p2p_df["sender_user_id"] == sender_id) &
        (p2p_df["recipient_user_id"] == recipient_id)
    )

    if mask.any():
        idx = p2p_df[mask].index[0]
        p2p_df.at[idx, "last_interaction_at"] = created_at
        p2p_df.at[idx, "txn_count"] += 1
    else:
        new_row = {
            "sender_user_id": sender_id,
            "recipient_user_id": recipient_id,
            "first_interaction_at": created_at,
            "last_interaction_at": created_at,
            "txn_count": 1,
        }
        p2p_df.loc[len(p2p_df)] = new_row


# ==========================================================
# Scenario 1 — ATO  
# ==========================================================

def pick_weighted_ato_victims(scores: Dict[str, float], k: int) -> List[str]:
    uids = list(scores.keys())
    weights = np.array(list(scores.values()))
    weights = weights / weights.sum()
    return list(np.random.choice(uids, size=k, replace=False, p=weights))


def select_compromised_session(sessions_df: pd.DataFrame, user_id: str) -> pd.Series:
    user_sessions = sessions_df[sessions_df["user_id"] == user_id]
    if user_sessions.empty:
        return None

    preferred = user_sessions[user_sessions["logout_at"].notna()]
    if not preferred.empty:
        return preferred.sample(1).iloc[0]

    return user_sessions.sample(1).iloc[0]


def create_attacker_device(
    devices_df: pd.DataFrame,
    user_devices_df: pd.DataFrame,
    user_id: str,
    login_at: datetime,
) -> str:
    """
    ATO MUST use a NEW DEVICE.
    Inject a new device and link to user.
    """
    new_device_id = gen_uuid()

    devices_df.loc[len(devices_df)] = {
        "device_id": new_device_id,
        "device_type": "mobile",
        "first_seen_at": login_at,
        "last_seen_at": login_at,
    }

    user_devices_df.loc[len(user_devices_df)] = {
        "user_id": user_id,
        "device_id": new_device_id,
        "first_seen_at": login_at,
        "last_seen_at": login_at,
        "is_primary_device": False,
    }

    return new_device_id


def generate_auth_failures(
    user_id: str,
    compromised_session: pd.Series,
    n_range: Tuple[int, int] = (5, 15),
) -> List[Dict]:
    rows = []
    login_at = compromised_session["login_at"]
    n = rng.randint(*n_range)

    for _ in range(n):
        seconds_before = rng.randint(60, 20 * 60)
        failed_at = login_at - timedelta(seconds=seconds_before)
        rows.append({
            "failure_id": gen_uuid(),
            "user_id": user_id,
            "device_id": None,
            "ip_address": None,
            "failure_reason": "invalid_password",
            "failed_at": failed_at,
        })
    return rows


def create_fraud_event(
    user_id: str,
    start: datetime,
    end: datetime,
) -> Dict:
    now = datetime.utcnow()
    return {
        "scenario_id": gen_uuid(),
        "primary_user_id": user_id,
        "fraud_type": "ATO",
        "scenario_version": "v1",
        "risk_entry_point": "new_device + password_reset",
        "behavior_change_notes": "fast high-value P2P after takeover",
        "pattern_complexity_score": 7,
        "injected_at": now,
        "started_at": start,
        "ended_at": end,
    }


def inject_ato_fraud_transactions(
    user_id: str,
    session: pd.Series,
    devices_df: pd.DataFrame,
    user_devices_df: pd.DataFrame,
    transactions_df: pd.DataFrame,
    p2p_df: pd.DataFrame,
    avg_amount_baselines: Dict[str, float],
    scenario_id: str,
    n_range: Tuple[int, int] = (2, 3),
) -> None:
    """
    Insert 2–3 fraudulent P2P transactions:
      - new recipients
      - high amount vs user baseline
      - correct denorm signals
    """

    login_at = session["login_at"]
    logout_at = session["logout_at"]
    if pd.isna(logout_at):
        logout_at = login_at + timedelta(minutes=30)

    #attacker device - dont remove, will break
    attacker_device_id = create_attacker_device(
        devices_df,
        user_devices_df,
        user_id,
        login_at
    )

    n = rng.randint(*n_range)

    for _ in range(n):

        existing_recip = set(
            p2p_df[p2p_df["sender_user_id"] == user_id]["recipient_user_id"].tolist()
        )
        all_users = set(transactions_df["user_id"].unique())
        candidates = list(all_users - existing_recip - {user_id})

        if candidates:
            recipient_user_id = rng.choice(candidates)
        else:
            # DNT
            other = [x for x in all_users if x != user_id]
            if not other:
                continue
            recipient_user_id = rng.choice(other)

        created_at = login_at + timedelta(
            seconds=rng.randint(60, int((logout_at - login_at).total_seconds()) - 20)
        )

        user_avg = avg_amount_baselines.get(user_id, 30.0)
        amount = round(rng.uniform(4 * user_avg, 12 * user_avg), 2)

        minutes_since_start = int(
            (created_at - login_at).total_seconds() / 60.0
        )
        velocity = rng.randint(4, 10)
        multiplier = round(amount / max(1, user_avg), 2)

        transactions_df.loc[len(transactions_df)] = {
            "txn_id": gen_uuid(),
            "user_id": user_id,
            "device_id": attacker_device_id,
            "session_id": session["session_id"],
            "merchant_id": None,
            "recipient_user_id": recipient_user_id,
            "created_at": created_at,
            "amount": amount,
            "currency": "USD",
            "txn_type": "p2p",
            "channel": "in_app",
            "status": "completed",
            "label_is_fraud": True,
            "scenario_id": scenario_id,
            "device_enrichment_id": None,
            # denorm signals !!! NEEDED
            "is_new_device_for_user": True,
            "is_first_time_recipient": True,
            "amount_vs_user_avg_multiplier": multiplier,
            "velocity_1h": velocity,
            "minutes_since_session_start": minutes_since_start,
        }

        update_or_create_p2p_relationship(
            p2p_df,
            user_id,
            recipient_user_id,
            created_at,
        )


def mark_session_compromised(sessions_df: pd.DataFrame, session_id: str):
    mask = sessions_df["session_id"] == session_id
    for col, val in [
        ("was_new_device_login", True),
        ("password_reset_during_session", True),
        ("was_geo_change", True),
        ("was_mfa_bypassed", True),
    ]:
        if col in sessions_df.columns:
            sessions_df.loc[mask, col] = val


# ==========================================================
# Orchestrator For Scenario 1
# ==========================================================

def inject_scenario_1_ato(
    users_df,
    sessions_df,
    devices_df,
    user_devices_df,
    transactions_df,
    p2p_df,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:

    scores = compute_ato_victim_scores(
        users_df,
        sessions_df,
        transactions_df,
        user_devices_df,
    )

    victims = pick_weighted_ato_victims(scores, N_ATO_SCENARIOS)

    fraud_event_rows = []
    auth_failure_rows = []

    avg_amount_baselines = compute_user_amount_baselines(transactions_df)

    for user_id in victims:

        session = select_compromised_session(sessions_df, user_id)
        if session is None:
            continue

        login_at = session["login_at"]
        logout_at = session["logout_at"]

        fe = create_fraud_event(user_id, login_at, logout_at)
        fraud_event_rows.append(fe)
        scenario_id = fe["scenario_id"]

        mark_session_compromised(sessions_df, session["session_id"])

        auth_failure_rows.extend(
            generate_auth_failures(user_id, session)
        )

        inject_ato_fraud_transactions(
            user_id,
            session,
            devices_df,
            user_devices_df,
            transactions_df,
            p2p_df,
            avg_amount_baselines,
            scenario_id,
        )

    fraud_events_df = pd.DataFrame(fraud_event_rows)
    auth_failures_df = pd.DataFrame(auth_failure_rows)

    return (
        users_df,
        sessions_df,
        devices_df,
        user_devices_df,
        transactions_df,
        p2p_df,
        fraud_events_df,
        auth_failures_df,
    )


# ==========================================================
# Scenario 2 — ATO + APP SCAM 
# ==========================================================

def inject_scenario_2_ato_plus_app(
    users_df,
    sessions_df,
    devices_df,
    user_devices_df,
    transactions_df,
    p2p_df,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
 
    scores = compute_ato_victim_scores(
        users_df,
        sessions_df,
        transactions_df,
        user_devices_df,
    )

    all_user_ids = list(scores.keys())
    if len(all_user_ids) <= N_ATO_APP_SCENARIOS:
        victims = all_user_ids
    else:
        victims = pick_weighted_ato_victims(scores, N_ATO_APP_SCENARIOS)

    fraud_event_rows = []
    auth_failure_rows = []
    avg_amount_baselines = compute_user_amount_baselines(transactions_df)

    for user_id in victims:

        session = select_compromised_session(sessions_df, user_id)
        if session is None:
            continue

        login_at = session["login_at"]
        logout_at = session["logout_at"]
        if pd.isna(logout_at):
            logout_at = login_at + timedelta(minutes=30)

        fe = create_fraud_event(
            user_id,
            login_at,
            logout_at,
        )
        fe["fraud_type"] = "ATO_APP_SCAM"
        fe["scenario_version"] = "v1_hybrid"
        fe["behavior_change_notes"] = (
            "ATO takeover followed by escalating APP scam P2P sends"
        )

        fraud_event_rows.append(fe)
        scenario_id = fe["scenario_id"]

        mark_session_compromised(sessions_df, session["session_id"])

        auth_failure_rows.extend(
            generate_auth_failures(user_id, session, n_range=(3, 10))
        )

        attacker_device_id = create_attacker_device(
            devices_df,
            user_devices_df,
            user_id,
            login_at
        )

        n_steps = rng.randint(3, 4)
        user_avg = avg_amount_baselines.get(user_id, 30.0)

        # Base amount ~2x avg, final up to ~10x avg
        start_amt = max(40.0, 2.0 * user_avg)
        end_amt = max(300.0, 10.0 * user_avg)

        amounts = np.linspace(start_amt, end_amt, n_steps)

        amounts = [round(float(a), 2) for a in amounts]

        total_window_minutes = rng.randint(30, 90)
        step_gap = max(10, total_window_minutes // n_steps)

        all_users = set(transactions_df["user_id"].unique())

        for i, amount in enumerate(amounts):
            existing_recip = set(
                p2p_df[p2p_df["sender_user_id"] == user_id]["recipient_user_id"].tolist()
            )
            candidate_recipients = list(all_users - existing_recip - {user_id})
            if candidate_recipients:
                recipient_user_id = rng.choice(candidate_recipients)
            else:
                # DNT
                other = [x for x in all_users if x != user_id]
                if not other:
                    continue
                recipient_user_id = rng.choice(other)

            created_at = login_at + timedelta(minutes=(10 + i * step_gap))
            if created_at > logout_at:
                # DNT - For session window
                created_at = logout_at - timedelta(minutes=5)

            minutes_since_start = int((created_at - login_at).total_seconds() / 60.0)
            velocity = rng.randint(4, 12)
            multiplier = round(amount / max(1.0, user_avg), 2)

            transactions_df.loc[len(transactions_df)] = {
                "txn_id": gen_uuid(),
                "user_id": user_id,
                "device_id": attacker_device_id,
                "session_id": session["session_id"],
                "merchant_id": None,
                "recipient_user_id": recipient_user_id,
                "created_at": created_at,
                "amount": amount,
                "currency": "USD",
                "txn_type": "p2p",
                "channel": "in_app",
                "status": "completed",
                "label_is_fraud": True,
                "scenario_id": scenario_id,
                "device_enrichment_id": None,
                # denorm signals - NEEDED!
                "is_new_device_for_user": True,
                "is_first_time_recipient": True,
                "amount_vs_user_avg_multiplier": multiplier,
                "velocity_1h": velocity,
                "minutes_since_session_start": minutes_since_start,
            }

            update_or_create_p2p_relationship(
                p2p_df,
                user_id,
                recipient_user_id,
                created_at,
            )

    fraud_events_df = pd.DataFrame(fraud_event_rows)
    auth_failures_df = pd.DataFrame(auth_failure_rows)

    return (
        users_df,
        sessions_df,
        devices_df,
        user_devices_df,
        transactions_df,
        p2p_df,
        fraud_events_df,
        auth_failures_df,
    )
import pandas as pd
from datetime import timedelta

def inject_scenario3_p2p_velocity_abuse(
    users_df: pd.DataFrame,
    sessions_df: pd.DataFrame,
    transactions_df: pd.DataFrame,
    p2p_df: pd.DataFrame,
    n_scenarios: int = 25,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:

    tx = transactions_df.copy()
    p2p = p2p_df.copy()

    base_p2p = tx[
        (tx["label_is_fraud"] == False)
        & (tx["txn_type"] == "p2p")
    ]

    if base_p2p.empty:
        return tx, p2p, pd.DataFrame(columns=["scenario_id","fraud_type","started_at","ended_at","injected_at"])

    counts = (
        base_p2p.groupby("user_id")["txn_id"]
        .count()
        .reset_index(name="p2p_count")
    )

    candidates = counts[counts["p2p_count"] >= 3]["user_id"].tolist()
    rng.shuffle(candidates)
    victims = candidates[:n_scenarios]

    if not victims:
        return tx, p2p, pd.DataFrame(columns=["scenario_id","fraud_type","started_at","ended_at","injected_at"])

    sessions_by_user = (
        sessions_df.sort_values("login_at")
        .groupby("user_id")
        .apply(lambda g: list(g.to_dict("records")))
        .to_dict()
    )

    all_user_ids = users_df["user_id"].tolist()

    new_p2p_rows = []
    fraud_tx_rows = []
    fraud_event_rows = []

# -------------------------------------------
# Scenario 3 – P2P Velocity   
# -------------------------------------------

def inject_scenario3_p2p_velocity_abuse(
    users_df,
    sessions_df,
    transactions_df,
    p2p_df,
    n_targets: int = 20,
    burst_size: int = 4,
):

    # Needed, if no p2p it skips
    if p2p_df.empty:
        print("Scenario 3: No P2P relationships found. Skipping.")
        return (
            users_df,
            sessions_df,
            transactions_df,
            p2p_df,
            pd.DataFrame(),  
            pd.DataFrame(), 
        )

    rng = random.Random(303)

    grouped = p2p_df.groupby("sender_user_id")["recipient_user_id"].count()
    eligible = list(grouped[grouped > 0].index)

    rng.shuffle(eligible)
    victims = eligible[:min(n_targets, len(eligible))]

    fraud_events_rows = []
    new_tx_rows = []
    now = datetime.utcnow()

    recip_lookup = (
        p2p_df.groupby("sender_user_id")["recipient_user_id"]
        .apply(list)
        .to_dict()
    )

    for victim in victims:
        victim_recips = recip_lookup.get(victim)
        if not victim_recips:
            continue

        rec = rng.choice(victim_recips)

        idx = p2p_df[
            (p2p_df.sender_user_id == victim)
            & (p2p_df.recipient_user_id == rec)
        ].index

        if len(idx) == 0:
            continue

        p2p_df.loc[idx, "txn_count"] = p2p_df.loc[idx, "txn_count"] + burst_size

        victim_sessions = sessions_df[sessions_df.user_id == victim]
        if victim_sessions.empty:
            continue

        sess = victim_sessions.sample(1, random_state=rng.randint(1, 99999)).iloc[0]
        base_time = sess["login_at"]

        timestamps = []
        for i in range(burst_size):
            offset = i * rng.randint(1,5)
            ts = base_time + timedelta(minutes=offset)
            if ts > sess["logout_at"]:
                ts = sess["logout_at"]
            timestamps.append(ts)
        amounts = [
            round(rng.uniform(50, 300), 2)
            for _ in range(burst_size)
        ]

        scenario_id = uuid.uuid4()
        started_at = min(timestamps)
        ended_at = max(timestamps)

        # Logs the fraud event 
        fraud_events_rows.append(
            {
                "scenario_id": scenario_id,
                "fraud_type": "P2P_VELOCITY_ABUSE",
                "started_at": started_at,
                "ended_at": ended_at,
                "injected_at": now,
            }
        )

        for ts, amt in zip(timestamps, amounts):
            new_tx_rows.append(
                {
                    "txn_id": uuid.uuid4(),
                    "user_id": victim,
                    "device_id": sess["device_id"],
                    "session_id": sess["session_id"],
                    "merchant_id": None,
                    "recipient_user_id": rec,
                    "created_at": ts,
                    "amount": amt,
                    "currency": "USD",
                    "txn_type": "p2p",
                    "channel": "in_app",
                    "status": "completed",
                    "label_is_fraud": True,
                    "scenario_id": scenario_id,
                    # denormalized fields - need i say more
                    "device_enrichment_id": None,
                    "is_new_device_for_user": False,
                    "is_first_time_recipient": False,
                    "amount_vs_user_avg_multiplier": 1.0,
                    "velocity_1h": burst_size,
                    "minutes_since_session_start": 0,
                }
            )

    # DF conversion 
    fe_df = pd.DataFrame(fraud_events_rows)
    burst_df = pd.DataFrame(new_tx_rows)

    transactions_df = (
        pd.concat([transactions_df, burst_df], ignore_index=True)
        .sort_values("created_at")
    )

    return (
        transactions_df,
        p2p_df,
        fe_df,
    )

# -------------------------------------------------------------------
# Scenario 4: Merchant Spend Spike - Testing + Big Cashout
# -------------------------------------------------------------------

def inject_scenario4_merchant_spike(
    users_df: pd.DataFrame,
    sessions_df: pd.DataFrame,
    transactions_df: pd.DataFrame,
    n_scenarios: int = 25,
) -> tuple[pd.DataFrame, pd.DataFrame]:
 
    tx = transactions_df.copy()

    base_merch = tx[
        (tx["label_is_fraud"] == False)
        & (tx["txn_type"] == "merchant")
        & (tx["merchant_id"].notnull())
    ]

    if base_merch.empty:
        return tx, pd.DataFrame(columns=["scenario_id", "fraud_type", "started_at", "ended_at", "injected_at"])

    counts = (
        base_merch.groupby("user_id")["txn_id"]
        .count()
        .reset_index(name="merchant_tx_count")
    )
    candidates = counts[counts["merchant_tx_count"] >= 3]["user_id"].tolist()
    rng.shuffle(candidates)
    victims = candidates[:n_scenarios]

    if not victims:
        return tx, pd.DataFrame(columns=["scenario_id", "fraud_type", "started_at", "ended_at", "injected_at"])

    sessions_by_user = (
        sessions_df.sort_values("login_at")
        .groupby("user_id")
        .apply(lambda g: list(g.to_dict("records")))
        .to_dict()
    )

    fraud_tx_rows = []
    fraud_event_rows = []

    all_merchants = base_merch["merchant_id"].unique().tolist()

    for user_id in victims:
        user_sessions = sessions_by_user.get(user_id, [])
        if not user_sessions:
            continue

        sess = sorted(user_sessions, key=lambda s: s["login_at"])[-1]
        session_id = sess["session_id"]
        device_id = sess["device_id"]
        login_at = sess["login_at"]
        logout_at = sess["logout_at"] or (login_at + timedelta(minutes=30))

        user_base = base_merch[base_merch["user_id"] == user_id]
        base_avg = float(user_base["amount"].mean()) if not user_base.empty else 40.0

        user_merchants = user_base["merchant_id"].unique().tolist()
        if not user_merchants:
            user_merchants = all_merchants
        rng.shuffle(user_merchants)
        chosen_merchants = user_merchants[: rng.randint(1, min(2, len(user_merchants)))]

        base_start = login_at + timedelta(minutes=rng.randint(5, 15))

        # for small txn tests before big spend
        n_small = rng.randint(2, 4)
        n_large = rng.randint(1, 2)
        n_total = n_small + n_large

        scenario_id = gen_uuid()
        times = []
        amounts = []

        for i in range(n_total):
            offset_minutes = rng.randint(0, 3) + i * rng.randint(1, 3)
            created_at = base_start + timedelta(minutes=offset_minutes)
            if created_at > logout_at:
                created_at = logout_at
            if created_at < login_at:
                created_at = login_at

            merchant_id = rng.choice(chosen_merchants)

            if i < n_small:
                amount = round(rng.uniform(5.0, 25.0), 2)
            else:
                multiplier = rng.uniform(3.0, 8.0)
                amount = round(max(50.0, base_avg * multiplier), 2)

            minutes_since_session_start = int(
                max(0, (created_at - login_at).total_seconds() / 60.0)
            )

            velocity_1h = max(4, n_total)

            fraud_tx_rows.append(
                {
                    "txn_id": gen_uuid(),
                    "user_id": user_id,
                    "device_id": device_id,
                    "session_id": session_id,
                    "merchant_id": merchant_id,
                    "recipient_user_id": None,
                    "created_at": created_at,
                    "amount": amount,
                    "currency": "USD",
                    "txn_type": "merchant",
                    "channel": "in_app",
                    "status": "completed",
                    "label_is_fraud": True,
                    "scenario_id": scenario_id,
                    "device_enrichment_id": None,
                    "is_new_device_for_user": False,
                    "is_first_time_recipient": False,
                    "amount_vs_user_avg_multiplier": round(amount / max(1.0, base_avg), 3),
                    "velocity_1h": velocity_1h,
                    "minutes_since_session_start": minutes_since_session_start,
                }
            )

            times.append(created_at)
            amounts.append(amount)

        if times:
            fraud_event_rows.append(
                {
                    "scenario_id": scenario_id,
                    "fraud_type": "MERCHANT_SPEND_SPIKE",
                    "started_at": min(times),
                    "ended_at": max(times),
                    "injected_at": max(times),
                }
            )

    if fraud_tx_rows:
        tx = pd.concat([tx, pd.DataFrame(fraud_tx_rows)], ignore_index=True)

    fe_df = pd.DataFrame(fraud_event_rows)
    return tx, fe_df

# ==========================================================
# Final Orchestrator The Big Fish
# ==========================================================

def inject_all_layer2_scenarios(
    users_df,
    sessions_df,
    devices_df,
    user_devices_df,
    transactions_df,
    p2p_df,
):
    """
    THIS
    Runs all four Layer 2 fraud scenarios:
      - Scenario 1: ATO takeover 
      - Scenario 2: ATO + APP scam 
      - Scenario 3: P2P velocity  
      - Scenario 4: Merchant spend spike 
    """

    # ------------------------------------------------------------
    # Scenario 1 — ATO Only
    # ------------------------------------------------------------
    (
        users_df,
        sessions_df,
        devices_df,
        user_devices_df,
        transactions_df,
        p2p_df,
        fe1_df,
        af1_df,
    ) = inject_scenario_1_ato(
        users_df,
        sessions_df,
        devices_df,
        user_devices_df,
        transactions_df,
        p2p_df,
    )

    # ------------------------------------------------------------
    # Scenario 2 — ATO + APP Scam
    # ------------------------------------------------------------
    (
        users_df,
        sessions_df,
        devices_df,
        user_devices_df,
        transactions_df,
        p2p_df,
        fe2_df,
        af2_df,
    ) = inject_scenario_2_ato_plus_app(
        users_df,
        sessions_df,
        devices_df,
        user_devices_df,
        transactions_df,
        p2p_df,
    )

    # ------------------------------------------------------------
    # Scenario 3 — P2P Velocity Abuse
    # ------------------------------------------------------------
    (
        transactions_df,
        p2p_df,
        fe3_df
    ) = inject_scenario3_p2p_velocity_abuse(
        users_df=users_df,
        sessions_df=sessions_df,
        transactions_df=transactions_df,
        p2p_df=p2p_df,
    )

    af3_df = pd.DataFrame(columns=["failure_id","user_id","device_id","ip_address","failure_reason","failed_at"])



    # ------------------------------------------------------------
    # Scenario 4 — Merchant Spend Spike
    # ------------------------------------------------------------
    (
        transactions_df,
        fe4_df
    ) = inject_scenario4_merchant_spike(
        users_df=users_df,
        sessions_df=sessions_df,
        transactions_df=transactions_df,
    )

    af4_df = pd.DataFrame(columns=["failure_id","user_id","device_id","ip_address","failure_reason","failed_at"])


    fraud_events_df = pd.concat(
        [fe1_df, fe2_df, fe3_df, fe4_df],
        ignore_index=True
    )

    auth_failures_df = pd.concat(
        [af1_df, af2_df, af3_df, af4_df],
        ignore_index=True
    )

    # Cleanup DNT!
    transactions_df["device_enrichment_id"] = None

    return (
        users_df,
        sessions_df,
        devices_df,
        user_devices_df,
        transactions_df,
        p2p_df,
        fraud_events_df,
        auth_failures_df,
    )


# ==========================================================
# The End 
# ==========================================================

def main():
    L2_DIR.mkdir(parents=True, exist_ok=True)

    users_df = pd.read_csv(L1_CORE / "users.csv", parse_dates=["created_at"])
    sessions_df = pd.read_csv(L1_CORE / "auth_sessions.csv", parse_dates=["login_at", "logout_at"])
    devices_df = pd.read_csv(L1_CORE / "devices.csv", parse_dates=["first_seen_at", "last_seen_at"])
    user_devices_df = pd.read_csv(L1_CORE / "user_devices.csv", parse_dates=["first_seen_at", "last_seen_at"])
    transactions_df = pd.read_csv(L1_TX / "transactions.csv", parse_dates=["created_at"])
    p2p_df = pd.read_csv(L1_TX / "p2p_recipients.csv", parse_dates=["first_interaction_at", "last_interaction_at"])

    original_tx_count = len(transactions_df)

    (
        users_df,
        sessions_df,
        devices_df,
        user_devices_df,
        transactions_df,
        p2p_df,
        fraud_events_df,
        auth_failures_df,
    ) = inject_all_layer2_scenarios(
        users_df,
        sessions_df,
        devices_df,
        user_devices_df,
        transactions_df,
        p2p_df,
    )

    users_df.to_csv(L2_DIR / "users_after_layer2.csv", index=False)
    sessions_df.to_csv(L2_DIR / "auth_sessions_after_layer2.csv", index=False)
    devices_df.to_csv(L2_DIR / "devices_after_layer2.csv", index=False)
    user_devices_df.to_csv(L2_DIR / "user_devices_after_layer2.csv", index=False)
    transactions_df.to_csv(L2_DIR / "transactions_after_layer2.csv", index=False)
    p2p_df.to_csv(L2_DIR / "p2p_recipients_after_layer2.csv", index=False)

    if not fraud_events_df.empty:
        fraud_events_df.to_csv(L2_DIR / "fraud_events_layer2.csv", index=False)
    if not auth_failures_df.empty:
        auth_failures_df.to_csv(L2_DIR / "auth_failures_layer2.csv", index=False)

    print("Layer 2 injection complete (Scenario 1 + Scenario 2).")
    print(f"Total fraud events: {len(fraud_events_df)}")
    print(f"Total auth failures: {len(auth_failures_df)}")
    print(f"New fraudulent transactions: {len(transactions_df) - original_tx_count}")


if __name__ == "__main__":
    main()

print("Injection pipeline finished.")
print("You can now open a Python REPL and run validations.")
 