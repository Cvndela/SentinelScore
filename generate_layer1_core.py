""""
Layer 1 Generator 
generate_layer1_core.py
SentinelScore - Core generator L1
"""
import uuid
import random
from datetime import datetime, timedelta
from typing import Tuple
import pandas as pd
from pathlib import Path



# Configs
N_USERS = 1000
GLOBAL_START = datetime(2023, 1, 1)
GLOBAL_END = datetime(2025, 1, 1)
RNG_SEED = 42

rng = random.Random(RNG_SEED)

def sample_human_login_time(date_only: datetime) -> datetime:
    p = rng.random()

    if p < 0.08:
        hour = rng.randint(0, 5)
    elif p < 0.80:
        hour = rng.randint(6, 20)
    elif p < 0.95:
        hour = rng.randint(21, 22)
    else:
        hour = 23

    minute = rng.randint(0, 59)
    second = rng.randint(0, 59)

    return datetime(
        year=date_only.year,
        month=date_only.month,
        day=date_only.day,
        hour=hour,
        minute=minute,
        second=second,
    )


def sample_session_duration_minutes() -> int:
# Session Length realism 
    p = rng.random()
    if p < 0.70:
        return rng.randint(5, 20)
    elif p < 0.95:
        return rng.randint(21, 40)
    else:
        return rng.randint(41, 60)


def gen_uuid() -> str:
    return str(uuid.uuid4())


def random_datetime_between(start: datetime, end: datetime) -> datetime:
    if end <= start:
        return start
    delta = end - start
    seconds = int(delta.total_seconds())
    offset = rng.randint(0, seconds)
    return start + timedelta(seconds=offset)


def random_date_range_within_period(
    global_start: datetime,
    global_end: datetime,
    min_days: int = 1,
    max_days: int = 365,
) -> Tuple[datetime, datetime]:
# Failsafe DNT!
    if global_end <= global_start:
        return global_start, global_start

    total_days = (global_end - global_start).days

    if total_days <= 0:
        return global_start, global_start

    effective_min = max(1, min(min_days, total_days))
    effective_max = max(1, min(max_days, total_days))

    if effective_min > effective_max:
        effective_min = effective_max

    length_days = rng.randint(int(effective_min), int(effective_max))

    max_offset = max(0, total_days - length_days)
    start_offset = rng.randint(0, max_offset)

    start = global_start + timedelta(days=start_offset)
    end = start + timedelta(days=length_days)

    if end > global_end:
        end = global_end

    return start, end


# -------------------------------------------
# Users
# --------------------------------------------

def generate_users() -> pd.DataFrame:
    countries = ["US", "US", "US", "CA", "GB", "AU"]
    regions_by_country = {
        "US": ["NY", "CA", "TX", "FL", "WA", "IL"],
        "CA": ["ON", "BC", "QC"],
        "GB": ["ENG", "SCO", "WLS"],
        "AU": ["NSW", "VIC", "QLD"],
    }
    age_buckets = ["18-24", "25-34", "35-44", "45-54", "55+"]
    income_buckets = ["<40k", "40-80k", "80-120k", "120k+"]

    rows = []
    for _ in range(N_USERS):
        user_id = gen_uuid()
        created_at = random_datetime_between(GLOBAL_START, GLOBAL_END)

        r = rng.random()
        if r < 0.7:
            kyc_risk_tier = "low"
        elif r < 0.93:
            kyc_risk_tier = "medium"
        else:
            kyc_risk_tier = "high"

        country = rng.choice(countries)
        region_choices = regions_by_country.get(country, ["NA"])
        region = rng.choice(region_choices)
        age_bucket = rng.choice(age_buckets)
        income_bucket = rng.choice(income_buckets)

        account_status = "active"

        rows.append(
            {
                "user_id": user_id,
                "created_at": created_at,
                "kyc_risk_tier": kyc_risk_tier,
                "country": country,
                "region": region,
                "age_bucket": age_bucket,
                "income_bucket": income_bucket,
                "account_status": account_status,
            }
        )

    df = pd.DataFrame(rows)
    df = df.sort_values("created_at").reset_index(drop=True)
    return df


# --------------------------------------------------
# Layer 1: devices, user_devices, device_enrichments
# --------------------------------------------------

def sample_device_fingerprint() -> Tuple[str, str, str]:
    device_type = rng.choice(["mobile", "mobile", "desktop", "tablet"])
    if device_type == "mobile":
        os = rng.choice(["iOS", "Android"])
    else:
        os = rng.choice(["Windows", "macOS", "Linux"])
    browser = rng.choice(["Chrome", "Safari", "Firefox", "Edge"])
    fingerprint = f"{device_type}-{os}-{browser}-{rng.randint(1000, 9999)}"
    return device_type, os, fingerprint


def generate_devices_and_enrichments(users_df: pd.DataFrame):
    device_rows = []
    user_device_rows = []
    enrichment_rows = []

    for _, user in users_df.iterrows():
        user_id = user["user_id"]
        user_created = user["created_at"]

        n_devices = 1
        if rng.random() < 0.3:
            n_devices = 2

        for idx in range(n_devices):
            device_id = gen_uuid()
            device_type, os, fingerprint = sample_device_fingerprint()

            dev_start, dev_end = random_date_range_within_period(
                user_created, GLOBAL_END, min_days=7, max_days=365
            )

            device_rows.append(
                {
                    "device_id": device_id,
                    "device_fingerprint": fingerprint,
                    "device_type": device_type,
                    "os": os,
                    "first_seen_at": dev_start,
                    "last_seen_at": dev_end,
                }
            )

            user_device_rows.append(
                {
                    "user_id": user_id,
                    "device_id": device_id,
                    "first_seen_at": dev_start,
                    "last_seen_at": dev_end,
                    "is_primary_device": (idx == 0),
                }
            )

            device_risk_score = round(rng.uniform(1.0, 10.0), 3)
            ip_risk_score = round(rng.uniform(1.0, 10.0), 3)
            enrichment_rows.append(
                {
                    "enrichment_id": gen_uuid(),
                    "device_id": device_id,
                    "ip_address": None,
                    "geo_country": user["country"],
                    "geo_region": user["region"],
                    "ip_risk_score": ip_risk_score,
                    "proxy_vpn_tor_flag": False,
                    "velocity_flag": False,
                    "device_risk_score": device_risk_score,
                    "snapshot_at": dev_start,
                }
            )

    devices_df = pd.DataFrame(device_rows).drop_duplicates("device_id")
    user_devices_df = pd.DataFrame(user_device_rows)
    device_enrichments_df = pd.DataFrame(enrichment_rows)
    return devices_df, user_devices_df, device_enrichments_df


# ----------------------------------------------
# Layer 1: auth_sessions (matches auth_sessions)
# ----------------------------------------------

def random_ip() -> str:
    return f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def generate_auth_sessions(
    users_df: pd.DataFrame,
    user_devices_df: pd.DataFrame,
    device_enrichments_df: pd.DataFrame,
) -> pd.DataFrame:
    devices_by_user = (
        user_devices_df.groupby("user_id")["device_id"].apply(list).to_dict()
    )

    enrichment_by_device = (
        device_enrichments_df.groupby("device_id")
        .agg(
            {
                "device_risk_score": "first",
                "ip_risk_score": "first",
                "geo_country": "first",
                "geo_region": "first",
            }
        )
        .to_dict("index")
    )

    session_rows = []

    for _, user in users_df.iterrows():
        user_id = user["user_id"]
        created_at = user["created_at"]

        user_devices = devices_by_user.get(user_id, [])
        if not user_devices:
            continue

        n_sessions = rng.randint(1, 5)
        for _ in range(n_sessions):
            device_id = rng.choice(user_devices)
            total_days = (GLOBAL_END - created_at).days
            if total_days < 1:
                base_date = created_at
            else:
                days_offset = rng.randint(0, total_days)
                base_date = created_at + timedelta(days=days_offset)
            login_at = sample_human_login_time(base_date)
            session_minutes = sample_session_duration_minutes()
            logout_at = login_at + timedelta(minutes=session_minutes)

            enrich = enrichment_by_device.get(device_id, None)
            if enrich:
                geo_country = enrich["geo_country"]
                geo_region = enrich["geo_region"]
                device_risk_snapshot = enrich["device_risk_score"]
                ip_risk_snapshot = enrich["ip_risk_score"]
            else:
                geo_country = user.get("country", None)
                geo_region = user.get("region", None)
                device_risk_snapshot = None
                ip_risk_snapshot = None

            session_rows.append(
                {
                    "session_id": gen_uuid(),
                    "user_id": user_id,
                    "device_id": device_id,
                    "ip_address": random_ip(),
                    "geo_country": geo_country,
                    "geo_region": geo_region,
                    "login_at": login_at,
                    "logout_at": logout_at,
                    "was_new_device_login": False,
                    "was_geo_change": False,
                    "was_mfa_bypassed": False,
                    "password_reset_during_session": False,
                    "device_risk_snapshot": device_risk_snapshot,
                    "ip_risk_snapshot": ip_risk_snapshot,
                    "session_risk_level": device_risk_snapshot or 5.0,
                }
            )

    sessions_df = pd.DataFrame(session_rows)
    return sessions_df


# ----------------------------------------------
# Orchestrator
# ----------------------------------------------

def main(output_dir: str = "data_output/layer1_core"):
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    users_df = generate_users()
    devices_df, user_devices_df, device_enrichments_df = generate_devices_and_enrichments(
        users_df
    )
    sessions_df = generate_auth_sessions(
        users_df, user_devices_df, device_enrichments_df
    )

    users_df.to_csv(out_path / "users.csv", index=False)
    devices_df.to_csv(out_path / "devices.csv", index=False)
    user_devices_df.to_csv(out_path / "user_devices.csv", index=False)
    device_enrichments_df.to_csv(out_path / "device_enrichments.csv", index=False)
    sessions_df.to_csv(out_path / "auth_sessions.csv", index=False)

    print(f"Wrote Layer 1 core CSVs to {out_path.resolve()}")


if __name__ == "__main__":
    main()
