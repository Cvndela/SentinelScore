import json
import uuid
from datetime import datetime, timezone
import logging
import pandas as pd
from datetime import datetime
from pathlib import Path

from feature_extractor import extract_features, FeatureInputs
from rule_evaluator import evaluate_rules

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent

LAYER1_TX_DIR = BASE_DIR / "data_output" / "layer1_tx"
LAYER2_DIR    = BASE_DIR / "data_output" / "layer2"

MERCHANTS_FILE       = LAYER1_TX_DIR / "merchants.csv"
TRANSACTIONS_FILE    = LAYER2_DIR / "transactions_after_layer2.csv"
SESSIONS_FILE        = LAYER2_DIR / "auth_sessions_after_layer2.csv"
P2P_FILE             = LAYER2_DIR / "p2p_recipients_after_layer2.csv"

DECISIONS_OUTPUT_FILE = BASE_DIR / "fraud_decisions.csv"
RULE_HITS_OUTPUT_FILE = BASE_DIR / "fraud_rule_hits.csv"


def load_inputs() -> FeatureInputs:
    logger.info("Loading transactions...")
    transactions = pd.read_csv(TRANSACTIONS_FILE, parse_dates=['created_at'])
    
    logger.info("Loading sessions...")
    sessions = pd.read_csv(SESSIONS_FILE, parse_dates=['login_at', 'logout_at'])
    
    logger.info("Loading P2P recipients...")
    p2p = pd.read_csv(P2P_FILE, parse_dates=['first_interaction_at', 'last_interaction_at'])
    
    logger.info("Loading merchants...")
    merchants = pd.read_csv(MERCHANTS_FILE)
    
    logger.info(f"Loaded {len(transactions)} transactions")
    
    return FeatureInputs(
        transactions=transactions,
        sessions=sessions,
        merchants=merchants,
        p2p_recipients=p2p
    )


def main():
    try:
        logger.info("=== STARTING FRAUD EVALUATION ===")

        inputs = load_inputs()

        if len(inputs.transactions) == 0:
            logger.error("No transactions found")
            return

        logger.info("Extracting features...")
        features_df = extract_features(inputs)
        logger.info(f"Extracted features for {len(features_df)} transactions")

        logger.info("Evaluating rules...")
        decisions_df, rule_hits_df = evaluate_rules(features_df)
        logger.info(f"Generated {len(decisions_df)} decisions")
        logger.info(f"Generated {len(rule_hits_df)} rule hits")

        # ---------------------------------------------------------
        # Normalize DECISIONS for SQL Match
        # ---------------------------------------------------------

        # Conversion - Dont touch 
        decisions_df["triggered_rules"] = decisions_df["triggered_rules"].apply(
            lambda x: x.split(',') if isinstance(x, str) and x else []
        )
        decisions_df["reason_codes"] = decisions_df["triggered_rules"].apply(
            lambda lst: json.dumps(lst)
        )

        output_df = decisions_df.merge(
            features_df[['txn_id', 'user_id', 'created_at']],
            on='txn_id',
            how='left'
        )

        output_df = output_df[[
            'txn_id',
            'user_id',
            'decision',
            'final_score',
            'reason_codes'
        ]].rename(columns={'final_score': 'risk_score'})

        output_df["decision_id"] = [str(uuid.uuid4()) for _ in range(len(output_df))]
        output_df["created_at"] = datetime.now(timezone.utc).isoformat()

        output_df = output_df[[
            'decision_id',
            'txn_id',
            'user_id',
            'decision',
            'risk_score',
            'reason_codes',
            'created_at'
        ]]

        # ---------------------------------------------------------
        # Added RULE Hits for Project Schema
        # ---------------------------------------------------------

        rule_hits_df["rule_hit_id"] = [str(uuid.uuid4()) for _ in range(len(rule_hits_df))]

        # User to txn - dont touch
        user_map = features_df.set_index("txn_id")["user_id"].to_dict()
        rule_hits_df["user_id"] = rule_hits_df["txn_id"].map(user_map)

        rule_hits_df["signal_values"] = rule_hits_df["reason"].apply(
            lambda r: json.dumps({"reason": r})
        )

        rule_hits_df["created_at"] = datetime.now(timezone.utc).isoformat()

        rule_hits_df = rule_hits_df[[
            "rule_hit_id",
            "txn_id",
            "user_id",
            "rule_name",
            "severity",
            "signal_values",
            "created_at"
        ]]

        # For Debug
        print("\n" + "="*60)
        print("EVALUATION SUMMARY")
        print("="*60)
        print(f"\nTotal transactions evaluated: {len(output_df):,}")
        print(f"\nDecision breakdown:")
        print(output_df['decision'].value_counts())
        print(f"\nRisk score distribution:")
        print(output_df['risk_score'].describe())
        
        if len(rule_hits_df) > 0:
            print(f"\nTop 10 triggered rules:")
            print(rule_hits_df['rule_name'].value_counts().head(10))
        
        print("="*60 + "\n")
        
        # Success?
        logger.info("Writing outputs...")
        output_df.to_csv(DECISIONS_OUTPUT_FILE, index=False)
        rule_hits_df.to_csv(RULE_HITS_OUTPUT_FILE, index=False)
        
        logger.info(f"✓ Saved decisions to: {DECISIONS_OUTPUT_FILE}")
        logger.info(f"✓ Saved rule hits to: {RULE_HITS_OUTPUT_FILE}")
        logger.info("=== FRAUD EVALUATION COMPLETE ===")
        
    except FileNotFoundError as e:
        logger.error(f"Required file not found: {e}")
        return
    except Exception as e:
        logger.error(f"Error during evaluation: {e}")
        import traceback
        traceback.print_exc()
        return


if __name__ == "__main__":
    main()