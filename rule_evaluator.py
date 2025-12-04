"""
Rule Evaluator
rule_evaluator.py
SentinelScore — Rule Evaluation & Scoring Layer 
"""

from __future__ import annotations

from typing import Dict, List, Tuple, Any
import pandas as pd

from rules_spec import RULES
from rule_conditions import RULE_CONDITIONS, RULE_EXPLANATIONS


# -----------------------------------------------------------
# Decision thresholds
# -----------------------------------------------------------
SCORE_BANDS = {
    "decline": 70,
    "review": 30,
    "approve": 0,
}

class RuleHit:
    def __init__(self, txn_id, rule_name, score, category, severity, reason, final_score=None):
        self.txn_id = txn_id
        self.rule_name = rule_name
        self.score = score
        self.category = category
        self.severity = severity
        self.reason = reason
        self.final_score = final_score


# -----------------------------------------------------------
# Core evaluation
# -----------------------------------------------------------
def _apply_rules_to_row(row: pd.Series) -> Tuple[int, List[RuleHit]]:
    hits: List[RuleHit] = []
    txn_id = row.get("txn_id")
    total_score = 0

    for rule_name, spec in RULES.items():

        if not spec.get("enabled", True):
            continue

        cond_fn = spec.get("condition")
        explain_fn = spec.get("explain")

        if rule_name not in RULE_CONDITIONS or cond_fn is None:
            continue

        try:
            triggered = cond_fn(row)
        except Exception:
            continue

        if not triggered:
            continue

        # Explanation
        try:
            reason = explain_fn(row)
        except Exception:
            reason = f"Rule {rule_name} triggered."

        score = int(spec.get("score", 0))
        total_score += score

        hits.append(
            RuleHit(
                txn_id=txn_id,
                rule_name=rule_name,
                score=score,
                category=spec.get("category", "UNKNOWN"),
                severity=spec.get("severity", "unknown"),
                reason=reason,
            )
        )

    return total_score, hits


def _decision_from_score(score: int) -> str:
    if score >= SCORE_BANDS["decline"]:
        return "decline"
    if score >= SCORE_BANDS["review"]:
        return "review"
    return "approve"


# -----------------------------------------------------------
# Public API
# -----------------------------------------------------------
def evaluate_rules(features_df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
    decisions: List[Dict[str, Any]] = []
    hits: List[Dict[str, Any]] = []

    for _, row in features_df.iterrows():
        final_score, row_hits = _apply_rules_to_row(row)
        decision = _decision_from_score(final_score)

        txn_id = row.get("txn_id")
        triggered_names = [h.rule_name for h in row_hits]
        primary_reason = row_hits[0].reason if row_hits else ""

        decisions.append(
            {
                "txn_id": txn_id,
                "final_score": final_score,
                "decision": decision,
                "triggered_rules": ",".join(triggered_names),
                "primary_reason": primary_reason,
            }
        )

        for h in row_hits:
            hits.append(
                {
                    "txn_id": h.txn_id,
                    "rule_name": h.rule_name,
                    "category": h.category,
                    "severity": h.severity,
                    "score": h.score,
                    "final_score": final_score,
                    "reason": h.reason,
                }
            )

    decisions_df = pd.DataFrame(decisions)
    rule_hits_df = pd.DataFrame(hits)

    return decisions_df, rule_hits_df


def evaluate_single_transaction(row: pd.Series) -> Dict[str, Any]:
    final_score, row_hits = _apply_rules_to_row(row)
    decision = _decision_from_score(final_score)

    return {
        "txn_id": row.get("txn_id"),
        "final_score": final_score,
        "decision": decision,
        "rules_triggered": [
            {
                "name": h.rule_name,
                "score": h.score,
                "category": h.category,
                "severity": h.severity,
                "reason": h.reason,
            }
            for h in row_hits
        ]
    }
