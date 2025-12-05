![Static Badge](https://img.shields.io/badge/SentinelScore-Real_Time_Fraud_%26_ATO_Rule_Engine-red?style=social&logo=servbay&logoColor=DB0000&logoSize=auto&labelColor=381111&color=DB0000)
![Static Badge](https://img.shields.io/badge/-Python-White?style=plastic&logo=python&logoColor=black&logoSize=auto&color=white)
![Static Badge](https://img.shields.io/badge/-SQL-White?style=plastic&logo=postgresql&logoColor=black&logoSize=auto&color=white)
# SentinelScore — Real Time Fraud & ATO Rule Engine
**Creator: Alex Chicaiza**\
**LinkedIn: www.linkedin.com/in/alex-chicaiza-a61631196** \
***GitHub: @Cvndela***

SentinelScore is a fully deterministic, SQL-backed fraud-risk engine built to simulate how an ATP-grade payments or banking platform evaluates user activity, device behavior, and transactional risk signals in real time.

The system generates structured synthetic data, enriches it through multi-layer transformations, extracts risk signals, evaluates transactions against a rule library, and produces deterministic fraud decisions.
No machine learning is used, all outcomes are traceable, explainable, and auditable.

SentinelScore demonstrates how a modern risk team can build a transparent rule engine, validate performance, and support downstream analytics using SQL + Python.

## Project Goals
### SentinelScore was designed to:
- Generate realistic, labeled fraud and legitimate data
- Model layered risk signals (devices, sessions, recipients, velocity, amount deviation)
- Build a deterministic rule engine with clear scoring logic
- Produce decisions with audit-ready explanations
- Validate accuracy using both SQL (operational metrics) and Python (analytic metrics)

### This project outlines a strong demonstration of:
- fraud pattern recognition
- rule-based scoring
- SQL data modeling
- cross-system validation
- risk controls design

## The Business Problem
### Post-pandemic fraud patterns have shifted dramatically toward:
- APP scams (authorized push payment fraud)
- ATO attacks (credential theft, social engineering)
- High-velocity P2P drains
- New-device session compromises
- Merchant spike fraud
Traditional ML systems struggle because:
- labels are noisy ("authorized" fraud)
- scammers exploit non-financial signals (device behavior, session anomalies)
- supervised models can't adapt fast enough

SentinelScore’s approach solves this by using deterministic signals + rule logic that mimics real-world fraud operations decisioning.

## Why Rule-Based Fraud Models Still Matter
- Fully explainable
- Easier to tune
- No dependency on labeled data
- Great for early-stage fintechs
- Perfect for APP fraud, which ML models frequently fail to classify
- Direct mapping to risk policies and compliance expectations
SentinelScore focuses on precision over volume, using rules that maximize true positives while minimizing customer friction.

## Architecture Overview
### SentinelScore operates through three structured layers:

### Layer 1 — Core Data Generation
Scripts:
- generate_layer1_core.py
- generate_layer1_transactions.py

Produces:
- users
- devices
- user-device relationships
- Auth Sessions
- P2P relationships
- Base Transactions (Legitimate + Fraud Labels)

### Layer 2 — Behavioral Injection (Fraud Scenarios)
Script:
- generate_layer2_injection.py

Adds:
- Fraud bursts
- First time recipient scams
- Device change anomalies
- Amount deviation patterns
- Velocity spikes
The Layer 2 output becomes the canonical dataset fed into the rule engine.

### Layer 3 - Feature Extraction + Rule Evaluation
Scripts:
- feature_extractor.py
- rules_spec.py
- rule_conditions.py
- rule_evaluator.py
- decision_writerv2.py

This layer:
- Extracts normalized features
- Applies deterministic rule conditions
- Assigns severity + score
- Aggregates rule hits
- Produces final decisions

## Tools Used
This project uses a lightweight, modern workflow consistent with how risk teams evaluate rule engines:
- Python 3.9 — data generation, feature extraction, rule evaluation
- PostgreSQL (Supabase) — cloud Postgres instance used for schema, inserts, and SQL validation
- Jupyter Notebook — analytic validation (AUC, precision/recall, drift, explainability)
- Pandas / NumPy — data transformation
- Matplotlib — compact visualizations for validation

No ML frameworks were used, all risk logic is deterministic.

## Active Rules (7 Total)
Seven rules are currently wired into the rule engine:

### ATO / Device / Session
- RULE_ATO_NEW_DEVICE_FAST_SPEND
- RULE_DEVICE_MISMATCH
- RULE_SESSION_SHORT_LIVED
### Hybrid / Social Engineering
- RULE_HYBRID_ATO_APP_SCAM
Velocity / Amount
- RULE_P2P_HIGH_VELOCITY
- RULE_MERCHANT_SPIKE
- RULE_AMOUNT_LARGE_DEVIATION

These rules are:
- deterministic
- fully explainable
- versioned
- wired directly through rules_spec.py

### Not activated (Future Enhancements)
These rule conditions exist in code but are intentionally not wired into rules_spec.py:
- RULE_ATO_PASSWORD_RESET
- RULE_ATO_MFA_BYPASS
- RULE_ATO_GEO_CHANGE
They remain available for future rule-set expansion and do not impact current scoring.

## Output: Decisions & Rule Hits
### Decisions (decisions table with CSV)
Each transaction receives:

| Field              | Purpose                       |
|--------------------|-------------------------------|
| `txn_id`           | Transaction being evaluated   |
| `user_id`          | ID of User                    |
| `decision`         | approve / review / decline    |
| `risk_score`       | Sum of triggered rule scores  |
| `reason_codes`     | JSON Format Explanation       |
| `created_at`       | Evaluation timestamp          |


### Rule Hits (rule_hits table with CSV)
Each triggered rule produces a row with:
| Field              | Purpose                           |
|--------------------|-----------------------------------|
| `rule_hit_id`      | Unique identifier                 |
| `txn_id`           | Transaction                       |
| `rule_name`        | Which rule fired                  |
| `severity`         | low / medium / high / critical    |
| `signal_values`    | Supporting values for explanation |
| `created_at`       |  Timestamp                        |
The rule engine is fully auditable — every scored decision can be reconstructed.

## SQL Schema 
The complete relational schema is included in schema.sql, featuring:
- users
- devices
- user_devices
- device_enrichments
- auth_sessions
- auth_failures
- merchants
- p2p_recipients
- fraud_events
- transactions (with XOR merchant/p2p constraint)
- rule_hits
- decisions
- user_baselines (future expansion table)

### Note: user_baselines is unused in current version:
This table exists for anticipated enhancements (behavior-driven thresholds) but is intentionally set aside in this release.

## Quick Start
### Layer 1
python generate_layer1_core.py\
python generate_layer1_transactions.py

### Layer 2
python generate_layer2_injection.py

### Rule Engine
python decision_writerv2.py

## Validation Framework
SentinelScore uses a hybrid validation strategy:

SQL Validation (Operational Metrics)
- True positives
- False positives
- FN/FP rates
- Threshold Sensitivity
- Score Distribution
- Rule frequency checks
- Fraud coverage by scenario
- Feature completeness (no null signal fields)
Supabase was used as the Postgres environment to show how modern fintech risk teams store events, rule hits, and decisions. All schema creation, inserts, and SQL-based validation were executed using the Supabase SQL editor.

Python Validation (Analytic Metrics)
Located in: SentinelScore_Validation.ipynb

Includes:
- AUC
- Precision, Recall, F1
- Feature drift analysis
- Rule activation frequency
- Multi-rule stacking
- Explainability checks
- Determinism checks
- Case-level reconstruction (“traceback test”)

Sample results (example from the validation notebook)
- Precision: 1.00
- Recall: ~0.60
- F1: ~0.75
- AUC: ~0.91
These figures come from the synthetic dataset used in validation — they will vary if the data generation code is modified.

## Determinism Guarantees

- No randomness is used after fraud labels are assigned
- No machine learning models
- Pure rule-based scoring
- Same inputs - identical outputs
- Decisions and rule hits can be reconstructed from raw features
Determinism in my opinion is crucial for auditability and operational trust.

## Future Expansion
The following extensions were designed but not implemented due to scope constraints or schema consistency considerations:

Additional Fraud Scenarios
Originally eight scenarios were planned. The final build includes the major ones, but these remain candidates for v3:
- complex ATO sequences
- mixed-channel fraud
- coordinated recipient ring behavior
- synthetic identity micro-spend patterns

Behavioral Baselines (user_baselines table)
A future version could calculate:
- per-user velocity norms
- per-user spend profiles
- temporal patterns
- device trust baselines
- recipient trust scoring
This provides a path to more adaptive rule scoring.

Additional Rule Families
The three dormant rules can be activated once the schema supports their signals:
- RULE_ATO_PASSWORD_RESET
- RULE_ATO_MFA_BYPASS
- RULE_ATO_GEO_CHANGE

Risk Score Calibration
Current thresholds:
- decline ≥ 70
- review ≥ 30
A future iteration could tune these thresholds using grid search or historical calibration.

API Layer
A lightweight REST interface could be added later for:
- scoring requests
- rule introspection
- export of decision logs

## Summary
My project demonstrates how a risk team would structure a transparent fraud-scoring pipeline without machine learning, emphasizing clarity, reproducibility, and operational alignment.
