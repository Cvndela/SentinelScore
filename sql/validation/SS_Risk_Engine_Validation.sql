-- ====================================
-- SentinelScore Risk Engine Validation 
-- ====================================

-- # Confusion Matrix # -- 

with cm as (
  select
    d.txn_id,
    d.decision,
    t.label_is_fraud
  from sentinelscore.decisions d
  join sentinelscore.transactions t
    on t.txn_id = d.txn_id
)
select
  label_is_fraud,
  sum(case when decision = 'approve' then 1 else 0 end) as approve_ct,
  sum(case when decision = 'review'  then 1 else 0 end) as review_ct,
  sum(case when decision = 'decline' then 1 else 0 end) as decline_ct
from cm
group by label_is_fraud
order by label_is_fraud;

-- # Rule Activtion Frequency # --

select 
	rule_name,
	count(*) as hits
from sentinelscore.rule_hits
group by rule_name
order by hits desc


-- # Fraud vs Clean Per Rule View # --
with hits as (
	select
		rh.rule_name,
		t.label_is_fraud
	from sentinelscore.rule_hits rh
	join sentinelscore.transactions t
	  on t.txn_id = rh.txn_id
)
select 
	rule_name,
	sum(case when label_is_fraud then 1 else 0 end) as fraud_hits,
	sum(case when not label_is_fraud then 1 else 0 end) as clean_hits,
	round(
		sum(case when label_is_fraud then 1 else 0 end)::numeric/
		nullif(count(*), 0),
		3
	) as fraud_hit_rate
from hits
group by rule_name
order by fraud_hit_rate desc, fraud_hits desc;

-- # Multi Rule Stack for Fired Rules # --
with per_txn as (
	select
	 	txn_id,
	 	count(distinct rule_name) as rules_triggered
	 from sentinelscore.rule_hits
	 group by txn_id
)
select 
	rules_triggered,
	count(*) as txn_count
from per_txn
group by rules_triggered
order by rules_triggered;

-- # Score Distribution # --
with sd as (
	select
	  d.txn_id,
	  d.risk_score,
	  t.label_is_fraud
	from sentinelscore.decisions d
	join sentinelscore.transactions t
	  on t.txn_id = d.txn_id
)
select 
	label_is_fraud,
	count(*) as n,
	round(min(risk_score), 2) as min_score,
	round(max(risk_score), 2) as max_score,
	round(avg(risk_score), 2) as avg_score
from sd
group by label_is_fraud
order by label_is_fraud;


-- # Threshold Sensitivity # --
with ts as (
select
	d.txn_id,
	d.risk_score,
	t.label_is_fraud
from
	sentinelscore.decisions d
join sentinelscore.transactions t
    on
	t.txn_id = d.txn_id
)
select
	'T70_R30' as config,
	sum(case when risk_score >= 70 then 1 else 0 end) as declines,
	sum(case when risk_score between 30 and 69.999 then 1 else 0 end) as reviews,
	sum(case when risk_score < 30 then 1 else 0 end) as approves
from
	ts
union all
select
	'T60_R25' as config,
	sum(case when risk_score >= 60 then 1 else 0 end) as declines,
	sum(case when risk_score between 25 and 59.999 then 1 else 0 end) as reviews,
	sum(case when risk_score < 25 then 1 else 0 end) as approves
from
	ts
union all
select
	'T80_R40' as config,
	sum(case when risk_score >= 80 then 1 else 0 end) as declines,
	sum(case when risk_score between 40 and 79.999 then 1 else 0 end) as reviews,
	sum(case when risk_score < 40 then 1 else 0 end) as approves
from
	ts;

-- # Drift/Stability by Month # --
with drift as (
select
	d.txn_id,
	d.decision,
	t.label_is_fraud,
	date_trunc('month', t.created_at) as month
from
	sentinelscore.decisions d
join sentinelscore.transactions t
    on
	t.txn_id = d.txn_id
)
select
	month,
	count(*) as total_txns,
	sum(case when decision = 'approve' then 1 else 0 end) as approves,
	sum(case when decision = 'review' then 1 else 0 end) as reviews,
	sum(case when decision = 'decline' then 1 else 0 end) as declines,
	sum(case when label_is_fraud then 1 else 0 end) as fraud_txns
from
	drift
group by
	month
order by
	month;

-- # Null Check for Key Features # --
select
	count(*) as total_txns,
	sum(case when created_at is null then 1 else 0 end) as null_created_at,
	sum(case when amount is null then 1 else 0 end) as null_amount,
	sum(case when velocity_1h is null then 1 else 0 end) as null_velocity,
	sum(case when amount_vs_user_avg_multiplier is null then 1 else 0 end) as null_multiplier
from
	sentinelscore.transactions;
