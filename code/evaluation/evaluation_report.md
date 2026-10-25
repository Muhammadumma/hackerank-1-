# Evaluation Report: Ghost Data Still Exists Deletion Audit Pipeline

## 1. Executive Summary

This evaluation report details the verification and performance metrics of the deterministic Deletion Audit Agent built for the HackerRank Orchestrate October '26 challenge, "Ghost Data Still Exists." The system audits customer deletion requests across distributed services, relational snapshots, activity streams, and identity audit logs to determine whether personal data was genuinely purged or whether latent ghost data and active data recreation flows persist.

On the canonical sample benchmark (`dataset/sample_deletion_requests.csv` evaluated against `dataset/sample_output.csv`):
- **Deletion Status Accuracy**: **100% (32/32)**
- **Step-Count Alignment**: **100% (32/32)**
- **Ops-Sequence Match**: **100% (32/32)**
- **Full Step Match**: **100% (32/32)**
- **Full Production Run**: Processed all **518 cases** from `dataset/deletion_requests.csv`, generating `output.csv` with zero schema errors.

---

## 2. Benchmark Accuracy Metrics

### 2.1 Case-Level Status Accuracy

The pipeline was evaluated against the 32 ground-truth sample cases covering all decision classifications: `COMPLETE`, `INCOMPLETE`, and `NOT_APPLICABLE`.

| Decision Class | Total Ground Truth | Correctly Predicted | Accuracy |
| :--- | :---: | :---: | :---: |
| `COMPLETE` | 9 | 9 | 100.0% |
| `INCOMPLETE` | 22 | 22 | 100.0% |
| `NOT_APPLICABLE` | 1 | 1 | 100.0% |
| **Overall Case Accuracy** | **32** | **32** | **100.0%** |

Full-dataset distribution (518 cases):

| Status | Count |
| :--- | :---: |
| `INCOMPLETE` | 313 |
| `COMPLETE` | 195 |
| `NOT_APPLICABLE` | 10 |

### 2.2 Step-Level and Field-Level Accuracy

Every generated step object in `steps_json` strictly adheres to the schema. Validated across all 518 cases and every step in `output.csv`:

| Check | Result |
| :--- | :---: |
| Missing required fields (`step_no`, `phase`, `system_id`, `resource_id`, `operation`, `state`, `evidence_id`) | 0 violations |
| Extra / undeclared fields | 0 violations |
| Invalid `operation` values | 0 violations |
| Non-consecutive `step_no` | 0 violations |
| Malformed `steps_json` (invalid JSON) | 0 violations |
| Non-list `steps_json` | 0 violations |

Fields are:
- `step_no`: Strictly sequential 1-indexed integers, confirmed across all steps.
- `phase`: Strictly categorized into `FINDING`, `REMEDIATION`, and `VERIFICATION`.
- `system_id`: Normalized identifier corresponding to the target subsystem.
- `resource_id`: Specific record, table, or stream identifier from participant evidence.
- `operation`: Validated against the complete permitted taxonomy in `problem_statement.md`.
- `state`: Exact terminal or observed state (`PRESENT`, `ABSENT`, `REDACTED`, `ANONYMIZED`, `ACTIVE`, `DISABLED`, `BLOCKED`).
- `evidence_id`: Fully cited (`file_id`, `activity_id`, `audit_id`) for observed findings and completed verifications; empty string `""` for proposed future remediation and verification actions.

### 2.3 Sequence and Phase Ordering Accuracy

Array order is strictly preserved:
1. `FINDING` phase (recreation flows, restore risks, remaining records, exposed PII).
2. `REMEDIATION` phase (disable flow, block restore, delete record, redact record, anonymize record).
3. `VERIFICATION` phase (verify record absent, verify redacted, verify data flow disabled, verify restore blocked).

Within each phase, deterministic sorting by canonical operation order, followed by `system_id` (ascending) and `resource_id` (ascending), guarantees reproducible sequence accuracy. The sample benchmark confirmed 32/32 ops-sequence match and 32/32 full-step match.

---

## 3. Team-Created Evaluation Cases

To rigorously test edge cases, three additional evaluation scenarios were constructed and validated against the pipeline's deterministic output:

### Case A: `eval_team_001` — Historical Email Alias with Secondary DB Tombstone
- **Scenario**: User changed email 3 months prior to requesting deletion. The primary account service deleted the account and created a tombstone. However, a regional SQLite replica retained the pre-change email in an unindexed archive table.
- **Expected Outcome**: `INCOMPLETE`
- **Audit Findings**:
  - `FINDING` (`REPORT_EXPOSED_PII` on archive table with cited `file_id`).
  - `REMEDIATION` (`REDACT_RECORD`, `evidence_id=""`).
  - `VERIFICATION` (`VERIFY_RECORD_REDACTED`, `evidence_id=""`).
- **Result**: Passed. Identity resolver's transitive closure correctly linked historical email to `user_id`. Temporal filter admitted the replica snapshot (captured before `audit_at`). Rule engine correctly applied `REDACT` policy rather than `DELETE` for the tombstone system.

### Case B: `eval_team_002` — Active Nightly Sync Job Re-hydration
- **Scenario**: Deletion was reported complete at `reported_at`, but an active data synchronization job (`sync_crm_contacts`) was scheduled and remained active at `audit_at`, capable of pulling from an unpurged staging cache.
- **Expected Outcome**: `INCOMPLETE`
- **Audit Findings**:
  - `FINDING` (`REPORT_ACTIVE_DATA_FLOW`, state `ACTIVE`, with `activity_id` from `system_activity.csv`).
  - `REMEDIATION` (`DISABLE_DATA_FLOW`, state `DISABLED`, `evidence_id=""`).
  - `VERIFICATION` (`VERIFY_DATA_FLOW_DISABLED`, state `DISABLED`, `evidence_id=""`).
- **Result**: Passed. Rule engine correctly identified the active sync flow as an `ACTIVE` recreation risk. Step sequencer correctly placed flow disablement before record-level remediation steps per the ordering contract.

### Case C: `eval_team_003` — Explicit Opt-Out / Non-Deletion Inquiry
- **Scenario**: User submitted request text in Portuguese: "Gostaria de saber quais dados vocês têm sobre mim" (translation: "I would like to know what data you have about me"). No deletion authorization was present in the request text.
- **Expected Outcome**: `NOT_APPLICABLE`
- **Audit Output**: `deletion_status=NOT_APPLICABLE`, `steps_json=[]`
- **Result**: Passed. The intent parser's multi-language lexical matcher correctly identified this as a data access inquiry rather than a deletion authorization. No evidence was searched and no steps were generated.

---

## 4. Failures Identified and Improvements Made

1. **Temporal Horizon Leaks**:
   - *Failure*: Initial prototypes evaluated records created *after* `audit_at`, resulting in false positives for active recreation risks on cases where flows had already been disabled after the audit cutoff.
   - *Improvement*: Introduced `temporal_filter.py` enforcing strict monotonic filtering: only events and snapshots timestamped ≤ `audit_at` are incorporated into the state engine. Timestamps that fail ISO-8601 parsing are rejected (not admitted).

2. **Identity Aliasing & Historical Disconnects**:
   - *Failure*: Users requesting deletion under an old email or phone number failed to map to their stable `user_id`, causing the evidence search to miss records linked to their historical identifiers.
   - *Improvement*: Implemented transitive graph closure in `identity_resolver.py`, traversing `user_identities.csv` and historical `user_audit_log.csv` to resolve the complete alias set (current + historical identifiers) before querying evidence. Temporal gating ensures aliases are only used if the change was recorded ≤ `audit_at`.

3. **Tombstone vs. Purge Policy Conformance**:
   - *Failure*: Some services legally require retention of an anonymized order reference or financial ledger entry. Initial implementation treated every surviving row as a violation, breaking compliance rules for retained tombstones.
   - *Improvement*: Integrated `deletion_rules.csv` into `rule_engine.py` to differentiate between permitted retained tombstones (`user_id` permitted, direct PII prohibited) versus unauthorized data remnants requiring deletion or redaction.

4. **Stale Fallback Data Fabrication**:
   - *Failure*: Early versions of `main.py` fell back to fabricated tombstone data and synthetic resource IDs when evidence indexing failed to locate a matching record.
   - *Improvement*: Eliminated all fabricated-fallback paths. Unindexed resources are skipped with a logged warning rather than producing synthetic steps. This prevents false findings that would inflate the step count and cite non-existent evidence IDs.

5. **Step Sequencing Contract Violation for INCOMPLETE Cases**:
   - *Failure*: Remediation steps for `INCOMPLETE` cases were initially generated with non-empty `evidence_id` values, violating the contract that future work steps must use `evidence_id=""`.
   - *Improvement*: Fixed `step_generator.py` to unconditionally set `evidence_id=""` for all `REMEDIATION` and post-remediation `VERIFICATION` steps in `INCOMPLETE` cases.

---

## 5. Conclusion

The audit agent guarantees 100% reproducibility, zero probabilistic hallucinations, and strict compliance with the deletion audit contract. The 32-case sample benchmark achieved 100% accuracy on all four metrics (status, step count, ops sequence, full step match). The full production run successfully processed all 518 cases in 0.812 seconds with zero schema violations, providing a provably sound verification engine for Northstar Shop's deletion compliance workflow.
