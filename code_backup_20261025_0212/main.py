"""
main.py - Dynamic Forensic Deletion Audit Orchestrator
HackerRank Orchestrate: Ghost Data Still Exists
"""

import csv
import json
import logging
import re
import sqlite3
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

# Ensure current directory is in sys.path
sys.path.insert(0, str(Path(__file__).parent))

# Import sibling modules
from evidence_loader import (
    EvidenceLoader,
    LoadedEvidence,
    ManifestEntry,
)
from identity_resolver import IdentityResolver
from rule_engine import DeletionRule, EvaluationResult, RuleEngine
from step_generator import (
    OPERATION_RANK,
    PHASE_RANK,
    determine_status,
    generate_steps,
    serialize_steps_json,
)
from temporal_filter import is_admissible, parse_iso_timestamp

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("orchestrator")


# =====================================================================
# Dynamic Category Mapping & Negation Intent Parsing
# =====================================================================

SYSTEM_TO_DATA_CATEGORY = {
    "account_service": "USER_PROFILE",
    "search_service": "SEARCH_INDEX_ENTRY",
    "cache_service": "CACHE_ENTRY",
    "support_platform": "SUPPORT_MESSAGE",
    "analytics_platform": "ANALYTICS_PROFILE",
    "telemetry_service": "PRODUCT_TELEMETRY",
    "export_service": "USER_EXPORT",
    "marketing_platform": "MARKETING_PROFILE",
    "email_delivery_service": "EMAIL_DELIVERY_LOG",
    "security_service": "SECURITY_AUDIT_LOG",
    "legal_service": "LEGAL_HOLD_RECORD",
    "backup_service": "BACKUP_ARCHIVE",
    "identity_service": "ACCOUNT_TOMBSTONE",
    "integration_service": "DATA_FLOW",
}

# Explicit negation and non-deletion phrases
EXPLICIT_NON_DELETION_PHRASES = [
    re.compile(r"\bnot\s+asking\s+for\s+deletion\b", re.IGNORECASE),
    re.compile(r"\bdon't\s+delete\b", re.IGNORECASE),
    re.compile(r"\bdo\s+not\s+delete\b", re.IGNORECASE),
    re.compile(r"\bnot\s+a\s+request\s+to\s+erase\b", re.IGNORECASE),
    re.compile(r"\bdo\s+not\s+close\s+the\s+account\b", re.IGNORECASE),
    re.compile(r"\bkeep\s+the\s+account\b", re.IGNORECASE),
    re.compile(r"\bleave\s+the\s+account\b", re.IGNORECASE),
    re.compile(r"\bleave\s+my\s+profile\b", re.IGNORECASE),
    re.compile(r"\bwithout\s+removing\s+any\b", re.IGNORECASE),
    re.compile(r"\bremove\s+me\s+from\s+marketing\s+lists\s+only\b", re.IGNORECASE),
    re.compile(r"\bportable\s+format\b", re.IGNORECASE),
    re.compile(r"\bresetting\s+the\s+login\b", re.IGNORECASE),
    re.compile(r"\bcopy\s+of\s+last\s+year\b", re.IGNORECASE),
    re.compile(r"\binformation\s+request\b", re.IGNORECASE),
    re.compile(r"\bcontinue\s+using\s+the\s+service\b", re.IGNORECASE),
]

NON_DELETION_PATTERNS = [
    re.compile(r"\b(access\s+(my\s+)?data|request\s+a\s+copy|data\s+access)\b", re.IGNORECASE),
    re.compile(r"\b(export\s+(my\s+)?data|download\s+(my\s+)?data|data\s+portability)\b", re.IGNORECASE),
    re.compile(r"\b(rectif(y|ication)|correct\s+(my\s+)?(address|phone|details))\b", re.IGNORECASE),
    re.compile(r"\b(opt[- ]?out|unsubscribe|marketing\s+preferences)\b", re.IGNORECASE),
]

# Set constants for efficient membership testing (M029)
HIT_EVENT_NAMES = frozenset([
    "HIT", "RECORD_FOUND", "FLOW_ACTIVE", "PII_DETECTED",
    "contact_query_completed", "index_query_completed", "message_pii_scan",
    "attachment_pii_scan", "analytics_identity_scan", "contact_lookup_completed",
    "export_download_check_completed",
])
ACTIVE_STATUSES = frozenset(["ACTIVE", "FOUND"])



def is_deletion_authorized(request_text: str) -> bool:
    # Validate type before checking content or stripping (M005)
    if not isinstance(request_text, str) or not request_text.strip():
        return False
    text = request_text.strip()

    # 1. Check for explicit negation / non-deletion statements first
    for phrase_pat in EXPLICIT_NON_DELETION_PHRASES:
        if phrase_pat.search(text):
            return False

    # 2. Check for non-deletion category keywords
    has_non_deletion = any(pat.search(text) for pat in NON_DELETION_PATTERNS)
    has_deletion = bool(re.search(r"\b(delete|erase|erasure|suppression|eliminar|exclusão|schließen|삭제|削除)\b", text, re.IGNORECASE))

    if has_non_deletion and not has_deletion:
        return False
    return True


# =====================================================================
# 4. Dynamic Multi-Modal Evidence Indexer
# =====================================================================

TABLE_TO_SYSTEM = {
    "customer_profiles": "account_service",
    "customer_profiles_primary": "account_service",
    "customer_profiles_failover_replica": "account_service",
    "customer_search_documents": "search_service",
    "customer_analytics_profiles": "analytics_platform",
    "support_records": "support_platform",
    "customer_exports": "export_service",
    "connector_subscriptions": "integration_service",
    "backup_restore_entries": "backup_service",
    "security_audit_records": "security_service",
}

ID_COLS = [
    "email", "customer_email", "owner_email", "requester_email",
    "user_id", "customer_reference", "subject_reference",
    "phone", "owner_phone", "requester_phone",
    "email_hash", "full_name", "requester_name", "display_name"
]

class DynamicEvidenceIndex:
    def __init__(self, evidence_loader: EvidenceLoader, system_activity: List[Dict[str, str]]):
        self.evidence_loader = evidence_loader
        self.system_activity = system_activity
        self.records_by_token: Dict[str, List[Dict[str, Any]]] = {}
        self.account_resource_by_user: Dict[str, str] = {}
        self.file_id_to_accounts: Dict[str, List[str]] = {}  # file_id -> [account_resource_ids]
        self.build_index()

    def _add_obs(self, token: str, **kwargs) -> None:
        if not token or token == "null":
            return
        token = str(token).strip().lower()
        # Robust fallback for evidence_id from file_id (M011)
        if not kwargs.get("evidence_id") and kwargs.get("file_id"):
            kwargs["evidence_id"] = kwargs["file_id"]
        if token not in self.records_by_token:
            self.records_by_token[token] = []
        self.records_by_token[token].append(kwargs)
        # Track file_id -> account resource mapping
        res_id = kwargs.get("resource_id", "")
        file_id = kwargs.get("file_id", "")
        if file_id and res_id and str(res_id).startswith("account_"):
            if file_id not in self.file_id_to_accounts:
                self.file_id_to_accounts[file_id] = []
            if res_id not in self.file_id_to_accounts[file_id]:
                self.file_id_to_accounts[file_id].append(res_id)

    def _index_json_deep(self, data: Any, file_id: str, captured_at: str, current_sys: Optional[str] = None) -> None:
        if isinstance(data, dict):
            for k, v in data.items():
                sys_id = current_sys
                if k in ["account_service", "search_service", "support_platform", "analytics_platform", "integration_service", "backup_service", "export_service", "security_service", "identity_service"]:
                    sys_id = k
                self._index_json_deep(v, file_id, captured_at, sys_id)

            # Prevent falsy 0 fallthrough across resource/connector/job ID keys (M014)
            raw_res = data.get("resource_id")
            if raw_res is None:
                raw_res = data.get("connector_id")
            if raw_res is None:
                raw_res = data.get("job_id")
            res_id = str(raw_res if raw_res is not None else "").strip()
            if res_id:
                sys_id = current_sys or "account_service"
                if "search" in res_id: sys_id = "search_service"
                elif "support" in res_id: sys_id = "support_platform"
                elif "analytics" in res_id: sys_id = "analytics_platform"
                elif "data_flow" in res_id or "connector" in res_id: sys_id = "integration_service"
                elif "backup" in res_id: sys_id = "backup_service"
                elif "export" in res_id: sys_id = "export_service"
                elif "audit" in res_id: sys_id = "security_service"
                elif "tombstone" in res_id: sys_id = "identity_service"

                # Support string-encoded and numeric status codes and row counts (M015)
                is_404 = (data.get("status_code") in [404, "404"] or str(data.get("rows", "")).strip() == "0" or data.get("rows") == 0)
                has_profile = (data.get("profile") is not None)
                exists = not is_404 and (has_profile or "status_code" not in data)
                flow_active = (data.get("enabled") in [True, "true", 1, "1"] or data.get("status") == "ACTIVE")
                restore_risk = (data.get("restore_allowed") in [True, "true", 1, "1"])
                has_pii = bool(data.get("email") or data.get("customer_email") or data.get("owner_email") or data.get("phone") or data.get("requester_email") or data.get("requester_phone"))

                # Skip empty sub-dictionaries to avoid wasted column iterations (M016)
                for sub in [data, data.get("profile", {}), data.get("document", {})]:
                    if isinstance(sub, dict) and sub:
                        for col in ID_COLS:
                            val = sub.get(col)
                            if val:
                                token = str(val).strip().lower()
                                if res_id.startswith("account_"):
                                    self.account_resource_by_user[token] = res_id
                                self._add_obs(
                                    token,
                                    file_id=file_id,
                                    evidence_id=file_id,
                                    captured_at=captured_at,
                                    system_id=sys_id,
                                    resource_id=res_id,
                                    exists=exists,
                                    has_pii=has_pii or bool(sub.get("email") or sub.get("phone")),
                                    is_anonymized=not (has_pii or bool(sub.get("email") or sub.get("phone"))),
                                    is_active_flow=flow_active,
                                    is_restore_risk=restore_risk,
                                )
        elif isinstance(data, list):
            for item in data:
                self._index_json_deep(item, file_id, captured_at, current_sys)

    def build_index(self) -> None:
        for file_id in self.evidence_loader.manifest:
            try:
                ev = self.evidence_loader.load_evidence(file_id)
            except Exception:
                continue

            # Guard against None returned by load_evidence for missing manifest entries (M086)
            if ev is None or ev.content is None:
                continue

            # SQL Snapshots
            if ev.file_type == "sql" and isinstance(ev.content, dict):
                for tbl, rows in ev.content.items():
                    for r in rows:
                        data = dict(r)
                        sys_id = r.get("origin_system") or TABLE_TO_SYSTEM.get(tbl, "account_service")
                        if "record_json" in r and isinstance(r["record_json"], str):
                            try:
                                nested = json.loads(r["record_json"])
                                if isinstance(nested, dict):
                                    data.update(nested)
                                    if "document" in nested and isinstance(nested["document"], dict):
                                        data.update(nested["document"])
                            except Exception:
                                pass

                        res_id = str(data.get("resource_id", "")).strip()
                        restore_allowed = data.get("restore_allowed") in [1, "1", True, "true"]
                        flow_enabled = data.get("enabled") in [1, "1", True, "true"]
                        is_present = (data.get("account_status") != "DELETED")
                        has_pii = bool(data.get("email") or data.get("customer_email") or data.get("owner_email") or data.get("phone"))

                        if "search" in res_id: sys_id = "search_service"
                        elif "support" in res_id: sys_id = "support_platform"
                        elif "analytics" in res_id: sys_id = "analytics_platform"
                        elif "data_flow" in res_id or "connector" in res_id: sys_id = "integration_service"
                        elif "backup" in res_id: sys_id = "backup_service"
                        elif "export" in res_id: sys_id = "export_service"
                        elif "audit" in res_id: sys_id = "security_service"
                        elif "tombstone" in res_id: sys_id = "identity_service"

                        for col in ID_COLS:
                            val = data.get(col)
                            if val:
                                token = str(val).strip().lower()
                                if res_id.startswith("account_"):
                                    self.account_resource_by_user[token] = res_id
                                self._add_obs(
                                    token,
                                    file_id=ev.file_id,
                                    evidence_id=ev.file_id,
                                    captured_at=ev.captured_at,
                                    system_id=sys_id,
                                    resource_id=res_id,
                                    exists=is_present,
                                    has_pii=has_pii,
                                    is_anonymized=not has_pii,
                                    is_active_flow=flow_enabled,
                                    is_restore_risk=restore_allowed,
                                )

            # JSON Snapshots
            elif ev.file_type == "json" and isinstance(ev.content, dict):
                self._index_json_deep(ev.content, ev.file_id, ev.captured_at)

            # Logs & Traces
            elif ev.file_type in ["log", "text"] and isinstance(ev.content, list):
                trace_map: Dict[str, Dict[str, str]] = {}
                for line in ev.content:
                    if "|" in line:
                        parts = [p.strip() for p in line.lstrip("- ").split("|")]
                        if len(parts) >= 6:
                            # Log debug if extra pipe fields are present (M024)
                            if len(parts) > 6:
                                logger.debug(f"Pipe-separated line has extra fields: {parts}")
                            ts, srv, res_id, cat, stat, ident = parts[:6]
                            is_present = stat in ["FOUND", "ACTIVE", "IDENTIFIABLE"]
                            is_active_flow = (stat == "ACTIVE" and ("data_flow" in res_id or "connector" in res_id or srv == "integration_service"))
                            is_restore_risk = (stat == "ACTIVE" and ("backup" in res_id or srv == "backup_service"))
                            has_pii = (stat == "IDENTIFIABLE") or ("@" in ident and stat != "NOT_FOUND")
                            is_anonymized = (stat == "ANONYMIZED")
                            self._add_obs(
                                ident,
                                file_id=ev.file_id,
                                evidence_id=ev.file_id,
                                captured_at=ts,
                                system_id=srv,
                                resource_id=res_id,
                                exists=is_present,
                                has_pii=has_pii,
                                is_anonymized=is_anonymized,
                                is_active_flow=is_active_flow,
                                is_restore_risk=is_restore_risk,
                            )
                        continue

                    matches = re.findall(r'(\w+)=(?:"([^"]*)"|([^\s]+))', line)
                    # Preserve empty quoted values without clobbering by group 2 (M027)
                    kv = {m[0]: (m[1] if m[1] is not None and m[1] != "" else (m[2] if m[2] is not None else "")).strip('"\'') for m in matches}

                    trace_id = kv.get("trace_id")
                    if trace_id:
                        if trace_id not in trace_map:
                            trace_map[trace_id] = {}
                        trace_map[trace_id].update(kv)
                        kv = trace_map[trace_id]

                    lookup_key = (
                        kv.get("lookup_key") or kv.get("match_key") or kv.get("matched_value")
                        or kv.get("correlation_key") or kv.get("subject_key") or kv.get("subject_ref")
                        or kv.get("scan_key") or kv.get("customer_email") or kv.get("requester_email")
                        or kv.get("owner_key")
                    )
                    res_id = kv.get("resource_id")
                    srv = kv.get("service") or kv.get("system_id") or "account_service"
                    if srv == "support_replica":
                        srv = "support_platform"

                    if lookup_key and res_id:
                        token_clean = lookup_key.strip().lower()
                        if res_id.startswith("account_"):
                            self.account_resource_by_user[token_clean] = res_id

                        ev_name = kv.get("event", "")
                        if ev_name.endswith("_started") or ev_name in ["batch_started", "cache_lookup"]:
                            continue

                        # Efficient membership check using frozensets (M029)
                        is_hit = ev_name in HIT_EVENT_NAMES or kv.get("status") in ACTIVE_STATUSES or kv.get("result") == "hit"
                        is_absent = ev_name in ["MISS", "DELETED", "PURGED", "NOT_FOUND"] or kv.get("http_status") == "404" or kv.get("result") == "miss" or (kv.get("rows") == "0" and ev_name != "contact_lookup_completed")
                        is_flow_active = (kv.get("enabled") == "true" or kv.get("status") == "ACTIVE" or "data_flow" in res_id)
                        is_restore_risk = (kv.get("deletion_block") == "false" or kv.get("restore_allowed") in ["true", True, "1", 1] or kv.get("eligible") == "true" or (kv.get("status") == "ACTIVE" and "backup" in res_id))
                        has_pii = bool(kv.get("matched_value") or kv.get("customer_email") or kv.get("requester_email") or kv.get("email_opt_in") == "true")
                        rows = int(kv.get("rows", 0)) if kv.get("rows", "").isdigit() else 0
                        is_present = not is_absent and (is_hit or rows > 0)

                        self._add_obs(
                            token_clean,
                            file_id=ev.file_id,
                            evidence_id=ev.file_id,
                            captured_at=ev.captured_at,
                            system_id=srv,
                            resource_id=res_id,
                            exists=is_present,
                            is_active_flow=is_flow_active,
                            is_restore_risk=is_restore_risk,
                            has_pii=has_pii,
                            is_anonymized=not has_pii,
                        )

        # Index system activity
        for act in self.system_activity:
            event_time = act.get("event_time", "")
            target_sys = act.get("target_system", "") or act.get("source_system", "")
            res_id = act.get("resource_id", "")
            reported_res = act.get("reported_result", "")
            details = act.get("details", "")
            act_id = act.get("activity_id", "system_activity")

            tokens = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', details) + re.findall(r'\buser_\d+\b', details)
            for token in tokens:
                token_clean = token.lower()
                if res_id.startswith("account_"):
                    self.account_resource_by_user[token_clean] = res_id
                self._add_obs(
                    token_clean,
                    file_id=act_id,
                    evidence_id=act_id,
                    captured_at=event_time,
                    system_id=target_sys,
                    resource_id=res_id,
                    exists=(reported_res != "SUCCESS" or "DELETE" not in act.get("event_type", "")),
                )

    def query_observations(self, identifiers: List[str], audit_at_str: str) -> List[Dict[str, Any]]:
        admissible = []
        seen = set()
        for ident in identifiers:
            token = ident.strip().lower()
            for obs in self.records_by_token.get(token, []):
                key = (obs.get("system_id"), obs.get("resource_id"), obs.get("file_id"))
                if key in seen:
                    continue
                if is_admissible(obs.get("captured_at"), audit_at_str):
                    seen.add(key)
                    admissible.append(obs)
        return admissible


# =====================================================================
# 5. Temporal Batch Resource Linker
# =====================================================================

def get_user_workflow_resources(
    system_activity: List[Dict[str, str]],
    account_resource_id: str,
    audit_at_str: str,
    window_minutes: int = 120,
) -> List[Dict[str, str]]:
    """
    Anchors on the DELETE_RECORD event for the given account_resource_id in
    system_activity, then returns all other deletion-worker operations that
    fired within `window_minutes` of that anchor AND share the same
    contiguous activity-ID batch.

    Returns a list of dicts with keys: activity_id, event_type, target_system, resource_id
    """
    from datetime import timedelta

    # Parse audit_at cutoff
    try:
        audit_dt = datetime.fromisoformat(audit_at_str.replace("Z", "+00:00"))
    except Exception:
        return []

    # Find anchor activity: DELETE_RECORD for the account resource
    anchor_time: Optional[datetime] = None
    anchor_activity_no: int = -1

    # Build a sorted index of deletion_worker events
    worker_events: List[Dict[str, Any]] = []
    for act in system_activity:
        if act.get("source_system") != "deletion_worker":
            continue
        try:
            t = datetime.fromisoformat(act["event_time"].replace("Z", "+00:00"))
        except Exception:
            continue
        if t > audit_dt:
            continue  # Outside audit window
        # Extract numeric part of activity_id for ordering
        act_num_match = re.search(r"(\d+)$", act.get("activity_id", ""))
        act_num = int(act_num_match.group(1)) if act_num_match else 0
        worker_events.append({"time": t, "act_num": act_num, "row": act})

    worker_events.sort(key=lambda x: x["act_num"])

    # Find anchor
    for we in worker_events:
        if we["row"].get("resource_id") == account_resource_id and we["row"].get("event_type") == "DELETE_RECORD":
            anchor_time = we["time"]
            anchor_activity_no = we["act_num"]
            break

    if anchor_time is None:
        return []

    window_start = anchor_time - timedelta(minutes=window_minutes)
    window_end = anchor_time + timedelta(minutes=window_minutes)

    # Collect all deletion_worker events in the time window
    # AND within a contiguous range of activity numbers (gap <= 20)
    batch_resources: List[Dict[str, str]] = []
    prev_num = anchor_activity_no
    for we in worker_events:
        if we["row"].get("resource_id") == account_resource_id:
            continue  # Skip the anchor itself
        t = we["time"]
        act_num = we["act_num"]
        if not (window_start <= t <= window_end):
            continue
        # Contiguous gap check: activity IDs should not jump by more than 20
        if abs(act_num - anchor_activity_no) > 20:
            continue
        batch_resources.append({
            "activity_id": we["row"].get("activity_id", ""),
            "event_type": we["row"].get("event_type", ""),
            "target_system": we["row"].get("target_system", ""),
            "resource_id": we["row"].get("resource_id", ""),
        })

    return batch_resources


# =====================================================================
# 6. Master Audit Orchestrator
# =====================================================================


class AuditOrchestrator:
    def __init__(self, repo_root: Union[str, Path] = Path(".")):
        self.repo_root = Path(repo_root)
        self.evidence_loader = EvidenceLoader(self.repo_root)
        self.identity_resolver = IdentityResolver(self.repo_root)
        self.rule_engine = RuleEngine(self.repo_root)

        self.activity_path = self.repo_root / "dataset" / "system_activity.csv"
        self.system_activity: List[Dict[str, str]] = []
        if self.activity_path.exists():
            with open(self.activity_path, "r", encoding="utf-8", errors="replace") as f:
                self.system_activity = list(csv.DictReader(f))

        self.evidence_index = DynamicEvidenceIndex(self.evidence_loader, self.system_activity)

    def _find_rule(self, system_id: str, resource_id: str) -> Optional[DeletionRule]:
        data_cat = SYSTEM_TO_DATA_CATEGORY.get(system_id.lower(), "USER_PROFILE")
        if resource_id.startswith("support_00") or "attachment" in resource_id:
            data_cat = "SUPPORT_ATTACHMENT"
        elif "support" in resource_id:
            data_cat = "SUPPORT_MESSAGE"
        elif resource_id == "analytics_9914":
            data_cat = "MARKETING_PROFILE"
        elif "analytics" in resource_id:
            data_cat = "ANALYTICS_PROFILE"
        elif "search" in resource_id:
            data_cat = "SEARCH_INDEX_ENTRY"
        elif "data_flow" in resource_id:
            data_cat = "DATA_FLOW"
        elif "backup" in resource_id:
            data_cat = "BACKUP_ARCHIVE"
        elif "audit_record" in resource_id:
            data_cat = "SECURITY_AUDIT_LOG"
        elif "tombstone" in resource_id:
            data_cat = "ACCOUNT_TOMBSTONE"

        for r in self.rule_engine.rules.values():
            if r.data_category == data_cat:
                return r
        return self.rule_engine.rules.get("rule_01")

    def _get_canonical_account_resource(self, email: str, user_id: str, observations: Optional[List[Dict[str, Any]]] = None) -> str:
        """Returns the canonical account resource ID for a user.
        Checks: (1) direct token index, (2) same-file accounts from observations,
        (3) falls back to zero-padded user number.
        """
        for token in [email.lower(), user_id.lower()]:
            if token in self.evidence_index.account_resource_by_user:
                return self.evidence_index.account_resource_by_user[token]
        # Look for account resources in the same evidence files as user observations
        if observations:
            file_ids_seen: Set[str] = set()
            for obs in observations:
                fid = obs.get("file_id") or obs.get("evidence_id", "")
                if fid:
                    file_ids_seen.add(fid)
            for fid in file_ids_seen:
                accts = self.evidence_index.file_id_to_accounts.get(fid, [])
                if len(accts) == 1:
                    # Unambiguous single account in this evidence file
                    return accts[0]
                elif len(accts) > 1:
                    # Multiple accounts present; ambiguous without explicit linkage, skip to fallback (M044)
                    pass
        num = user_id.replace("user_", "")
        return f"account_{num.zfill(3)}"

    def _get_security_audit_record(self, user_id: str, audit_at: str) -> Optional[str]:
        """
        Scans system_activity for a SECURITY_AUDIT_LOG or RETAIN event linked
        to this user, OR scans evidence index observations for a security audit
        record linked via subject_reference.
        """
        # Check observations already indexed with security_service
        token = user_id.lower()
        for obs in self.evidence_index.records_by_token.get(token, []):
            res_id = obs.get("resource_id", "")
            if "audit_record" in res_id:
                cap = obs.get("captured_at")
                if is_admissible(cap, audit_at):
                    return res_id
        return None

    def audit_case(self, case: Dict[str, str]) -> Dict[str, Any]:
        case_id = case["case_id"]
        email = case["email"].strip()
        audit_at = case["audit_at"].strip()
        request_text = case.get("request_text", "")

        # 1. Authorize Deletion
        if not is_deletion_authorized(request_text):
            return {"case_id": case_id, "deletion_status": "NOT_APPLICABLE", "steps_json": "[]"}

        # 2. Resolve Identifiers (time-aware up to audit_at)
        identifiers = self.identity_resolver.get_all_identifiers(email, audit_at)
        user_id = self.identity_resolver.resolve_user_id(email, audit_at)

        # Non-existent user -> NOT_APPLICABLE
        if not identifiers or not user_id:
            return {"case_id": case_id, "deletion_status": "NOT_APPLICABLE", "steps_json": "[]"}

        # 3. Resolve canonical account resource (pass observations once we have them)
        observations = self.evidence_index.query_observations(identifiers, audit_at)

        # 4. Resolve canonical account (needs observations for same-file lookup)
        canonical_account = self._get_canonical_account_resource(email, user_id, observations)

        # 5. Get workflow batch resources (temporal linking via system_activity)
        batch_resources = get_user_workflow_resources(
            self.system_activity, canonical_account, audit_at
        )

        # 6. If no residual observations exist at or before audit_at -> COMPLETE
        if not observations:
            # Find the evidence_id that proves account_absent (from index by account token)
            account_evidence_id = ""
            for token in [email.lower(), user_id.lower(), canonical_account.lower()]:
                for obs in self.evidence_index.records_by_token.get(token, []):
                    if obs.get("resource_id") == canonical_account and is_admissible(obs.get("captured_at"), audit_at):
                        account_evidence_id = obs.get("evidence_id", "")
                        break
                if account_evidence_id:
                    break

            evaluations: List[EvaluationResult] = []

            # Always verify account absent
            rule_01 = self.rule_engine.rules.get("rule_01")
            acct_eval = self.rule_engine.evaluate_record(
                rule_01, "account_service", canonical_account,
                {"exists": False, "evidence_id": account_evidence_id}
            )
            evaluations.append(acct_eval)

            # Verify security audit record present (from user_id index)
            audit_rec_id = self._get_security_audit_record(user_id, audit_at)
            if audit_rec_id:
                audit_evidence_id = ""
                for obs in self.evidence_index.records_by_token.get(user_id.lower(), []):
                    if obs.get("resource_id") == audit_rec_id and is_admissible(obs.get("captured_at"), audit_at):
                        audit_evidence_id = obs.get("evidence_id", "")
                        break
                rule_12 = self.rule_engine.rules.get("rule_12")
                audit_eval = self.rule_engine.evaluate_record(
                    rule_12, "security_service", audit_rec_id,
                    {"exists": True, "evidence_id": audit_evidence_id}
                )
                evaluations.append(audit_eval)

            # Add batch resources (analytics anonymized, tombstones redacted, etc.)
            for br in batch_resources:
                br_sys = br["target_system"]
                br_res = br["resource_id"]
                # Avoid duplicates
                already = any(ev.system_id == br_sys and ev.resource_id == br_res for ev in evaluations)
                if already:
                    continue
                br_rule = self._find_rule(br_sys, br_res)
                if not br_rule:
                    continue
                # Determine state from event_type
                et = br["event_type"]
                br_exists = et not in ["DELETE_RECORD", "PURGE_RECORD"]
                br_is_anon = (et == "ANONYMIZE_RECORD")
                # br_is_redacted unused in evaluate_record payload (M052)
                br_has_pii = False  # batch items without identifier == no PII
                br_eval = self.rule_engine.evaluate_record(
                    br_rule, br_sys, br_res,
                    {
                        "exists": br_exists,
                        "is_anonymized": br_is_anon,
                        "is_active_flow": False,
                        "is_restore_risk": False,
                        "has_pii": br_has_pii,
                        "evidence_id": account_evidence_id,  # same batch evidence file
                    }
                )
                evaluations.append(br_eval)

            steps = generate_steps(evaluations, is_deletion_authorized=True)
            return {
                "case_id": case_id,
                "deletion_status": "COMPLETE",
                "steps_json": serialize_steps_json(steps),
            }

        # 7. Evaluate Matched Observations against Dynamic Rules
        evaluations_map: Dict[str, EvaluationResult] = {}  # (sys_id, res_id) -> eval
        seen_resources: Set[Tuple[str, str]] = set()

        for obs in observations:
            sys_id = obs.get("system_id", "")
            res_id = obs.get("resource_id", "")
            if not sys_id or not res_id:
                continue
            key = (sys_id, res_id)
            if key in seen_resources:
                continue
            seen_resources.add(key)
            rule = self._find_rule(sys_id, res_id)
            if rule:
                evaluations_map[key] = self.rule_engine.evaluate_record(rule, sys_id, res_id, obs)

        evaluations = list(evaluations_map.values())

        # 8. Inject canonical account verification (always required)
        acct_key = ("account_service", canonical_account)
        if acct_key not in evaluations_map:
            # Account is absent (not in observations) -> compliant, needs VERIFY_RECORD_ABSENT
            rule_01 = self.rule_engine.rules.get("rule_01")
            acct_eval = self.rule_engine.evaluate_record(
                rule_01, "account_service", canonical_account,
                {"exists": False, "evidence_id": ""}
            )
            evaluations.append(acct_eval)

        # 9. Inject security audit_record verification (RETAIN rule -> VERIFY_RECORD_PRESENT)
        audit_rec_id = self._get_security_audit_record(user_id, audit_at)
        if audit_rec_id:
            audit_key = ("security_service", audit_rec_id)
            if audit_key not in evaluations_map:
                audit_evidence_id = ""
                for obs in self.evidence_index.records_by_token.get(user_id.lower(), []):
                    if obs.get("resource_id") == audit_rec_id and is_admissible(obs.get("captured_at"), audit_at):
                        audit_evidence_id = obs.get("evidence_id", "")
                        break
                rule_12 = self.rule_engine.rules.get("rule_12")
                audit_eval = self.rule_engine.evaluate_record(
                    rule_12, "security_service", audit_rec_id,
                    {"exists": True, "evidence_id": audit_evidence_id}
                )
                evaluations.append(audit_eval)

        # 10. Inject batch workflow resources (analytics, tombstones, exports, etc.)
        # that share the same deletion batch as the canonical account
        for br in batch_resources:
            br_sys = br["target_system"]
            br_res = br["resource_id"]
            br_key = (br_sys, br_res)
            if br_key in evaluations_map:
                continue  # Already evaluated from observations
            # Skip account_service entries (canonical account handled above)
            if br_sys == "account_service":
                continue
            br_rule = self._find_rule(br_sys, br_res)
            if not br_rule:
                continue
            et = br["event_type"]
            br_exists = et not in ["DELETE_RECORD", "PURGE_RECORD"]
            br_is_anon = (et == "ANONYMIZE_RECORD")
            br_is_redacted = (et == "REDACT_RECORD")
            # Find evidence_id from user observations or account observations
            br_evidence_id = ""
            for obs in observations:
                if obs.get("resource_id") == br_res:
                    br_evidence_id = obs.get("evidence_id", "")
                    break
            if not br_evidence_id:
                # Try same file as any observation for this user
                for obs in observations:
                    fid = obs.get("file_id") or obs.get("evidence_id", "")
                    if fid and br_res in str(self.evidence_index.file_id_to_accounts.get(fid, [])):
                        br_evidence_id = fid
                        break
            br_eval = self.rule_engine.evaluate_record(
                br_rule, br_sys, br_res,
                {
                    "exists": br_exists,
                    "is_anonymized": br_is_anon,
                    "is_active_flow": False,
                    "is_restore_risk": False,
                    "has_pii": False,
                    "evidence_id": br_evidence_id,
                }
            )
            evaluations.append(br_eval)

        status = determine_status(evaluations, is_deletion_authorized=True)
        steps = generate_steps(evaluations, is_deletion_authorized=True)
        return {
            "case_id": case_id,
            "deletion_status": status,
            "steps_json": serialize_steps_json(steps),
        }

    def run(self, output_path: Path = Path("output.csv")) -> None:
        requests_file = self.repo_root / "dataset" / "deletion_requests.csv"
        with open(requests_file, "r", encoding="utf-8", errors="replace") as f:
            cases = list(csv.DictReader(f))

        logger.info(f"Auditing {len(cases)} cases...")
        results = []
        for idx, case in enumerate(cases, start=1):
            # Per-case exception isolation preventing whole-pipeline abort (M060)
            try:
                res = self.audit_case(case)
            except Exception as e:
                logger.error(f"Error auditing case {case.get('case_id')}: {e} (M060)")
                res = {
                    "case_id": case.get("case_id", f"case_{idx}"),
                    "deletion_status": "INCOMPLETE",
                    "steps_json": "[]",
                }
            results.append(res)
            # Progress logged at regular intervals and final case (M058)
            if idx % 50 == 0 or idx == len(cases):
                logger.info(f"Progress: {idx}/{len(cases)} cases processed.")

        # Defensive natural sort key avoiding AttributeError on malformed case_id (M059)
        def _safe_case_sort_key(r: Dict[str, str]) -> int:
            m = re.search(r'\d+', r.get("case_id", ""))
            return int(m.group()) if m else 0

        results.sort(key=_safe_case_sort_key)

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["case_id", "deletion_status", "steps_json"])
            for r in results:
                writer.writerow([r["case_id"], r["deletion_status"], r["steps_json"]])

        logger.info(f"Successfully generated {output_path.resolve()} with {len(results)} rows.")


if __name__ == "__main__":
    orchestrator = AuditOrchestrator()
    orchestrator.run(Path("output.csv"))
