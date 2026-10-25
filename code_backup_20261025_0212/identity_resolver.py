"""
identity_resolver.py - Forensic Identity Resolution and Temporal Alias Mapping
HackerRank Orchestrate: Ghost Data Still Exists
"""

import csv
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union

from temporal_filter import is_admissible, parse_iso_timestamp

logger = logging.getLogger("identity_resolver")


@dataclass
class UserIdentityRecord:
    user_id: str
    name: str
    primary_email: str
    primary_phone: str
    email_hash: str
    updated_at: str
    all_emails: Set[str] = field(default_factory=set)
    all_phones: Set[str] = field(default_factory=set)
    all_names: Set[str] = field(default_factory=set)
    all_hashes: Set[str] = field(default_factory=set)

    def get_tokens(self) -> Set[str]:
        tokens = {self.user_id}
        if self.primary_email:
            tokens.add(self.primary_email.lower())
        if self.primary_phone:
            tokens.add(self.primary_phone)
        if self.name:
            tokens.add(self.name)
        if self.email_hash:
            tokens.add(self.email_hash.lower())
        tokens.update(e.lower() for e in self.all_emails if e)
        tokens.update(p for p in self.all_phones if p)
        tokens.update(n for n in self.all_names if n)
        tokens.update(h.lower() for h in self.all_hashes if h)
        return tokens


class IdentityResolver:
    def __init__(self, repo_root: Union[str, Path] = "."):
        self.repo_root = Path(repo_root)
        self.identities_path = self.repo_root / "dataset" / "user_identities.csv"
        self.audit_log_path = self.repo_root / "dataset" / "user_audit_log.csv"

        # Base snapshot records
        self.users_by_id: Dict[str, UserIdentityRecord] = {}
        self.email_to_userid: Dict[str, str] = {}
        self.phone_to_userid: Dict[str, str] = {}
        self.hash_to_userid: Dict[str, str] = {}

        # Raw audit log entries for case-specific temporal filtering:
        # list of dicts: {audit_id, user_id, event_time, field_name, old_value, new_value}
        self.raw_audit_entries: List[Dict[str, str]] = []

        self._load_identities()
        self._load_raw_audit_log()

    def _load_identities(self) -> None:
        if not self.identities_path.exists():
            logger.warning(f"Identities file not found: {self.identities_path}")
            return

        # Use utf-8 with fallback warning on replacement characters (M066)
        with open(self.identities_path, "r", encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f):
                u_id = row.get("user_id", "").strip()
                if not u_id:
                    continue
                if "\ufffd" in str(row):
                    logger.warning(f"Decoding replacement detected in identity row for user {u_id} (M066)")
                name = row.get("name", "").strip()
                email = row.get("email", "").strip().lower()
                phone = row.get("phone", "").strip()
                e_hash = row.get("email_hash", "").strip().lower()
                updated_at = row.get("updated_at", "").strip()

                rec = UserIdentityRecord(
                    user_id=u_id,
                    name=name,
                    primary_email=email,
                    primary_phone=phone,
                    email_hash=e_hash,
                    updated_at=updated_at,
                    all_emails={email} if email else set(),
                    all_phones={phone} if phone else set(),
                    all_names={name} if name else set(),
                    all_hashes={e_hash} if e_hash else set(),
                )
                self.users_by_id[u_id] = rec
                if email:
                    self.email_to_userid[email] = u_id
                if phone:
                    self.phone_to_userid[phone] = u_id
                if e_hash:
                    self.hash_to_userid[e_hash] = u_id

    def _load_raw_audit_log(self) -> None:
        if not self.audit_log_path.exists():
            return

        with open(self.audit_log_path, "r", encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f):
                self.raw_audit_entries.append(row)

    def resolve_user_id(self, identifier: str, audit_at: Optional[str] = None) -> Optional[str]:
        """
        Resolves an email, phone, user_id, or hash to the stable user_id,
        respecting historical records up to audit_at.
        """
        if not identifier:
            return None
        clean = identifier.strip().lower()

        # Direct current snapshot check
        if clean in self.email_to_userid:
            return self.email_to_userid[clean]
        if identifier.strip() in self.users_by_id:
            return identifier.strip()
        if identifier.strip() in self.phone_to_userid:
            return self.phone_to_userid[identifier.strip()]
        if clean in self.hash_to_userid:
            return self.hash_to_userid[clean]

        # Check audit log entries up to audit_at
        for entry in self.raw_audit_entries:
            if audit_at and not is_admissible(entry.get("event_time"), audit_at):
                continue
            u_id = entry.get("user_id", "").strip()
            old_val = entry.get("old_value", "").strip()
            new_val = entry.get("new_value", "").strip()
            for v in (old_val, new_val):
                # Consistent lowercased and exact comparison (M062)
                if v and (v.strip().lower() == clean or v.strip() == identifier.strip()):
                    return u_id

        return None

    def get_all_identifiers(self, identifier: str, audit_at: Optional[str] = None) -> List[str]:
        """
        Returns all known identifier tokens (current + historical up to audit_at)
        associated with the user. If identifier cannot be mapped, returns empty list.
        """
        user_id = self.resolve_user_id(identifier, audit_at)
        if not user_id:
            return []

        tokens: Set[str] = {user_id}
        base_record = self.users_by_id.get(user_id)
        if base_record:
            tokens.update(base_record.get_tokens())

        # Enrich with historical audit changes up to audit_at
        for entry in self.raw_audit_entries:
            if entry.get("user_id", "").strip() != user_id:
                continue
            if audit_at and not is_admissible(entry.get("event_time"), audit_at):
                continue
            for val in (entry.get("old_value", "").strip(), entry.get("new_value", "").strip()):
                if val:
                    tokens.add(val.lower() if "@" in val or len(val) == 64 else val)

        return sorted(list(tokens))
