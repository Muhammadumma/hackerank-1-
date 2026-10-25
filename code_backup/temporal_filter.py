"""
temporal_filter.py - Temporal Cutoff and Evidence Admissibility Gate
HackerRank Orchestrate: Ghost Data Still Exists
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger("temporal_filter")


def parse_iso_timestamp(ts: Optional[Union[str, datetime]]) -> Optional[datetime]:
    """
    Safely normalizes varied timestamp formats into UTC timezone-aware datetime.
    Supports ISO 8601 strings with 'Z' or timezone offsets.
    Returns None if missing, malformed, or invalid.
    """
    if ts is None:
        return None
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc)

    if not isinstance(ts, str):
        return None

    clean_str = ts.strip()
    if not clean_str:
        return None

    # Replace Z with +00:00 for ISO-8601 parsing
    normalized = clean_str.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        pass

    fallback_formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
    ]
    for fmt in fallback_formats:
        try:
            dt = datetime.strptime(clean_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            continue

    return None


def is_admissible(
    event_timestamp: Optional[Union[str, datetime]],
    audit_at: Optional[Union[str, datetime]],
) -> bool:
    """
    Strict temporal admissibility test under challenge contract:
    - Evidence is admissible if and only if event_timestamp <= audit_at in UTC.
    - If audit_at is missing or unparseable: Returns False (cannot audit without cutoff).
    - If event_timestamp is missing or unparseable: Returns False (cannot prove timing).
    """
    if audit_at is None or event_timestamp is None:
        return False

    audit_dt = parse_iso_timestamp(audit_at)
    if audit_dt is None:
        return False

    event_dt = parse_iso_timestamp(event_timestamp)
    if event_dt is None:
        return False

    return event_dt <= audit_dt


def filter_evidence_records(
    records: List[Dict[str, Any]],
    timestamp_key: str,
    audit_at: Optional[Union[str, datetime]],
) -> List[Dict[str, Any]]:
    """
    Returns only records whose timestamp_key contains a valid timestamp <= audit_at.
    """
    return [r for r in records if is_admissible(r.get(timestamp_key), audit_at)]
