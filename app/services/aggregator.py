"""
aggregator.py
-------------
Orchestrates VirusTotal scanning for links and attachments
extracted from a parsed email dictionary.
"""

import time
from typing import Dict, Any, List, Set
from .virustotal import scan_url, check_file_hash
from ..utilities.config import REQUEST_DELAY


def _extract_links(parsed: Dict[str, Any]) -> List[str]:
    links = parsed.get("links") or []
    if not isinstance(links, list):
        return []
    seen: Set[str] = set()
    return [u for u in links if u and not (u in seen or seen.add(u))]


def _extract_attachments(parsed: Dict[str, Any]) -> List[Dict[str, str]]:
    attachments = parsed.get("attachments") or []
    if not isinstance(attachments, list):
        return []
    cleaned = []
    seen_hashes: Set[str] = set()
    for att in attachments:
        sha256 = att.get("hash_sha256")
        if not sha256 or sha256 in seen_hashes:
            continue
        seen_hashes.add(sha256)
        cleaned.append({
            "filename": att.get("filename", "unknown"),
            "hash_sha256": sha256,
        })
    return cleaned


def run_virustotal_analysis(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """
    Given a parsed email dict (from emailParser), run VirusTotal
    on all unique links and attachment hashes.

    Returns a virustotal result dict ready to be stored in the DB.
    """
    email_id = parsed.get("email_id", "unknown")
    links = _extract_links(parsed)
    attachments = _extract_attachments(parsed)

    vt_links_results: List[Dict[str, Any]] = []
    vt_attachments_results: List[Dict[str, Any]] = []
    error = None

    try:
        for idx, url in enumerate(links):
            result = scan_url(url)
            vt_links_results.append(result)
            if idx < len(links) - 1 or attachments:
                time.sleep(REQUEST_DELAY)

        for idx, att in enumerate(attachments):
            result = check_file_hash(att["hash_sha256"], att["filename"])
            vt_attachments_results.append(result)
            if idx < len(attachments) - 1:
                time.sleep(REQUEST_DELAY)

    except Exception as e:
        error = str(e)

    return {
        "email_id": email_id,
        "virustotal": {
            "links": vt_links_results,
            "attachments": vt_attachments_results,
            "error": error,
        },
    }
