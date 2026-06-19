"""
virustotal.py
-------------
VirusTotal API integration as a reusable service module.
"""

import requests
from typing import Dict, Any
from ..utilities.config import settings

VIRUSTOTAL_API_KEY = settings.virustotal_api_key
VT_BASE_URL = "https://www.virustotal.com/api/v3"

HEADERS = {
    "x-apikey": VIRUSTOTAL_API_KEY,
    "Accept": "application/json",
}


def _safe_get(data: dict, path: list, default=0):
    try:
        for key in path:
            data = data[key]
        return data
    except (KeyError, TypeError):
        return default


def _compute_verdict(malicious_votes: int) -> str:
    if malicious_votes >= 5:
        return "malicious"
    elif malicious_votes > 0:
        return "suspicious"
    return "clean"


def scan_url(url: str) -> Dict[str, Any]:
    """Submit URL to VirusTotal and return analysis result."""
    result: Dict[str, Any] = {
        "url": url,
        "malicious_votes": 0,
        "clean_votes": 0,
        "verdict": "clean",
    }

    if not VIRUSTOTAL_API_KEY:
        result["error"] = "Missing VirusTotal API key"
        return result

    try:
        submit_resp = requests.post(
            f"{VT_BASE_URL}/urls",
            headers=HEADERS,
            data={"url": url},
            timeout=15,
        )
        if submit_resp.status_code == 429:
            raise Exception("Rate limit exceeded")
        submit_resp.raise_for_status()

        analysis_id = _safe_get(submit_resp.json(), ["data", "id"], None)
        if not analysis_id:
            raise Exception("Missing analysis ID in response")

        analysis_resp = requests.get(
            f"{VT_BASE_URL}/analyses/{analysis_id}",
            headers=HEADERS,
            timeout=15,
        )
        if analysis_resp.status_code == 429:
            raise Exception("Rate limit exceeded")
        analysis_resp.raise_for_status()

        stats = _safe_get(analysis_resp.json(), ["data", "attributes", "stats"], {})
        malicious = stats.get("malicious", 0)
        harmless = stats.get("harmless", 0)

        result.update({
            "malicious_votes": malicious,
            "clean_votes": harmless,
            "verdict": _compute_verdict(malicious),
        })

    except requests.RequestException as e:
        result["error"] = f"Network error: {e}"
    except Exception as e:
        result["error"] = str(e)

    return result


def check_file_hash(sha256: str, filename: str = "unknown") -> Dict[str, Any]:
    """Check file reputation by SHA-256 hash."""
    result: Dict[str, Any] = {
        "filename": filename,
        "hash_sha256": sha256,
        "malicious_votes": 0,
        "clean_votes": 0,
        "verdict": "clean",
    }

    if not sha256:
        result["error"] = "Missing SHA256 hash"
        return result

    if not VIRUSTOTAL_API_KEY:
        result["error"] = "Missing VirusTotal API key"
        return result

    try:
        resp = requests.get(
            f"{VT_BASE_URL}/files/{sha256}",
            headers=HEADERS,
            timeout=15,
        )
        if resp.status_code == 404:
            result["error"] = "Hash not found in VirusTotal"
            return result
        if resp.status_code == 429:
            raise Exception("Rate limit exceeded")
        resp.raise_for_status()

        stats = _safe_get(resp.json(), ["data", "attributes", "last_analysis_stats"], {})
        malicious = stats.get("malicious", 0)
        harmless = stats.get("harmless", 0)

        result.update({
            "malicious_votes": malicious,
            "clean_votes": harmless,
            "verdict": _compute_verdict(malicious),
        })

    except requests.RequestException as e:
        result["error"] = f"Network error: {e}"
    except Exception as e:
        result["error"] = str(e)

    return result
