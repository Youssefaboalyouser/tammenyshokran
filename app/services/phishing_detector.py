"""
phishing_detector.py
--------------------
Rule-Based Phishing Detection Engine — importable service module.
"""

import re
import socket
import ipaddress
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from html.parser import HTMLParser

# ── Feature flag ────────────────────────────────────────────────────────────
enable_network_check = False  # Set True to enable reverse DNS / ASN lookups

# ── Constants ────────────────────────────────────────────────────────────────

TRUSTED_DOMAINS = [
    "paypal.com", "google.com", "microsoft.com", "apple.com", "amazon.com",
    "facebook.com", "twitter.com", "instagram.com", "linkedin.com", "netflix.com",
    "bankofamerica.com", "chase.com", "wellsfargo.com", "citibank.com",
    "ebay.com", "dropbox.com", "yahoo.com", "outlook.com", "hotmail.com",
    "dhl.com", "fedex.com", "ups.com", "usps.com", "irs.gov",
]

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
    "icloud.com", "protonmail.com", "mail.com", "yandex.com", "zoho.com",
    "live.com", "msn.com", "gmx.com", "inbox.com",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "short.io", "cutt.ly", "rb.gy",
    "shorturl.at", "tiny.cc", "bl.ink",
}

HIGH_RISK_EXTENSIONS = {
    ".exe", ".js", ".vbs", ".scr", ".bat", ".cmd", ".docm", ".xlsm",
    ".msi", ".ps1", ".hta", ".jar", ".pif", ".com", ".reg",
}

MIME_EXTENSION_MAP = {
    "application/pdf": ".pdf",
    "application/msword": ".doc",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.ms-excel": ".xls",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/zip": ".zip",
    "application/x-rar-compressed": ".rar",
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "text/plain": ".txt",
    "application/x-msdownload": ".exe",
}

CHAR_SUBSTITUTIONS = {
    "0": "o", "1": "l", "3": "e", "4": "a",
    "5": "s", "6": "g", "7": "t", "@": "a",
    "vv": "w", "rn": "m",
}

SUSPICIOUS_ASN_KEYWORDS = [
    "digitalocean", "linode", "vultr", "ovh", "hetzner",
    "choopa", "psychz", "serverius", "hostwinds", "contabo",
    "frantech", "buyvm", "sharktech", "m247",
]


# ── Utilities ────────────────────────────────────────────────────────────────

def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            curr_row.append(min(
                prev_row[j + 1] + 1,
                curr_row[j] + 1,
                prev_row[j] + (c1 != c2),
            ))
        prev_row = curr_row
    return prev_row[-1]


def normalize_domain(domain: str) -> str:
    normalized = domain.lower()
    for fake, real in CHAR_SUBSTITUTIONS.items():
        normalized = normalized.replace(fake, real)
    return normalized


def extract_domain(url_or_email: str) -> str:
    if not url_or_email:
        return ""
    if url_or_email.startswith("http"):
        return urlparse(url_or_email).netloc.lower().lstrip("www.")
    if "@" in url_or_email:
        return url_or_email.split("@")[-1].lower()
    return url_or_email.lower().lstrip("www.")


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def reverse_dns_lookup(ip: str):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def get_asn_info(ip: str):
    try:
        import subprocess
        result = subprocess.run(
            ["whois", ip], capture_output=True, text=True, timeout=5
        )
        output = result.stdout.lower()
        for keyword in SUSPICIOUS_ASN_KEYWORDS:
            if keyword in output:
                return keyword
        return None
    except Exception:
        return None


# ── HTML parser ──────────────────────────────────────────────────────────────

class PhishingHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.anchor_pairs: list = []
        self._current_href = None
        self._current_text: list = []
        self.raw_styles: list = []
        self.has_base64_images = False
        self._style_count = 0

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        style = attrs_dict.get("style", "")
        if style:
            self.raw_styles.append(style)
            self._style_count += 1
        if tag == "a":
            self._current_href = attrs_dict.get("href", "")
            self._current_text = []
        if tag == "img":
            src = attrs_dict.get("src", "")
            if src.startswith("data:image"):
                self.has_base64_images = True

    def handle_endtag(self, tag):
        if tag == "a" and self._current_href is not None:
            self.anchor_pairs.append(
                ("".join(self._current_text).strip(), self._current_href)
            )
            self._current_href = None
            self._current_text = []

    def handle_data(self, data):
        if self._current_href is not None:
            self._current_text.append(data)

    @property
    def inline_style_count(self):
        return self._style_count


# ── Detection modules ────────────────────────────────────────────────────────

def auth_checks(email: dict) -> list[str]:
    flags = []
    headers = email.get("headers", {})
    spf = (headers.get("spf") or "").lower()
    dkim = (headers.get("dkim") or "").lower()
    dmarc = (headers.get("dmarc") or "").lower()

    if spf == "fail":
        flags.append("SPF failed")
    elif spf == "none":
        flags.append("SPF missing")
    if dkim == "fail":
        flags.append("DKIM failed")
    if dmarc == "fail":
        flags.append("DMARC failed")
    if dkim == "pass" and dmarc == "fail":
        flags.append("Authentication misalignment (DKIM pass, DMARC fail)")
    return flags


def sender_checks(email: dict) -> list[str]:
    flags = []
    sender = email.get("sender", {})
    sender_email = sender.get("email", "") or ""
    sender_domain = sender.get("domain", "") or extract_domain(sender_email)
    reply_to = sender.get("reply_to", "") or ""
    links = email.get("links") or []
    sender_name = sender.get("name", "") or ""

    if reply_to:
        reply_domain = extract_domain(reply_to)
        if reply_domain and reply_domain != sender_domain:
            flags.append("Reply-To domain mismatch")

    link_domains = {extract_domain(u) for u in links if u}
    if link_domains and sender_domain and sender_domain not in link_domains:
        flags.append("Sender domain does not match link domains")

    normalized_sender = normalize_domain(sender_domain)
    for trusted in TRUSTED_DOMAINS:
        trusted_base = trusted.split(".")[0]
        sender_base = normalized_sender.split(".")[0]
        dist = levenshtein_distance(sender_base, trusted_base)
        if dist == 1 and len(sender_base) > 4 and sender_domain != trusted:
            flags.append(f"Possible typosquatting domain detected ({sender_domain})")
            break

    if sender_domain in FREE_EMAIL_PROVIDERS:
        org_keywords = ["support", "noreply", "service", "info", "admin",
                        "helpdesk", "security", "billing", "account", "team"]
        name_lower = sender_name.lower()
        local_part = sender_email.split("@")[0].lower() if "@" in sender_email else ""
        if any(kw in name_lower or kw in local_part for kw in org_keywords):
            flags.append("Free email used for organizational communication")

    return flags


def link_checks(email: dict, vt_data: dict | None = None) -> list[str]:
    flags = []
    links = email.get("links") or []
    html_body = (email.get("body") or {}).get("html", "") or ""

    vt_links: dict = {}
    if vt_data:
        for entry in (vt_data.get("virustotal") or {}).get("links", []):
            vt_links[entry.get("url")] = entry

    parser = PhishingHTMLParser()
    if html_body:
        parser.feed(html_body)

    seen_flags: set = set()

    def _add(f):
        if f not in seen_flags:
            flags.append(f)
            seen_flags.add(f)

    for url in links:
        parsed = urlparse(url)
        host = parsed.netloc
        query_params = parse_qs(parsed.query)

        if url in vt_links:
            vt_entry = vt_links[url]
            if vt_entry.get("verdict") != "clean":
                _add("Malicious link detected by VirusTotal")
            total = vt_entry.get("malicious_votes", 0) + vt_entry.get("clean_votes", 0)
            if total == 0:
                _add("Unverified link (no reputation data)")
        else:
            _add("Unverified link (no reputation data)")

        clean_host = host.split(":")[0]
        if is_ip_address(clean_host):
            _add("Suspicious URL (IP address used)")
        if len(url) > 100:
            _add("Suspicious long URL")
        if len(query_params) > 5:
            _add("Suspicious URL parameters")
        bare_host = clean_host.lstrip("www.")
        if bare_host in URL_SHORTENERS:
            _add("URL shortener used")

    for visible_text, href in parser.anchor_pairs:
        if not href or not visible_text or not href.startswith("http"):
            continue
        href_domain = extract_domain(href)
        text_url_match = re.search(r"https?://([^\s/]+)", visible_text)
        if text_url_match:
            text_domain = text_url_match.group(1).lstrip("www.")
            if text_domain and text_domain != href_domain:
                _add("Anchor text mismatch detected")

    return flags


def attachment_checks(email: dict, vt_data: dict | None = None) -> list[str]:
    flags = []
    attachments = email.get("attachments") or []

    vt_attachments: dict = {}
    if vt_data:
        for entry in (vt_data.get("virustotal") or {}).get("attachments", []):
            vt_attachments[entry.get("hash_sha256")] = entry

    for att in attachments:
        filename = att.get("filename", "")
        mime_type = att.get("type", "")
        sha256 = att.get("hash_sha256", "")
        ext = Path(filename).suffix.lower() if filename else ""

        if ext in HIGH_RISK_EXTENSIONS:
            flags.append(f"High-risk attachment type ({ext})")

        expected_ext = MIME_EXTENSION_MAP.get(mime_type)
        if expected_ext and ext and ext != expected_ext:
            flags.append(
                f"Attachment type mismatch ({filename}: ext {ext}, MIME {mime_type})"
            )

        if sha256 and sha256 in vt_attachments:
            vt_entry = vt_attachments[sha256]
            if vt_entry.get("malicious_votes", 0) > 0:
                flags.append(f"Malicious attachment detected by VirusTotal ({filename})")
        elif sha256:
            flags.append(f"Attachment not found in VirusTotal ({filename})")

    return flags


def header_checks(email: dict) -> list[str]:
    flags = []
    headers = email.get("headers", {})
    ip = (headers.get("received_from_ip") or "").strip()

    if not ip:
        return flags

    hostname = None
    if enable_network_check:
        hostname = reverse_dns_lookup(ip)
    if not hostname:
        flags.append("Missing reverse DNS")

    asn_info = None
    if enable_network_check:
        asn_info = get_asn_info(ip)
    if asn_info:
        flags.append(f"Suspicious sending infrastructure (ASN: {asn_info})")

    sender_domain = (email.get("sender") or {}).get("domain", "") or ""
    if hostname and sender_domain:
        sender_tld = sender_domain.split(".")[-1].lower()
        hostname_tld = hostname.split(".")[-1].lower()
        if (
            len(sender_tld) == 2 and len(hostname_tld) == 2
            and sender_tld != hostname_tld
            and sender_tld not in ("com", "net", "org")
            and hostname_tld not in ("com", "net", "org")
        ):
            flags.append("Geographical mismatch between sender and infrastructure")

    return flags


def html_checks(email: dict) -> list[str]:
    flags = []
    html_body = (email.get("body") or {}).get("html", "") or ""

    if not html_body:
        return flags

    hidden_patterns = [r"display\s*:\s*none", r"visibility\s*:\s*hidden"]
    for pattern in hidden_patterns:
        if re.search(pattern, html_body, re.IGNORECASE):
            flags.append("Hidden text detected in HTML")
            break

    if re.search(r"font-size\s*:\s*0", html_body, re.IGNORECASE):
        flags.append("Zero-size text detected")
    if re.search(r'src\s*=\s*["\']data:image/', html_body, re.IGNORECASE):
        flags.append("Embedded base64 image detected")

    parser = PhishingHTMLParser()
    parser.feed(html_body)
    if parser.inline_style_count > 20:
        flags.append("Excessive HTML styling (possible obfuscation)")

    return flags


# ── Main engine ──────────────────────────────────────────────────────────────

def analyze_email(parsed_email: dict, vt_data: dict | None = None) -> dict:
    """
    Run all rule-based checks and return structured result.
    This is the primary entry point used by the emails router.
    """
    all_flags: list[str] = []
    all_flags.extend(auth_checks(parsed_email))
    all_flags.extend(sender_checks(parsed_email))
    all_flags.extend(link_checks(parsed_email, vt_data))
    all_flags.extend(attachment_checks(parsed_email, vt_data))
    all_flags.extend(header_checks(parsed_email))
    all_flags.extend(html_checks(parsed_email))

    # Deduplicate
    seen: set = set()
    unique_flags = [f for f in all_flags if not (f in seen or seen.add(f))]

    return {
        "email_id": parsed_email.get("email_id", ""),
        "rule_based": {"flags": unique_flags},
    }


def compute_risk_score(flags: list[str], nlp_is_spam: bool, nlp_score: float) -> float:
    """
    Compute a 0–100 risk score from phishing flags + NLP result.

    This score is the primary decision input for the final verdict.
    """
    FLAG_WEIGHTS = {
        # === Tier 1: Strong Indicators ===
        "Malicious link detected by VirusTotal": 40,
        "Malicious attachment detected by VirusTotal": 40,
        "Possible typosquatting domain detected": 25,

        # === Tier 2: Medium Indicators ===
        "DMARC failed": 12,
        "SPF failed": 10,
        "DKIM failed": 10,
        "Reply-To domain mismatch": 10,
        "Sender domain does not match link domain": 9,
        "High-risk attachment type": 10,
        "Suspicious sending infrastructure": 10,
        "Missing reverse DNS": 6,
        "Suspicious URL (IP address used)": 8,
        "Anchor text mismatch detected": 8,
        "Hidden text detected in HTML": 6,

        # === Tier 3: Weak Indicators ===
        "SPF missing": 3,
        "Free email used for organizational communication": 3,
        "URL shortener used": 4,
        "Suspicious long URL": 4,
        "Unverified link (no reputation data)": 3,
        "Embedded base64 image detected": 3,
    }

    base_score = 0.0
    for flag in flags:
        matched = False
        for key, weight in FLAG_WEIGHTS.items():
            if flag.startswith(key):
                base_score += weight
                matched = True
                break
        if not matched:
            base_score += 3  # generic unknown flag

    # Combination boosts: increase score when specific combinations appear
    # Use substring checks to account for flags that include extra context
    flag_text = "\n".join(flags)
    def has(sub: str) -> bool:
        return sub in flag_text

    # Hidden text + Anchor mismatch => boost
    if has("Hidden text detected in HTML") and has("Anchor text mismatch detected"):
        base_score += 10

    # Authentication collapse: SPF + DKIM + DMARC failed
    if has("SPF failed") and has("DKIM failed") and has("DMARC failed"):
        base_score += 15

    # URL shortener used together with anchor mismatch
    if has("URL shortener used") and has("Anchor text mismatch detected"):
        base_score += 8

    # Free email used for org communication + Reply-To mismatch
    if has("Free email used for organizational communication") and has("Reply-To domain mismatch"):
        base_score += 8
    if has("Sender domain does not match link domain") and has("Anchor text mismatch detected"):
        base_score += 10
    if has("Unverified link (no reputation data)") and has("Suspicious long URL"):
        base_score += 6
    if has("Missing reverse DNS") and has("Suspicious sending infrastructure"):
        base_score += 8
    if has("Sender domain does not match link domain") and has("Unverified link (no reputation data)"):
        base_score += 7
    # NLP contribution (max 15 points), rule detection carries the remaining weight.
    if nlp_is_spam:
        base_score += nlp_score * 15

    return min(round(base_score, 1), 100.0)


def verdict_from_score(score: float) -> str:
    """
    Convert a computed risk score into a final verdict label.
    """
    # New thresholds requested:
    # 0 – 29   -> SAFE
    # 30 – 59  -> SUSPICIOUS
    # 60+     -> HIGH RISK
    if score >= 60:
        return "High Risk"
    elif score >= 30:
        return "SUSPICIOUS"
    return "SAFE"
