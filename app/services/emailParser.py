"""
emailParser.py
--------------
Parses .eml bytes into a rich, structured dictionary.
Now a pure service module (no file I/O at the call site).
"""

import email
import email.utils
import email.header
import hashlib
import re
import uuid
from datetime import datetime, timezone
from email import policy
from pathlib import Path
from typing import Optional

import cv2
import numpy as np

try:
    import pytesseract
    TESSERACT_AVAILABLE = True
except ImportError:
    TESSERACT_AVAILABLE = False

# ── Constants ────────────────────────────────────────────────────────────────
IMAGE_MIME_TYPES = {
    "image/png", "image/jpeg", "image/jpg", "image/gif",
    "image/bmp", "image/tiff",
}


# ── OCR helpers ──────────────────────────────────────────────────────────────

def preprocess_for_ocr(image_bytes: bytes) -> np.ndarray:
    nparr = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("Could not decode image bytes")
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    gray = cv2.resize(gray, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
    thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]
    return thresh


def ocr_image_bytes(image_bytes: bytes, lang: str = "ara+eng") -> str:
    if not TESSERACT_AVAILABLE:
        return ""
    preprocessed = preprocess_for_ocr(image_bytes)
    config = r"--oem 3 --psm 3"
    text = pytesseract.image_to_string(preprocessed, lang=lang, config=config)
    return text.strip()


# ── Decoding helpers ─────────────────────────────────────────────────────────

def _safe_decode(payload: bytes, charset: str = "utf-8") -> str:
    for enc in (charset or "utf-8", "utf-8", "latin-1"):
        try:
            return payload.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return payload.decode("utf-8", errors="replace")


def _decode_header_value(raw: Optional[str]) -> Optional[str]:
    if raw is None:
        return None
    parts = email.header.decode_header(raw)
    decoded = []
    for fragment, charset in parts:
        if isinstance(fragment, bytes):
            decoded.append(_safe_decode(fragment, charset))
        else:
            decoded.append(fragment)
    return "".join(decoded).strip() or None


def _parse_address(raw: Optional[str]) -> dict:
    if not raw:
        return {"name": None, "email": None, "domain": None}
    name, addr = email.utils.parseaddr(raw)
    name = name.strip() or None
    addr = addr.strip().lower() or None
    domain = addr.split("@", 1)[1] if addr and "@" in addr else None
    return {"name": name, "email": addr, "domain": domain}


def _normalise_timestamp(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    try:
        parsed = email.utils.parsedate_to_datetime(raw)
        utc = parsed.astimezone(timezone.utc)
        return utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return raw


def _extract_links(text: str) -> list[str]:
    return re.findall(r'https?://[^\s\'"<>]+', text)


def _hash_bytes(data: bytes) -> dict:
    return {
        "hash_md5": hashlib.md5(data).hexdigest(),
        "hash_sha256": hashlib.sha256(data).hexdigest(),
    }


def _detect_language(text: str) -> Optional[str]:
    if not text:
        return None
    arabic_chars = sum(1 for c in text if "\u0600" <= c <= "\u06ff")
    return "ar" if arabic_chars / max(len(text), 1) > 0.2 else "en"


def _extract_auth_result(msg, keyword: str) -> Optional[str]:
    auth_results = msg.get_all("Authentication-Results") or []
    pattern = re.compile(rf"{keyword}=([a-zA-Z]+)", re.IGNORECASE)
    for header in auth_results:
        m = pattern.search(header)
        if m:
            return m.group(1).lower()
    return None


def _first_received_ip(msg) -> Optional[str]:
    received = msg.get_all("Received") or []
    ip_pattern = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")
    for header in received:
        m = ip_pattern.search(header)
        if m:
            return m.group(1)
    return None


# ── Main parser ──────────────────────────────────────────────────────────────

def parse_eml_bytes(raw_bytes: bytes) -> dict:
    """
    Parse raw .eml bytes and return a structured dictionary.
    This is the primary entry point used by the FastAPI emails router.
    """
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)

    sender_raw = _decode_header_value(msg.get("From"))
    reply_to_raw = _decode_header_value(msg.get("Reply-To"))
    sender = _parse_address(sender_raw)
    reply_parsed = _parse_address(reply_to_raw)
    sender["reply_to"] = reply_parsed.get("email")

    recipient = _decode_header_value(msg.get("To"))

    plain_text = None
    html = None
    attachments = []
    all_links = []
    is_image_email = False

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))
            charset = part.get_content_charset()

            # Attachment
            if "attachment" in content_disposition or part.get_filename():
                filename = _decode_header_value(part.get_filename())
                payload = part.get_payload(decode=True) or b""
                if filename:
                    record = {
                        "filename": filename,
                        "type": content_type,
                        **_hash_bytes(payload),
                    }
                    # Normalise image/jpg → image/jpeg for MIME check
                    effective_mime = (
                        "image/jpeg"
                        if content_type == "image/jpg"
                        else content_type
                    )
                    if effective_mime in IMAGE_MIME_TYPES or Path(filename).suffix.lower() in (
                        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff"
                    ):
                        try:
                            record["ocr_text"] = ocr_image_bytes(payload) or None
                        except Exception as exc:
                            record["ocr_error"] = str(exc)
                    attachments.append(record)
                continue

            # Plain text
            if content_type == "text/plain":
                raw = part.get_payload(decode=True)
                if raw:
                    plain_text = _safe_decode(raw, charset)
                    all_links.extend(_extract_links(plain_text))

            # HTML
            elif content_type == "text/html":
                raw = part.get_payload(decode=True)
                if raw:
                    html = _safe_decode(raw, charset)
                    all_links.extend(_extract_links(html))

            # Detect image-based email (CID references)
            if content_type in ("text/plain", "text/html"):
                if (html and "cid:" in html) or (plain_text and "cid:" in (plain_text or "")):
                    is_image_email = True

            # Inline images
            effective_mime = "image/jpeg" if content_type == "image/jpg" else content_type
            if effective_mime in IMAGE_MIME_TYPES and "inline" in content_disposition:
                payload = part.get_payload(decode=True) or b""
                filename = _decode_header_value(part.get_filename()) or f"inline_{uuid.uuid4().hex[:8]}.png"
                try:
                    ocr_text = ocr_image_bytes(payload)
                    attachments.append({
                        "filename": filename,
                        "type": content_type,
                        "inline": True,
                        "ocr_text": ocr_text or None,
                        **_hash_bytes(payload),
                    })
                except Exception as exc:
                    attachments.append({"filename": filename, "ocr_error": str(exc)})
    else:
        raw = msg.get_payload(decode=True)
        if raw:
            content_type = msg.get_content_type()
            charset = msg.get_content_charset()
            decoded = _safe_decode(raw, charset)
            if content_type == "text/html":
                html = decoded
            else:
                plain_text = decoded
            all_links.extend(_extract_links(decoded))

    # Deduplicate links
    seen: set = set()
    links = [u for u in all_links if not (u in seen or seen.add(u))]

    headers_parsed = {
        "spf": _extract_auth_result(msg, "spf"),
        "dkim": _extract_auth_result(msg, "dkim"),
        "dmarc": _extract_auth_result(msg, "dmarc"),
        "x_mailer": (
            _decode_header_value(msg.get("X-Mailer"))
            or _decode_header_value(msg.get("User-Agent"))
        ),
        "received_from_ip": _first_received_ip(msg),
    }

    return {
        "email_id": str(uuid.uuid4()),
        "timestamp": _normalise_timestamp(msg.get("Date")),
        "sender": sender,
        "recipient": recipient,
        "subject": _decode_header_value(msg.get("Subject")),
        "body": {
            "plain_text": plain_text,
            "html": html,
            "language": _detect_language(plain_text or html or ""),
            "is_image_email": is_image_email,
        },
        "links": links if links else None,
        "attachments": attachments if attachments else None,
        "headers": headers_parsed,
    }


def parse_eml_file(file_path: str | Path) -> dict:
    """Convenience wrapper that reads a file from disk."""
    return parse_eml_bytes(Path(file_path).read_bytes())
