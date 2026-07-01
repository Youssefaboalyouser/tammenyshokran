"""
emailParser.py
--------------
Parses .eml bytes into a rich, structured dictionary.
Now a pure service module (no file I/O at the call site).
"""

import email # parsers raw RFC 822/MIME email message into python objects
import email.utils
import email.header
import hashlib # cryptographic hashes for attachments analysis
import re # regex for link extraction and authentication result parsing also to extract ip
import uuid # generate unique email_id for each parsed email
from datetime import datetime, timezone # timezone handling for email timestamps
from email import policy
from pathlib import Path # file path manipulaiton
from typing import Optional

import cv2 # computer vision library for image processing and OCR
import numpy as np # numerical computing library for image processing

try:
    import pytesseract # tesseract OCR library for extracting text from images
    TESSERACT_AVAILABLE = True 
except ImportError:
    TESSERACT_AVAILABLE = False

# ── Constants ────────────────────────────────────────────────────────────────
IMAGE_MIME_TYPES = {
    "image/png", "image/jpeg", "image/jpg", "image/gif",
    "image/bmp", "image/tiff",
}


# ── OCR helpers ──────────────────────────────────────────────────────────────
# this function used for transforms raw file attachment image bytes into high contrast binary image (black and white) suitable for OCR processing, returning the processed image as a numpy array
def preprocess_for_ocr(image_bytes: bytes) -> np.ndarray:
    nparr = np.frombuffer(image_bytes, np.uint8) # convert bytes to numpy array of 8bit unsigned integers
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR) # decode the image bytes into a color image (BGR format) using OpenCV
    if img is None:
        raise ValueError("Could not decode image bytes")
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY) # convert the color image to grayscale
    gray = cv2.resize(gray, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC) # upscale the image by 2x using cubic interpolation to improve OCR accuracy
    thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1] # apply Otsu's thresholding to convert the grayscale image to a binary image (black and white) for better OCR results
    return thresh

# this function used for translates visual grahhic content of image attachments into machine readable text using tesseract OCR, returning the extracted text as a string or empty string if tesseract is not available
def ocr_image_bytes(image_bytes: bytes, lang: str = "ara+eng") -> str:
    if not TESSERACT_AVAILABLE:
        return ""
    preprocessed = preprocess_for_ocr(image_bytes)
    config = r"--oem 3 --psm 3" # configure the Neural Network LSTM engine mode + page segmentation mode to automaticlly segment layout blocks
    text = pytesseract.image_to_string(preprocessed, lang=lang, config=config)
    return text.strip()


# ── Decoding helpers ─────────────────────────────────────────────────────────
# this function used for converts raw files/text bytes into standard python strings safely witout letting bad characters crash the program
def _safe_decode(payload: bytes, charset: str = "utf-8") -> str:
    for enc in (charset or "utf-8", "utf-8", "latin-1"): # loop with different lang schema
        try:
            return payload.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return payload.decode("utf-8", errors="replace")

# this function used for convert MIME encoded non ascii email headers into plain (human readable text)
def _decode_header_value(raw: Optional[str]) -> Optional[str]:
    if raw is None: # return None if the header is empty or not present
        return None
    parts = email.header.decode_header(raw) # break the haeder into a list of tuples (fragment, charset) for each part of the header
    decoded = []
    for fragment, charset in parts:
        if isinstance(fragment, bytes):
            decoded.append(_safe_decode(fragment, charset))
        else: # if its alerady a regular string, just append it to the list
            decoded.append(fragment)
    return "".join(decoded).strip() or None

# this function used for seperates a raw email address header into individual identity components (name, email, domain) and returns them as a dictionary
def _parse_address(raw: Optional[str]) -> dict:
    if not raw:
        return {"name": None, "email": None, "domain": None}
    name, addr = email.utils.parseaddr(raw) # extract a tuple clean seperated (name, email) from the raw header
    name = name.strip() or None
    addr = addr.strip().lower() or None
    domain = addr.split("@", 1)[1] if addr and "@" in addr else None
    return {"name": name, "email": addr, "domain": domain}

# this function used for parses unpredictable text strings from email dates and return ISO 8601 uniform UTC timespamp strings (YYYY-MM-DDTHH:MM:SSZ) or None if the input is invalid or empty 
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

# this function used for determine if the primary text profile of the email body is arabic or english
def _detect_language(text: str) -> Optional[str]:
    if not text:
        return None
    arabic_chars = sum(1 for c in text if "\u0600" <= c <= "\u06ff")
    return "ar" if arabic_chars / max(len(text), 1) > 0.2 else "en" # if more than 20% of the text is arabic characters, classify as arabic, otherwise english

# this function used for look into email routing envelopes to determine wheter defensive checks like SPF, DKIM, and DMARC have passed or failed for the email, returning the result as a lowercase string or None if not found
def _extract_auth_result(msg, keyword: str) -> Optional[str]:
    auth_results = msg.get_all("Authentication-Results") or []
    pattern = re.compile(rf"{keyword}=([a-zA-Z]+)", re.IGNORECASE)
    for header in auth_results:
        m = pattern.search(header)
        if m: # if the first hit matches the regex pattern, return the result in lowercase
            return m.group(1).lower()
    return None

# this function used for locates the original , boundary ip address that initially deliverd the message to mail infustructurre, by parsing the "Received" headers in the email and returning the first valid IPv4 address found, or None if no valid IP is found
def _first_received_ip(msg) -> Optional[str]:
    received = msg.get_all("Received") or []
    ip_pattern = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")
    for header in received:
        m = ip_pattern.search(header)
        if m:
            return m.group(1)
    return None


# ── Main parser ──────────────────────────────────────────────────────────────
# this function used for parses raw .eml bytes into a structured dictionary containing all relevant email information, including sender, recipient, subject, body, links, attachments, and headers(central engine for the email parsing service)
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
    # check if the email is multipart (contains multiple parts like text, html, attachments) or one type of content, and process accordingly
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
