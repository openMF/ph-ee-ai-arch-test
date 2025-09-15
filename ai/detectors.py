import os, re

ALLOWED_ID_TYPES = {"ALIAS","IBAN","MSISDN","EMAIL","ACCOUNT_ID","BUSINESS","DEVICE","PERSONAL_ID"}
ALLOWED_CURRENCIES = {
    c.strip().upper()
    for c in os.getenv("ALLOWED_CURRENCIES", "CAD,USD,EUR,KES,UGX,TZS,GHS,NGN").split(",")
    if c.strip()
}
SQLI_PATTERNS = [
    r"(?i)\bOR\b\s+1=1\b",
    r"(?i)UNION\s+SELECT",
    r"(?i)DROP\s+TABLE",
    r"--", r";--", r"'--", r"\"--",
]

XSS_PATTERNS = [
    r"(?i)<\s*script\b", r"(?i)onload\s*=", r"(?i)onerror\s*=",
]

def any_regex(text, patterns):
    for p in patterns:
        if re.search(p, text):
            return True
    return False

def extract_total_ms(line: str):
    """ops-app access log line -> total millis after 'total:' """
    m = re.search(r"total:\s*(\d+)", line)
    return int(m.group(1)) if m else None

def find_negative_amount(text: str):
    return re.search(r'"amount"\s*:\s*"-\d+', text) or re.search(r'"amount"\s*:\s*{\s*"amount"\s*:\s*"-\d+', text)

def find_too_many_decimals(text: str):
    return re.search(r'"amount"\s*:\s*"\d+\.\d{3,}"', text)

def find_non_allowed_idtype(text: str):
    """
    Detect invalid partyIdType both when it appears as a JSON field and when it
    only exists inside Jackson's 'Cannot deserialize ... from String "X"' error.
    """
    # 1) Normal JSON body
    m = re.search(r'"partyIdType"\s*:\s*"([^"]+)"', text)
    if m and m.group(1) not in ALLOWED_ID_TYPES:
        return m.group(1)

    # 2) Jackson parse error (Channel/Zeebe logs)
    m = re.search(r'Cannot deserialize[^"]+from String\s*"([^"]+)"', text)
    if m and m.group(1) not in ALLOWED_ID_TYPES:
        return m.group(1)

    return None

def find_invalid_currency(text: str):
    """
    Return a human friendly reason if currency is invalid, else None.
    - Must be 3 uppercase letters (basic ISO 4217 form)
    - If ALLOWED_CURRENCIES is set, must be in that allow-list
    """
    m = re.search(r'"currency"\s*:\s*"([A-Za-z]+)"', text)
    if not m:
        return None
    cur = m.group(1)
    if not re.fullmatch(r"[A-Z]{3}", cur):
        return f"Non‑ISO currency: {cur}"
    if ALLOWED_CURRENCIES and cur not in ALLOWED_CURRENCIES:
        return f"Disallowed currency: {cur}"
    return None

# NEW: when there is no JSON field because Jackson failed before parsing
def find_idtype_enum_error(text: str):
    m = re.search(r'IdentifierType.*?from String\s+"([^"]+)"[^:]*?:\s*not one of the values accepted', text)
    return m.group(1) if m else None

def is_sqli(text: str): return any_regex(text, SQLI_PATTERNS)
def is_xss(text: str):  return any_regex(text, XSS_PATTERNS)

def find_biginteger_error(text: str):
    return "MessagePack cannot serialize BigInteger larger than 2^64-1" in text

# NEW: canonicalize backpressure phrases (we’ll still count in ai_alert_bot)
def find_backpressure_phrase(text: str):
    return ("writer is full" in text.lower()) or ("failed to write client request" in text.lower())

def summarize_payload_issues(body: str):
    issues = []
    if find_negative_amount(body):
        issues.append("Negative amount")
    if find_too_many_decimals(body):
        issues.append("Too many decimals in amount")

    bad = find_non_allowed_idtype(body)
    if bad:
        issues.append(f"Invalid partyIdType: {bad}")

    bad_exc = find_idtype_enum_error(body)
    if bad_exc:
        issues.append(f"Invalid partyIdType (exception): {bad_exc}")

    badcur = find_invalid_currency(body)
    if badcur:
        issues.append(badcur)

    if is_sqli(body):
        issues.append("SQLi-like pattern")
    if is_xss(body):
        issues.append("XSS-like pattern")
    if find_biginteger_error(body):
        issues.append("BigInteger overflow (MessagePack)")
    return issues
