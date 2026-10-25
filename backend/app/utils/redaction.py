import re

# Common secret patterns for secondary redaction safety
SECRET_PATTERNS = [
    re.compile(r'(AKIA[0-9A-Z]{16})', re.IGNORECASE),
    re.compile(r'(gh[pousr]_[A-Za-z0-9_]{36,255})'),
    re.compile(r'(github_pat_[A-Za-z0-9_]{82})'),
    re.compile(r'(xox[baprs]-[0-9A-Za-z\-]{10,250})'),
    re.compile(r'([sr]k_(?:live|test)_[0-9a-zA-Z]{24})'),
    re.compile(r'(rk_live_[0-9a-zA-Z]{24})'),
    re.compile(r'(sk-[a-zA-Z0-9]{20,50})'),
    re.compile(r'(AIza[0-9A-Za-z-_]{35})'),
    re.compile(r'(-----BEGIN [A-Z ]+ PRIVATE KEY-----[^-]+-----END [A-Z ]+ PRIVATE KEY-----)', re.DOTALL),
    re.compile(r'(eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+)'), # JWT
    re.compile(r'(password\s*[:=]\s*["\'])([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'(secret\s*[:=]\s*["\'])([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'(api[_-]?key\s*[:=]\s*["\'])([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'(token\s*[:=]\s*["\'])([^"\']+)["\']', re.IGNORECASE),
]

def redact_secret_string(value: str) -> str:
    """Masks secret value while preserving prefix for context if possible."""
    if not value:
        return "[REDACTED]"
    clean = str(value).strip()
    if len(clean) <= 6:
        return "[REDACTED]"
    # Show first 3-4 chars and mask remainder
    prefix = clean[:3]
    return f"{prefix}***REDACTED***"

def redact_text(text: str) -> str:
    """Scans any text snippet or evidence string and masks potential raw credentials."""
    if not text:
        return ""
    
    redacted = text
    # Mask private keys specifically
    redacted = re.sub(
        r'-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----',
        '-----BEGIN PRIVATE KEY-----\n*** REDACTED PRIVATE KEY CONTENT ***\n-----END PRIVATE KEY-----',
        redacted
    )

    # Mask key=value style assignments
    def mask_key_val(match):
        prefix = match.group(1)
        val = match.group(2)
        if len(val) > 4:
            masked_val = val[:2] + "****REDACTED****"
        else:
            masked_val = "****REDACTED****"
        return f"{prefix}{masked_val}\""

    for pattern in [
        re.compile(r'((?:password|secret|api[_-]?key|token|access[_-]?key|auth_token)\s*[:=]\s*["\'])([^"\']+)["\']', re.IGNORECASE)
    ]:
        redacted = pattern.sub(mask_key_val, redacted)

    # Mask common known token prefixes
    # AWS Access Key
    redacted = re.sub(r'\b(AKIA[0-9A-Z]{16})\b', lambda m: m.group(1)[:4] + "****REDACTED****", redacted)
    # GitHub Tokens
    redacted = re.sub(r'\b(gh[pousr]_[A-Za-z0-9_]{30,255})\b', lambda m: m.group(1)[:6] + "****REDACTED****", redacted)
    redacted = re.sub(r'\b(github_pat_[A-Za-z0-9_]{30,100})\b', lambda m: m.group(1)[:12] + "****REDACTED****", redacted)
    # Slack
    redacted = re.sub(r'\b(xox[baprs]-[0-9A-Za-z\-]{10,250})\b', lambda m: m.group(1)[:6] + "****REDACTED****", redacted)
    # Stripe
    redacted = re.sub(r'\b([sr]k_live_[0-9a-zA-Z]{16,40})\b', lambda m: m.group(1)[:8] + "****REDACTED****", redacted)
    # Google API Key
    redacted = re.sub(r'\b(AIza[0-9A-Za-z-_]{30,40})\b', lambda m: m.group(1)[:6] + "****REDACTED****", redacted)

    return redacted
