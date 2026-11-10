import html
import re
from typing import Any

SENSITIVE_KEY_PATTERN = re.compile(
    r"(api[_-]?key|secret|token|password|authorization|service[_-]?role)",
    re.IGNORECASE,
)


def sanitize_text(value: str, max_length: int = 2048) -> str:
    """Strip control characters and normalize user-controlled strings safely."""
    cleaned = "".join(ch for ch in value if ch >= " " or ch in ("\n", "\t"))
    return cleaned[:max_length]


def escape_html_text(value: str) -> str:
    """Escape HTML special characters when generating safe display strings."""
    return html.escape(sanitize_text(value), quote=True)


def redact_secrets(obj: Any) -> Any:
    """Recursively redact sensitive keys from dictionaries before persisting reports."""
    if isinstance(obj, dict):
        sanitized = {}
        for k, v in obj.items():
            if SENSITIVE_KEY_PATTERN.search(str(k)):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = redact_secrets(v)
        return sanitized
    if isinstance(obj, list):
        return [redact_secrets(item) for item in obj]
    return obj

