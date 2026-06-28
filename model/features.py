import re
from collections import namedtuple
from urllib.parse import urlparse

SimpleParse = namedtuple("SimpleParse", ["scheme", "hostname", "path"])

SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "banking", "bank", "paypal", "password", "credential", "webscr", "ebayisapi",
    "wp-admin", "submit", "billing", "invoice", "support", "security", "alert",
]

SHORTENERS = [
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "rebrand.ly", "shorturl.at",
]

SUSPICIOUS_TLDS = ["zip", "review", "country", "kim", "cricket", "science",
                   "work", "party", "gq", "link", "tk", "ml", "ga", "cf"]

IP_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

FEATURE_NAMES = [
    "url_length", "hostname_length", "path_length", "num_dots", "num_hyphens",
    "num_at", "num_question_marks", "num_ampersands", "num_equals",
    "num_underscores", "num_percent", "num_slashes", "num_digits", "digit_ratio",
    "num_subdomains", "has_ip", "has_https", "has_at_symbol", "is_shortened",
    "suspicious_word_count", "suspicious_tld", "longest_token_length",
]


def normalize_url(url: str) -> str:
    url = (url or "").strip()
    url = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", url)
    url = re.sub(r"^www\.", "", url, flags=re.IGNORECASE)
    return url


def _safe_parse(url: str):
    url = (url or "").strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = "http://" + url
    try:
        return urlparse(url)
    except ValueError:
        rest = url.split("://", 1)[-1]
        host, _, path = rest.partition("/")
        return SimpleParse(scheme=url.split("://", 1)[0],
                           hostname=host.split(":")[0].lower() or None,
                           path="/" + path if path else "")


def extract_features(url: str) -> dict:
    url = normalize_url(url)
    parsed = _safe_parse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    full = url.lower()

    digits = sum(c.isdigit() for c in url)
    tokens = re.split(r"\W+", url)
    longest_token = max((len(t) for t in tokens), default=0)

    return {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_at": url.count("@"),
        "num_question_marks": url.count("?"),
        "num_ampersands": url.count("&"),
        "num_equals": url.count("="),
        "num_underscores": url.count("_"),
        "num_percent": url.count("%"),
        "num_slashes": url.count("/"),
        "num_digits": digits,
        "digit_ratio": digits / len(url) if url else 0.0,
        "num_subdomains": max(hostname.count(".") - 1, 0),
        "has_ip": int(bool(IP_PATTERN.match(hostname))),
        "has_https": int(parsed.scheme == "https"),
        "has_at_symbol": int("@" in url),
        "is_shortened": int(any(s in hostname for s in SHORTENERS)),
        "suspicious_word_count": sum(full.count(w) for w in SUSPICIOUS_WORDS),
        "suspicious_tld": int(hostname.split(".")[-1] in SUSPICIOUS_TLDS
                              if "." in hostname else 0),
        "longest_token_length": longest_token,
    }


def featurize(url: str) -> list:
    f = extract_features(url)
    return [f[name] for name in FEATURE_NAMES]
