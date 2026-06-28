from model.features import normalize_url, _safe_parse

TRUSTED_DOMAINS = {
    "google.com", "gmail.com", "youtube.com", "microsoft.com", "live.com",
    "outlook.com", "office.com", "apple.com", "icloud.com", "amazon.com",
    "facebook.com", "instagram.com", "linkedin.com", "x.com", "twitter.com",
    "github.com", "gitlab.com", "dropbox.com", "adobe.com", "netflix.com",
    "wikipedia.org", "paypal.com", "stripe.com", "chase.com", "bankofamerica.com",
    "wellsfargo.com", "citibank.com", "americanexpress.com", "visa.com",
    "mastercard.com",
}


def get_registered_domain(url: str) -> str:
    parsed = _safe_parse(normalize_url(url))
    return (parsed.hostname or "").lower()


def is_trusted(url: str) -> bool:
    host = get_registered_domain(url)
    if not host:
        return False
    for domain in TRUSTED_DOMAINS:
        if host == domain or host.endswith("." + domain):
            return True
    return False
