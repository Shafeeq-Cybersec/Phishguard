import re

from model.features import (IP_PATTERN, SUSPICIOUS_WORDS, _safe_parse,
                            extract_features, normalize_url)

MULTI_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "gov.au", "edu.au",
    "co.in", "net.in", "org.in", "gen.in", "firm.in",
    "com.br", "net.br", "org.br", "gov.br",
    "co.jp", "or.jp", "ne.jp", "go.jp", "ac.jp",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "co.za", "org.za", "gov.za", "com.mx", "com.sg", "com.hk", "co.kr",
    "com.tr", "co.id", "com.my", "co.nz", "com.ar", "com.tw", "com.ua",
    "co.il", "com.ph", "com.vn", "com.pk", "com.ng", "com.sa", "com.co",
}

BRAND_DOMAINS = {
    "paypal": "paypal.com", "apple": "apple.com", "icloud": "apple.com",
    "google": "google.com", "gmail": "google.com", "youtube": "youtube.com",
    "microsoft": "microsoft.com", "outlook": "outlook.com", "office365": "office.com",
    "amazon": "amazon.com", "netflix": "netflix.com", "facebook": "facebook.com",
    "instagram": "instagram.com", "whatsapp": "whatsapp.com", "linkedin": "linkedin.com",
    "twitter": "twitter.com", "ebay": "ebay.com", "dhl": "dhl.com", "fedex": "fedex.com",
    "ups": "ups.com", "chase": "chase.com", "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com", "citibank": "citibank.com",
    "americanexpress": "americanexpress.com", "coinbase": "coinbase.com",
    "binance": "binance.com", "steam": "steampowered.com", "dropbox": "dropbox.com",
}

BRAND_DISPLAY = {
    "paypal": "PayPal", "apple": "Apple", "icloud": "iCloud", "google": "Google",
    "gmail": "Gmail", "youtube": "YouTube", "microsoft": "Microsoft",
    "outlook": "Outlook", "office365": "Microsoft 365", "amazon": "Amazon",
    "netflix": "Netflix", "facebook": "Facebook", "instagram": "Instagram",
    "whatsapp": "WhatsApp", "linkedin": "LinkedIn", "twitter": "X (Twitter)",
    "ebay": "eBay", "dhl": "DHL", "fedex": "FedEx", "ups": "UPS", "chase": "Chase",
    "wellsfargo": "Wells Fargo", "bankofamerica": "Bank of America",
    "citibank": "Citibank", "americanexpress": "American Express",
    "coinbase": "Coinbase", "binance": "Binance", "steam": "Steam",
    "dropbox": "Dropbox",
}

_KEYWORD_VOCAB = sorted(set(SUSPICIOUS_WORDS) | set(BRAND_DOMAINS), key=len, reverse=True)


def _hostname(url: str) -> str:
    return (_safe_parse(normalize_url(url)).hostname or "").lower()


def registered_domain(host: str) -> str:
    if IP_PATTERN.match(host):
        return host
    labels = host.split(".")
    if len(labels) < 2:
        return host
    last_two = ".".join(labels[-2:])
    if last_two in MULTI_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def _word_in(word: str, text: str) -> bool:
    return re.search(rf"(?<![a-z0-9]){re.escape(word)}(?![a-z0-9])", text) is not None


def analyze_domain(url: str) -> dict:
    host = _hostname(url)
    reg = registered_domain(host)
    text = normalize_url(url).lower()

    claimed = None
    official = None
    for brand, off in BRAND_DOMAINS.items():
        if _word_in(brand, text):
            claimed = brand
            official = off
            break

    impersonation = False
    if claimed:
        impersonation = not (reg == official or reg.endswith("." + official))

    return {
        "registered_domain": reg,
        "claimed_brand": claimed.title() if claimed else None,
        "official_domain": official,
        "impersonation": impersonation,
    }


def detected_keywords(url: str) -> list:
    text = normalize_url(url).lower()
    found = {w for w in _KEYWORD_VOCAB if _word_in(w, text)}
    return sorted(found, key=lambda w: text.find(w))


def feature_table(url: str, https: bool) -> list:
    f = extract_features(url)
    host = _hostname(url)
    tld = "—" if IP_PATTERN.match(host) else (host.rsplit(".", 1)[-1] if "." in host else "—")
    return [
        {"label": "Length", "value": f["url_length"]},
        {"label": "Subdomains", "value": f["num_subdomains"]},
        {"label": "HTTPS", "value": "Yes" if https else "No"},
        {"label": "Contains IP", "value": "Yes" if f["has_ip"] else "No"},
        {"label": "Contains @", "value": "Yes" if f["has_at_symbol"] else "No"},
        {"label": "Hyphens", "value": f["num_hyphens"]},
        {"label": "Digits", "value": f["num_digits"]},
        {"label": "Query parameters", "value": "Yes" if f["num_question_marks"] else "No"},
        {"label": "Suspicious words", "value": f["suspicious_word_count"]},
        {"label": "TLD", "value": "." + tld if tld != "—" else "—"},
    ]


def risk_breakdown(url: str, domain: dict, https: bool, risk_score: float) -> dict:
    f = extract_features(url)
    raw = []

    if domain.get("impersonation"):
        raw.append(("Brand impersonation", 30))
    if f["suspicious_word_count"]:
        raw.append(("Suspicious keywords", min(f["suspicious_word_count"] * 7, 35)))
    if f["has_ip"]:
        raw.append(("IP address as host", 25))
    if f["is_shortened"]:
        raw.append(("URL shortener", 20))
    if f["has_at_symbol"]:
        raw.append(("'@' redirection trick", 15))
    if f["url_length"] >= 75:
        raw.append(("Long URL", 15))
    elif f["url_length"] >= 50:
        raw.append(("Long URL", 8))
    if f["num_subdomains"] >= 4:
        raw.append(("Too many subdomains", 15))
    elif f["num_subdomains"] >= 2:
        raw.append(("Too many subdomains", 8))
    if f["suspicious_tld"]:
        raw.append(("Suspicious TLD", 12))
    if f["num_hyphens"] >= 4:
        raw.append(("Many hyphens", 6))
    if f["num_question_marks"]:
        raw.append(("Query parameters", 4))

    total = round(risk_score)
    raw_sum = sum(w for _, w in raw)
    if not raw or raw_sum == 0 or total <= 0:
        return {"items": [], "total": total}

    scaled = [(label, w / raw_sum * total) for label, w in raw]
    ints = [round(v) for _, v in scaled]
    diff = total - sum(ints)
    if ints:
        idx = max(range(len(scaled)), key=lambda i: scaled[i][1])
        ints[idx] += diff

    items = [{"label": label, "pct": p}
             for (label, _), p in zip(scaled, ints) if p > 0]
    items.sort(key=lambda d: d["pct"], reverse=True)
    return {"items": items, "total": total}


def tree_votes(clf, x: list) -> dict:
    votes = [int(est.predict([x])[0]) for est in clf.estimators_]
    total = len(votes)
    phishing = sum(votes)
    return {
        "phishing_trees": phishing,
        "safe_trees": total - phishing,
        "total": total,
        "vote_pct": round(phishing / total * 100) if total else 0,
    }
