from model.features import normalize_url, _safe_parse

TRUSTED_DOMAINS = {
    # Big Tech
    "google.com", "gmail.com", "youtube.com", "microsoft.com", "live.com",
    "outlook.com", "office.com", "apple.com", "icloud.com", "amazon.com",
    "facebook.com", "instagram.com", "linkedin.com", "x.com", "twitter.com",
    "github.com", "gitlab.com", "dropbox.com", "adobe.com", "netflix.com",
    "wikipedia.org", "cloudflare.com", "aws.amazon.com", "azure.microsoft.com",
    "slack.com", "zoom.us", "notion.so", "figma.com", "canva.com",
    "shopify.com", "wordpress.com", "medium.com", "substack.com",
    "stackoverflow.com", "reddit.com", "discord.com", "twitch.tv",
    "spotify.com", "whatsapp.com", "telegram.org",
    # Finance
    "paypal.com", "stripe.com", "chase.com", "bankofamerica.com",
    "wellsfargo.com", "citibank.com", "americanexpress.com", "visa.com",
    "mastercard.com", "coinbase.com", "binance.com",
    # Cybersecurity
    "virustotal.com", "shodan.io", "haveibeenpwned.com", "kali.org",
    "exploit-db.com", "cve.mitre.org", "nvd.nist.gov", "sans.org",
    "owasp.org", "malwarebytes.com", "avast.com", "norton.com",
    "kaspersky.com", "crowdstrike.com", "paloaltonetworks.com",
    "phishtank.org", "phishtank.com", "urlvoid.com", "urlscan.io",
    "hybrid-analysis.com", "any.run", "abuse.ch", "threatfox.abuse.ch",
    "cyberchef.org", "censys.io", "greynoise.io",
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
