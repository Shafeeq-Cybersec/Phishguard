from model.features import normalize_url, _safe_parse

TRUSTED_DOMAINS = {
    # Big Tech
    "google.com", "gmail.com", "youtube.com", "microsoft.com", "live.com",
    "outlook.com", "office.com", "apple.com", "icloud.com", "amazon.com",
    "facebook.com", "instagram.com", "linkedin.com", "x.com", "twitter.com",
    "github.com", "gitlab.com", "dropbox.com", "adobe.com", "netflix.com",
    "wikipedia.org", "cloudflare.com", "slack.com", "zoom.us", "notion.so",
    "figma.com", "canva.com", "shopify.com", "wordpress.com", "medium.com",
    "substack.com", "stackoverflow.com", "reddit.com", "discord.com",
    "twitch.tv", "spotify.com", "whatsapp.com", "telegram.org",
    "huggingface.co", "kaggle.com", "colab.research.google.com",
    "vercel.app", "netlify.app", "heroku.com", "render.com",
    "digitalocean.com", "linode.com", "firebase.google.com",
    "npmjs.com", "pypi.org", "dockerhub.com", "hub.docker.com",
    "atlassian.com", "jira.atlassian.com", "trello.com", "asana.com",
    "salesforce.com", "hubspot.com", "intercom.com", "zendesk.com",
    "twilio.com", "sendgrid.com", "mailchimp.com",
    "coursera.org", "udemy.com", "edx.org", "khanacademy.org",
    "w3schools.com", "geeksforgeeks.org", "leetcode.com", "hackerrank.com",
    "replit.com", "codepen.io", "codesandbox.io",
    # Finance & Banking
    "paypal.com", "stripe.com", "chase.com", "bankofamerica.com",
    "wellsfargo.com", "citibank.com", "americanexpress.com", "visa.com",
    "mastercard.com", "coinbase.com", "binance.com", "kraken.com",
    "robinhood.com", "etrade.com", "fidelity.com", "schwab.com",
    "intuit.com", "turbotax.com", "quickbooks.com", "wise.com",
    # Cybersecurity
    "virustotal.com", "shodan.io", "haveibeenpwned.com", "kali.org",
    "exploit-db.com", "cve.mitre.org", "nvd.nist.gov", "sans.org",
    "owasp.org", "malwarebytes.com", "avast.com", "norton.com",
    "kaspersky.com", "crowdstrike.com", "paloaltonetworks.com",
    "phishtank.org", "phishtank.com", "urlvoid.com", "urlscan.io",
    "hybrid-analysis.com", "any.run", "abuse.ch", "cyberchef.org",
    "censys.io", "greynoise.io", "threatintelligenceplatform.com",
    "securitytrails.com", "intezer.com", "joesandbox.com",
    # News & Government
    "bbc.com", "bbc.co.uk", "cnn.com", "nytimes.com", "theguardian.com",
    "reuters.com", "bloomberg.com", "techcrunch.com", "wired.com",
    "theverge.com", "arstechnica.com", "zdnet.com", "bleepingcomputer.com",
    "gov.uk", "usa.gov", "europa.eu", "un.org", "who.int",
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
