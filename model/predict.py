import os
import re

import joblib
import requests

from model.allowlist import is_trusted
from model.analysis import (analyze_domain, detected_keywords, feature_table,
                            risk_breakdown, tree_votes)
from model.features import extract_features, featurize, normalize_url
from model.features import is_shortened_url

_MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishguard_model.pkl")
_artifact = None


def resolve_url(url: str) -> str:
    try:
        r = requests.get(url, allow_redirects=True, timeout=5, stream=True,
                         headers={"User-Agent": "Mozilla/5.0"})
        r.close()
        final = r.url
        return final if final and final != url else url
    except Exception:
        return url


def _load():
    global _artifact
    if _artifact is None:
        _artifact = joblib.load(_MODEL_PATH)
    return _artifact


def get_metadata() -> dict:
    art = _load()
    return {
        "metrics": art.get("metrics", {}),
        "feature_names": art.get("feature_names", []),
        "feature_importances": art.get("feature_importances", {}),
        "trained_on": art.get("trained_on"),
    }


def warmup() -> None:
    _load()


def scan_url(url: str) -> dict:
    url = (url or "").strip()
    if not url:
        raise ValueError("empty url")

    original_url = url
    resolved_url = None
    shortened_unresolved = False
    if is_shortened_url(url):
        resolved = resolve_url(url)
        if resolved != url:
            resolved_url = resolved
            url = resolved
        else:
            shortened_unresolved = True

    artifact = _load()
    clf = artifact["model"]

    x = featurize(url)
    model_risk = round(float(clf.predict_proba([x])[0][1]) * 100, 1)
    https = bool(re.match(r"^https://", url, re.IGNORECASE))

    trusted = is_trusted(url)
    if trusted:
        risk_score = min(model_risk, 5.0)
        verdict = "SAFE"
    else:
        risk_score = model_risk
        if model_risk >= 70:
            verdict = "PHISHING"
        elif model_risk >= 40:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

    domain = analyze_domain(url)

    return {
        "url": original_url,
        "resolved_url": resolved_url,
        "shortened_unresolved": shortened_unresolved,
        "normalized": normalize_url(url),
        "verdict": verdict,
        "risk_score": risk_score,
        "model_risk": model_risk,
        "trusted": trusted,
        "https": https,
        "domain": domain,
        "risk_breakdown": risk_breakdown(url, domain, https, risk_score),
        "keywords": detected_keywords(url),
        "features": feature_table(url, https),
        "tree_votes": tree_votes(clf, x),
    }
