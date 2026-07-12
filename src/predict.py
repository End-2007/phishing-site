# ============================================================
# PHISHING DETECTOR - Predict
# Author: Naman Dugar | HCIC-SI 2026 | P16
# ============================================================

import joblib
import os
import time
from urllib.parse import urlparse
from feature_extractor import analyze_url

# ============================================================
# WHITELIST - Known legitimate domains (skip full analysis)
# ============================================================

WHITELIST = {
    'google.com', 'github.com', 'microsoft.com', 'apple.com',
    'amazon.com', 'facebook.com', 'twitter.com', 'linkedin.com',
    'sbi.co.in', 'hdfcbank.com', 'icicibank.com', 'axisbank.com',
    'irctc.co.in', 'incometax.gov.in', 'gov.in', 'nic.in',
    'youtube.com', 'instagram.com', 'wikipedia.org', 'stackoverflow.com',
    'anthropic.com', 'openai.com', 'cloudflare.com', 'aws.amazon.com'
}

# ============================================================
# LOAD MODEL ONCE
# ============================================================

BASE = os.path.dirname(__file__)
MODEL_PATH = os.path.join(BASE, '..', 'models', 'phishing_model.pkl')
FEATURES_PATH = os.path.join(BASE, '..', 'models', 'feature_names.pkl')

print("Loading model...")
model = joblib.load(MODEL_PATH)
feature_names = joblib.load(FEATURES_PATH)
print("Model loaded successfully.")

# ============================================================
# MAIN PREDICTION FUNCTION
# ============================================================

def predict(url):
    """
    Takes a URL string.
    Returns a complete result dictionary.
    """

    # STEP 1: Clean URL
    url = url.strip()

    # STEP 2: Check if empty
    if not url:
        return {
            "url": url,
            "risk_score": 0,
            "verdict": "INVALID",
            "verdict_color": "grey",
            "ml_confidence": "0%",
            "detection_time": "0s",
            "signals": {},
            "error": "Empty URL provided"
        }

    # STEP 3: Add http:// if no scheme
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url

    # STEP 4: Whitelist check
    domain = urlparse(url).netloc.lower().replace('www.', '')
    if any(domain.endswith(w) for w in WHITELIST):
        return {
            "url": url,
            "risk_score": 5,
            "verdict": "SAFE",
            "verdict_color": "green",
            "ml_confidence": "100.0%",
            "detection_time": "0.1s",
            "signals": {
                "url_features":    {"score": 0, "flags": ["Verified legitimate domain"]},
                "page_content":    {"score": 0, "flags": ["Verified legitimate domain"]},
                "ssl_certificate": {"score": 0, "flags": ["Verified legitimate domain"]},
                "domain_age":      {"score": 0, "flags": ["Verified legitimate domain"]}
            }
        }

    # STEP 5: Full 4-signal analysis
    start_time = time.time()
    result = analyze_url(url, model, feature_names)
    end_time = time.time()

    result['detection_time'] = f"{end_time - start_time:.1f}s"

    return result


# ============================================================
# BATCH PREDICTION
# ============================================================

def predict_batch(urls):
    """Takes a list of URLs, returns list of results."""
    results = []
    for url in urls:
        result = predict(url)
        results.append(result)
    return results


# ============================================================
# HELPER: One-line summary
# ============================================================

def get_summary(result):
    """Returns a one-line summary of the prediction result."""
    return (
        f"{result['verdict']} | "
        f"Risk: {result['risk_score']}/100 | "
        f"ML Confidence: {result['ml_confidence']} | "
        f"Time: {result['detection_time']}"
    )


# ============================================================
# QUICK TEST
# ============================================================

if __name__ == "__main__":

    test_urls = [
        "https://www.google.com",
        "https://www.sbi.co.in",
        "http://paypal-secure-login-verify.xyz/account/confirm",
        "http://192.168.1.1/bank/login",
        "https://github.com",
    ]

    print("\n" + "="*60)
    print("PHISHING DETECTOR - Batch Test")
    print("="*60)

    for url in test_urls:
        result = predict(url)
        print(f"\nURL     : {result['url']}")
        print(f"Verdict : {result['verdict']}")
        print(f"Score   : {result['risk_score']}/100")
        print(f"Time    : {result['detection_time']}")
        print(f"Summary : {get_summary(result)}")
        print("-"*60)