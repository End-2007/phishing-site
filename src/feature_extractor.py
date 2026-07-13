# Phishing Detector - Live 4-Signal Feature Extractor
# Author: Naman Dugar | HCIC-SI 2026 | P16
#
# Signals:
#   1. URL Features       (instant, no network)
#   2. Page Content       (fetches live page)
#   3. SSL Certificate    (checks cert details)
#   4. WHOIS Domain Age   (checks domain registration)
# All 4 signals run in parallel using concurrent.futures

import re
import ssl
import socket
import requests
import whois
import concurrent.futures
from urllib.parse import urlparse
from datetime import datetime
from bs4 import BeautifulSoup
import warnings
warnings.filterwarnings("ignore")

TIMEOUT = 10

SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
    'is.gd', 'buff.ly', 'adf.ly', 'bitly.com', 'rb.gy'
}

SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'update',
    'bank', 'account', 'password', 'confirm', 'paypal',
    'ebay', 'amazon', 'apple', 'microsoft', 'google',
    'netflix', 'support', 'service', 'suspend', 'unusual'
]

TRUSTED_ISSUERS = [
    'digicert', 'comodo', 'sectigo', 'globalsign', 'geotrust',
    'thawte', 'entrust', 'godaddy', 'network solutions', 'symantec',
    "let's encrypt", 'amazon', 'cloudflare', 'microsoft',
    'google trust services', 'google'
]

HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/120.0.0.0 Safari/537.36'
    )
}


# Signal 1: URL Features

def extract_url_features(url):
    """Extract 26 features from the URL string alone. No network needed."""
    features = {}
    flags = []

    try:
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
        domain = parsed.netloc.lower().split(':')[0]
        path = parsed.path.lower()
        full = url.lower()

        features['url_length'] = len(url)
        features['domain_length'] = len(domain)
        features['path_length'] = len(path)

        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_at'] = url.count('@')
        features['num_question'] = url.count('?')
        features['num_equals'] = url.count('=')
        features['num_ampersand'] = url.count('&')
        features['num_percent'] = url.count('%')
        features['num_digits'] = sum(c.isdigit() for c in url)

        subdomains = domain.split('.')
        features['num_subdomains'] = max(0, len(subdomains) - 2)
        features['has_ip_address'] = int(bool(
            re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain)
        ))
        features['is_url_shortener'] = int(
            any(s in domain for s in SHORTENERS)
        )

        features['has_https'] = int(parsed.scheme == 'https')

        features['suspicious_keyword_count'] = sum(
            1 for kw in SUSPICIOUS_KEYWORDS if kw in full
        )
        features['has_suspicious_keyword'] = int(
            features['suspicious_keyword_count'] > 0
        )

        features['has_double_slash'] = int('//' in path)
        features['has_hex_encoding'] = int(
            bool(re.search(r'%[0-9a-fA-F]{2}', url))
        )
        features['path_depth'] = path.count('/')
        features['has_port'] = int(':' in parsed.netloc)
        features['tld_in_path'] = int(
            bool(re.search(r'\.(com|net|org|info|biz)', path))
        )

        features['digit_ratio'] = features['num_digits'] / max(len(url), 1)
        features['special_char_ratio'] = (
            features['num_dots'] + features['num_hyphens'] +
            features['num_at'] + features['num_percent']
        ) / max(len(url), 1)

        # Build explanation flags
        if features['url_length'] > 75:
            flags.append("URL is unusually long")
        if features['has_ip_address']:
            flags.append("IP address used instead of domain name")
        if features['is_url_shortener']:
            flags.append("URL shortener detected")
        if not features['has_https']:
            flags.append("No HTTPS")
        if features['has_suspicious_keyword']:
            flags.append(f"Suspicious keywords found in URL")
        if features['num_subdomains'] > 2:
            flags.append(f"Too many subdomains ({features['num_subdomains']})")
        if features['num_at'] > 0:
            flags.append("@ symbol in URL (suspicious)")
        if features['has_ip_address']:
            flags.append("Direct IP address in URL")

    except Exception as e:
        features = {k: 0 for k in [
            'url_length', 'domain_length', 'path_length',
            'num_dots', 'num_hyphens', 'num_underscores',
            'num_slashes', 'num_at', 'num_question', 'num_equals',
            'num_ampersand', 'num_percent', 'num_digits',
            'num_subdomains', 'has_ip_address', 'is_url_shortener',
            'has_https', 'suspicious_keyword_count', 'has_suspicious_keyword',
            'has_double_slash', 'has_hex_encoding', 'path_depth',
            'has_port', 'tld_in_path', 'digit_ratio', 'special_char_ratio'
        ]}
        flags.append(f"URL parsing error: {str(e)}")

    # Heuristic score: 0-100 (higher = more suspicious)
    score = min(100, int(sum([
        20 if features.get('has_ip_address') else 0,
        15 if features.get('is_url_shortener') else 0,
        15 if not features.get('has_https') else 0,
        10 if features.get('has_suspicious_keyword') else 0,
        10 if features.get('url_length', 0) > 75 else 0,
        10 if features.get('num_subdomains', 0) > 2 else 0,
        10 if features.get('num_at', 0) > 0 else 0,
        5  if features.get('has_double_slash') else 0,
        5  if features.get('has_hex_encoding') else 0,
    ])))

    return features, score, flags


# Signal 2: Page Content Analysis

def analyze_page_content(url):
    """Fetch the live page and analyze its HTML structure."""
    flags = []
    score = 0

    try:
        response = requests.get(
            url, timeout=TIMEOUT,
            headers=HEADERS,
            allow_redirects=True,
            verify=False
        )
        soup = BeautifulSoup(response.text, 'html.parser')
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        password_fields = soup.find_all('input', {'type': 'password'})
        has_password_field = len(password_fields) > 0

        forms = soup.find_all('form')
        external_form = False
        for form in forms:
            action = form.get('action', '')
            if action and action.startswith('http'):
                action_domain = urlparse(action).netloc.lower()
                if action_domain and action_domain != domain:
                    external_form = True
                    break

        all_links = soup.find_all('a', href=True)
        external_links = 0
        internal_links = 0
        for link in all_links:
            href = link['href']
            if href.startswith('http'):
                if domain not in href:
                    external_links += 1
                else:
                    internal_links += 1
            else:
                internal_links += 1

        total_links = external_links + internal_links
        external_ratio = external_links / max(total_links, 1)

        iframes = soup.find_all('iframe')
        has_iframe = len(iframes) > 0

        title_tag = soup.find('title')
        page_title = title_tag.text.lower() if title_tag else ''
        title_domain_mismatch = False
        if page_title:
            for kw in SUSPICIOUS_KEYWORDS:
                if kw in page_title and kw not in domain:
                    title_domain_mismatch = True
                    break

        favicon = soup.find('link', rel=lambda r: r and 'icon' in r)
        external_favicon = False
        if favicon and favicon.get('href', '').startswith('http'):
            if domain not in favicon['href']:
                external_favicon = True

        hidden_elements = soup.find_all(style=re.compile(r'display\s*:\s*none'))
        has_hidden = len(hidden_elements) > 3

        redirect_count = len(response.history)

        if has_password_field:
            flags.append("Password input field detected on page")
        if external_form:
            flags.append("Form submits to external domain")
        if external_ratio > 0.6:
            flags.append(f"High external link ratio ({external_ratio:.0%})")
        if has_iframe:
            flags.append("Hidden iframes detected")
        if title_domain_mismatch:
            flags.append("Page title doesn't match domain")
        if external_favicon:
            flags.append("Favicon loaded from external domain")
        if has_hidden:
            flags.append("Excessive hidden elements detected")
        if redirect_count > 2:
            flags.append(f"Multiple redirects ({redirect_count})")

        score = min(100, int(sum([
            25 if external_form else 0,
            20 if has_password_field and external_ratio > 0.5 else 0,
            15 if external_ratio > 0.7 else 0,
            10 if has_iframe else 0,
            10 if title_domain_mismatch else 0,
            10 if external_favicon else 0,
            5  if has_hidden else 0,
            5  if redirect_count > 2 else 0,
        ])))

    except requests.exceptions.SSLError:
        flags.append("SSL verification failed — possible fake site")
        score = 60
    except requests.exceptions.ConnectionError:
        flags.append("Could not connect to URL — site may be down or fake")
        score = 70
    except requests.exceptions.Timeout:
        flags.append("Request timed out")
        score = 50
    except Exception as e:
        flags.append(f"Page fetch error: {str(e)}")
        score = 40

    return score, flags


# Signal 3: SSL Certificate Analysis

def analyze_ssl_certificate(url):
    """Check SSL certificate validity, age, and issuer."""
    flags = []
    score = 0

    try:
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
        hostname = parsed.netloc.split(':')[0]

        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.create_connection((hostname, 443), timeout=TIMEOUT),
            server_hostname=hostname
        )
        cert = conn.getpeercert()
        conn.close()

        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        not_before = not_before.replace(tzinfo=None)
        not_after = not_after.replace(tzinfo=None)
        cert_age_days = (datetime.utcnow() - not_before).days
        days_until_expiry = (not_after - datetime.utcnow()).days

        issuer_info = dict(x[0] for x in cert.get('issuer', []))
        issuer_org = issuer_info.get('organizationName', '').lower()
        is_trusted_issuer = any(t in issuer_org for t in TRUSTED_ISSUERS)

        subject_info = dict(x[0] for x in cert.get('subject', []))
        cn = subject_info.get('commonName', '').lower()
        cn_matches = hostname.lower() in cn or cn in hostname.lower()

        san_list = []
        for san_type, san_value in cert.get('subjectAltName', []):
            san_list.append(san_value.lower())
        san_matches = any(hostname.lower() in s or s in hostname.lower() for s in san_list)

        domain_verified = cn_matches or san_matches

        if cert_age_days < 30:
            flags.append(f"Certificate issued only {cert_age_days} days ago")
        if days_until_expiry < 30:
            flags.append(f"Certificate expires in {days_until_expiry} days")
        if not is_trusted_issuer:
            flags.append(f"Untrusted certificate issuer: {issuer_org}")
        if not domain_verified:
            flags.append("Certificate CN does not match domain")

        score = min(100, int(sum([
            30 if cert_age_days < 7 else (10 if cert_age_days < 30 else 0),
            15 if not is_trusted_issuer else 0,
            25 if not domain_verified else 0,
            10 if days_until_expiry < 30 else 0,
        ])))

        if not flags:
            flags.append("SSL certificate looks valid")

    except ssl.SSLCertVerificationError:
        flags.append("SSL certificate verification failed")
        score = 80
    except ssl.SSLError:
        flags.append("SSL error — invalid or self-signed certificate")
        score = 75
    except socket.timeout:
        flags.append("SSL connection timed out")
        score = 30
    except ConnectionRefusedError:
        flags.append("HTTPS not available on this domain")
        score = 50
    except Exception as e:
        flags.append(f"SSL check error: {str(e)}")
        score = 30

    return score, flags


# Signal 4: WHOIS Domain Age

def analyze_whois(url):
    """Check domain registration age and other WHOIS data."""
    flags = []
    score = 0

    try:
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
        domain = parsed.netloc.split(':')[0]

        if domain.startswith('www.'):
            domain = domain[4:]

        w = whois.whois(domain)

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        if creation_date:
            if isinstance(creation_date, str):
                creation_date = datetime.strptime(creation_date[:10], '%Y-%m-%d')

            if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)
            domain_age_days = (datetime.utcnow() - creation_date).days

            if domain_age_days < 30:
                flags.append(f"Domain registered only {domain_age_days} days ago")
                score += 50
            elif domain_age_days < 90:
                flags.append(f"Domain is relatively new ({domain_age_days} days old)")
                score += 25
            elif domain_age_days < 365:
                flags.append(f"Domain is less than 1 year old ({domain_age_days} days)")
                score += 10
            else:
                flags.append(f"Domain is {domain_age_days // 365} year(s) old — looks legitimate")
        else:
            flags.append("Could not determine domain age")
            score += 20

        country = getattr(w, 'country', None)
        if country:
            flags.append(f"Registrar country: {country}")

        if expiration_date:
            if isinstance(expiration_date, str):
                expiration_date = datetime.strptime(expiration_date[:10], '%Y-%m-%d')
            days_to_expiry = (expiration_date - datetime.utcnow()).days
            if days_to_expiry < 60:
                flags.append(f"Domain expires in {days_to_expiry} days")
                score += 15

        score = min(100, score)

    except Exception as e:
        flags.append(f"WHOIS lookup failed: {str(e)}")
        score = 25

    return score, flags


# Main: Run all 4 signals in parallel

def analyze_url(url, model, feature_names):
    """
    Full phishing analysis of a URL.
    Runs all 4 signals in parallel and returns a result dictionary.
    """
    print(f"\n  Analyzing: {url}")
    print("  Running 4-signal analysis in parallel...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        future_url     = executor.submit(extract_url_features, url)
        future_page    = executor.submit(analyze_page_content, url)
        future_ssl     = executor.submit(analyze_ssl_certificate, url)
        future_whois   = executor.submit(analyze_whois, url)

        url_features, url_score, url_flags     = future_url.result()
        page_score, page_flags                 = future_page.result()
        ssl_score, ssl_flags                   = future_ssl.result()
        whois_score, whois_flags               = future_whois.result()

    # ML model prediction
    import pandas as pd
    import numpy as np

    feature_vector = pd.DataFrame([url_features])[feature_names]
    ml_probability = float(model.predict_proba(feature_vector)[0][1])
    ml_score = int(ml_probability * 100)

    # Weighted ensemble: ML 40%, Page 25%, SSL 20%, WHOIS 15%
    final_score = int(
        ml_score   * 0.40 +
        page_score * 0.25 +
        ssl_score  * 0.20 +
        whois_score * 0.15
    )
    final_score = min(100, final_score)

    if final_score >= 65:
        verdict = "PHISHING"
        verdict_color = "red"
    elif final_score >= 50:
        verdict = "SUSPICIOUS"
        verdict_color = "orange"
    else:
        verdict = "SAFE"
        verdict_color = "green"

    result = {
        "url": url,
        "risk_score": final_score,
        "verdict": verdict,
        "verdict_color": verdict_color,
        "ml_confidence": f"{ml_probability*100:.1f}%",
        "signals": {
            "url_features": {
                "score": url_score,
                "flags": url_flags if url_flags else ["No suspicious URL patterns found"]
            },
            "page_content": {
                "score": page_score,
                "flags": page_flags if page_flags else ["Page content looks normal"]
            },
            "ssl_certificate": {
                "score": ssl_score,
                "flags": ssl_flags if ssl_flags else ["SSL certificate looks valid"]
            },
            "domain_age": {
                "score": whois_score,
                "flags": whois_flags if whois_flags else ["Domain age is acceptable"]
            }
        }
    }

    return result


if __name__ == "__main__":
    import joblib

    print("Loading model...")
    model = joblib.load('../models/phishing_model.pkl')
    feature_names = joblib.load('../models/feature_names.pkl')

    test_urls = [
        "https://www.google.com",
        "http://paypal-secure-login-verify.xyz/account/confirm",
        "https://github.com",
    ]

    for url in test_urls:
        result = analyze_url(url, model, feature_names)
        print(f"\n  URL     : {result['url']}")
        print(f"  Verdict : {result['verdict']}")
        print(f"  Score   : {result['risk_score']}/100")
        print(f"  ML Conf : {result['ml_confidence']}")
        for signal, data in result['signals'].items():
            print(f"  [{signal}] Score: {data['score']} | {' | '.join(data['flags'][:2])}")