# Phishing Detector - Data Merge, Clean & Model Training
# Author: Naman Dugar | HCIC-SI 2026 | P16

import pandas as pd
import numpy as np
import os
import re
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from urllib.parse import urlparse

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, roc_auc_score, roc_curve,
    classification_report
)
from sklearn.utils import resample
from xgboost import XGBClassifier
import warnings
warnings.filterwarnings("ignore")


# Step 1: Load all 3 datasets

print("\n[1/7] Loading datasets...")

BASE = os.path.join(os.path.dirname(__file__), '..', 'data')

# Dataset 1: ISCX Malicious URLs — columns: url, type (benign/phishing/malware/defacement)
df1 = pd.read_csv(os.path.join(BASE, 'malicious_phish.csv'))
df1 = df1.rename(columns={'url': 'url', 'type': 'label_raw'})
df1['label'] = df1['label_raw'].apply(
    lambda x: 0 if str(x).strip().lower() == 'benign' else 1
)
df1 = df1[['url', 'label']]
print(f"  Dataset 1 (ISCX):          {len(df1):>8,} rows")

# Dataset 2: Phishing Site URLs — columns: URL, Label (good/bad)
df2 = pd.read_csv(os.path.join(BASE, 'phishing_site_urls.csv'))
df2.columns = df2.columns.str.strip()
url_col2 = [c for c in df2.columns if c.lower() in ['url', 'urls']][0]
label_col2 = [c for c in df2.columns if c.lower() == 'label'][0]
df2 = df2.rename(columns={url_col2: 'url', label_col2: 'label_raw'})
df2['label'] = df2['label_raw'].apply(
    lambda x: 0 if str(x).strip().lower() in ['good', 'legitimate', 'benign', '0'] else 1
)
df2 = df2[['url', 'label']]
print(f"  Dataset 2 (Phishing Site): {len(df2):>8,} rows")

# Dataset 3: PhishTank Verified — all URLs are confirmed phishing
df3 = pd.read_csv(os.path.join(BASE, 'verified_online.csv'), on_bad_lines='skip')
df3.columns = df3.columns.str.strip().str.lower()
url_col3 = [c for c in df3.columns if 'url' in c][0]
df3 = df3[[url_col3]].rename(columns={url_col3: 'url'})
df3['label'] = 1
print(f"  Dataset 3 (PhishTank):     {len(df3):>8,} rows")


# Step 2: Merge and clean

print("\n[2/7] Merging and cleaning...")

df = pd.concat([df1, df2, df3], ignore_index=True)
print(f"  Total before cleaning:     {len(df):>8,} rows")

df = df.dropna(subset=['url', 'label'])
df = df[df['url'].astype(str).str.strip() != '']
df['url'] = df['url'].astype(str).str.strip().str.lower()
df = df.drop_duplicates(subset=['url'])
df['label'] = df['label'].astype(int)
df = df[df['url'].str.len() >= 4]

print(f"  Total after cleaning:      {len(df):>8,} rows")
print(f"  Legitimate (0):            {(df['label']==0).sum():>8,}")
print(f"  Phishing   (1):            {(df['label']==1).sum():>8,}")


# Step 3: Feature extraction (URL-based only)
# Training uses URL features since we can't fetch 650K+ live pages.
# Live detection uses the full 4-signal extractor for better accuracy.

print("\n[3/7] Extracting URL features...")

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

def extract_url_features(url):
    features = {}
    try:
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
        domain = parsed.netloc.lower()
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
            re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain.split(':')[0])
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
        features['has_hex_encoding'] = int('%' in url and re.search(r'%[0-9a-fA-F]{2}', url) is not None)
        features['path_depth'] = path.count('/')
        features['has_port'] = int(':' in domain)
        features['tld_in_path'] = int(bool(re.search(r'\.(com|net|org|info|biz)', path)))

        features['digit_ratio'] = features['num_digits'] / max(len(url), 1)
        features['special_char_ratio'] = (
            features['num_dots'] + features['num_hyphens'] +
            features['num_at'] + features['num_percent']
        ) / max(len(url), 1)

    except Exception:
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
    return features

print("  Extracting features (this takes 2-3 minutes for large datasets)...")
feature_list = [extract_url_features(url) for url in df['url']]
X = pd.DataFrame(feature_list)
y = df['label'].values

print(f"  Features extracted: {X.shape[1]} features x {X.shape[0]:,} samples")


# Step 4: Handle class imbalance

print("\n[4/7] Balancing classes...")

X['label'] = y
majority = X[X['label'] == 0]
minority = X[X['label'] == 1]

print(f"  Before balancing — Majority: {len(majority):,} | Minority: {len(minority):,}")

if len(majority) > len(minority) * 1.5:
    majority_downsampled = resample(
        majority, replace=False,
        n_samples=len(minority),
        random_state=42
    )
    X_balanced = pd.concat([majority_downsampled, minority])
else:
    X_balanced = X.copy()

X_balanced = X_balanced.sample(frac=1, random_state=42).reset_index(drop=True)
y_balanced = X_balanced['label'].values
X_balanced = X_balanced.drop('label', axis=1)

print(f"  After balancing  — Total: {len(X_balanced):,} | 50-50 split")


# Step 5: Train/test split and model training

print("\n[5/7] Training XGBoost model...")

X_train, X_test, y_train, y_test = train_test_split(
    X_balanced, y_balanced,
    test_size=0.2,
    random_state=42,
    stratify=y_balanced
)

print(f"  Train size: {len(X_train):,} | Test size: {len(X_test):,}")

model = XGBClassifier(
    n_estimators=500,
    max_depth=8,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    use_label_encoder=False,
    eval_metric='logloss',
    random_state=42,
    n_jobs=-1
)

model.fit(
    X_train, y_train,
    eval_set=[(X_test, y_test)],
    verbose=50
)


# Step 6: Evaluate

print("\n[6/7] Evaluating model...")

y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

acc  = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred)
rec  = recall_score(y_test, y_pred)
f1   = f1_score(y_test, y_pred)
auc  = roc_auc_score(y_test, y_prob)

print(f"\n  Accuracy  : {acc*100:.2f}%")
print(f"  Precision : {prec*100:.2f}%")
print(f"  Recall    : {rec*100:.2f}%")
print(f"  F1 Score  : {f1*100:.2f}%")
print(f"  ROC-AUC   : {auc*100:.2f}%")

print("\n  Classification Report:")
print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

feature_names = list(X_balanced.columns)

# Confusion matrix
os.makedirs(os.path.join(os.path.dirname(__file__), '..', 'reports'), exist_ok=True)
REPORT_DIR = os.path.join(os.path.dirname(__file__), '..', 'reports')

cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(6, 5))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=['Legitimate', 'Phishing'],
            yticklabels=['Legitimate', 'Phishing'])
plt.title('Confusion Matrix')
plt.ylabel('Actual')
plt.xlabel('Predicted')
plt.tight_layout()
plt.savefig(os.path.join(REPORT_DIR, 'confusion_matrix.png'), dpi=150)
plt.close()
print("  Saved: reports/confusion_matrix.png")

# ROC curve
fpr, tpr, _ = roc_curve(y_test, y_prob)
plt.figure(figsize=(6, 5))
plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC Curve (AUC = {auc:.3f})')
plt.plot([0, 1], [0, 1], color='navy', lw=1, linestyle='--')
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('ROC Curve')
plt.legend(loc='lower right')
plt.tight_layout()
plt.savefig(os.path.join(REPORT_DIR, 'roc_curve.png'), dpi=150)
plt.close()
print("  Saved: reports/roc_curve.png")

# Feature importance
importance = pd.Series(model.feature_importances_, index=feature_names)
importance = importance.sort_values(ascending=False).head(15)
plt.figure(figsize=(8, 6))
importance.plot(kind='barh', color='steelblue')
plt.title('Top 15 Most Important Features')
plt.xlabel('Importance Score')
plt.gca().invert_yaxis()
plt.tight_layout()
plt.savefig(os.path.join(REPORT_DIR, 'feature_importance.png'), dpi=150)
plt.close()
print("  Saved: reports/feature_importance.png")


# Step 7: Save model

print("\n[7/7] Saving model...")

MODEL_DIR = os.path.join(os.path.dirname(__file__), '..', 'models')
os.makedirs(MODEL_DIR, exist_ok=True)

joblib.dump(model, os.path.join(MODEL_DIR, 'phishing_model.pkl'))
joblib.dump(feature_names, os.path.join(MODEL_DIR, 'feature_names.pkl'))

print("  Saved: models/phishing_model.pkl")
print("  Saved: models/feature_names.pkl")

print(f"\nTraining complete. Accuracy: {acc*100:.2f}% | AUC: {auc*100:.2f}%\n")