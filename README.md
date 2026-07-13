# 🛡️ Phishing Detector

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![XGBoost](https://img.shields.io/badge/XGBoost-ML%20Model-FF6600?style=for-the-badge)
![Streamlit](https://img.shields.io/badge/Streamlit-Frontend-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-REST%20API-000000?style=for-the-badge&logo=flask&logoColor=white)
![Status](https://img.shields.io/badge/Status-Active-22c55e?style=for-the-badge)

An ML-powered phishing URL detection system with a **Streamlit frontend**, **Flask REST API**, and **explainable AI**. The system uses an **XGBoost** model trained on 650K+ URLs combined with a **live 4-signal concurrent analyzer** (URL Features, Page Content, SSL Certificate, WHOIS Domain Age) to deliver real-time phishing verdicts.

---

## 📑 Table of Contents

- [Project Overview](#-project-overview)
- [Features](#-features)
- [Architecture](#-architecture--workflow)
- [Project Structure](#-project-structure)
- [Dataset Information](#-dataset-information)
- [Installation & Setup](#%EF%B8%8F-installation--setup)
- [Usage](#-usage)
- [Model Details](#-model-details)
- [Evaluation Metrics](#-evaluation-metrics)
- [Screenshots](#-screenshots)
- [Deployment](#-deployment-streamlit-cloud)
- [Future Improvements](#-future-improvements)
- [Contributing](#-contributing)
- [License & Author](#-license--author)

---

## 📖 Project Overview

### Problem Statement
Phishing attacks remain one of the most prevalent cyber threats. Traditional blacklist-based approaches fail against zero-day phishing URLs and are inherently reactive.

### Solution
This project implements a **hybrid phishing detection system** that combines:

1. **Machine Learning Model** — An XGBoost classifier trained on 650K+ labeled URLs to recognize malicious patterns from the URL string alone (26 engineered features).
2. **Live 4-Signal Analyzer** — For real-time predictions, the system concurrently inspects four signals and combines them into a weighted risk score using an ensemble approach.

| Signal | Weight | Method |
|--------|--------|--------|
| 🧠 ML Prediction (URL Features) | 40% | XGBoost model on 26 URL features |
| 📄 Page Content | 25% | Live HTML analysis (forms, iframes, redirects) |
| 🔒 SSL Certificate | 20% | Certificate issuer, expiry, domain match |
| 🌐 Domain Age (WHOIS) | 15% | Domain registration age and expiry |

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Single URL Scanner** | Paste any URL and get an instant verdict with a risk gauge chart |
| 🧠 **Explainable AI** | See exactly *why* a URL was flagged — signal-by-signal breakdown with human-readable flags |
| 📁 **Batch CSV Analysis** | Upload a CSV of URLs for bulk scanning with a live progress bar |
| 📥 **Export Reports** | Download results as CSV, JSON, or a text report |
| 📊 **Analytics Dashboard** | Verdict distribution, risk histograms, and feature importance charts |
| 📜 **Prediction History** | Full session-based scan history with export |
| 🖼️ **URL Screenshot Preview** | Live website screenshot for visual verification |
| ⚡ **Confidence Score** | ML model confidence percentage for every prediction |
| 🚀 **Live Progress Indicator** | Real-time status updates during the 4-signal analysis |
| ✅ **Domain Whitelisting** | Instant SAFE verdict for known legitimate domains |
| 🔗 **Automatic URL Normalization** | Handles missing `http://`, whitespace, and edge cases |

---

## 🏗 Architecture & Workflow

### Training Pipeline (`src/train_model.py`)
```
3 CSV Datasets → Merge & Clean → Extract 26 Features → Balance Classes → Train XGBoost → Save Model + Reports
```

### Prediction Pipeline (`src/predict.py` + `src/feature_extractor.py`)
```
URL Input → Whitelist Check → 4 Parallel Signals → Weighted Ensemble → Verdict (SAFE / SUSPICIOUS / PHISHING)
```

### Application Layer
```
Flask API (app/api.py)  ←  REST endpoints for programmatic access
Streamlit UI (app/app.py)  ←  Interactive web dashboard
```

---

## 📂 Project Structure

```text
phishing-detector/
├── .streamlit/
│   └── config.toml              # Streamlit dark theme configuration
├── app/
│   ├── api.py                   # Flask REST API (GET /, POST /predict, POST /predict_batch)
│   └── app.py                   # Streamlit frontend (3-tab dashboard)
├── data/
│   ├── malicious_phish.csv      # ISCX Malicious URLs dataset (~650K rows)
│   ├── phishing_site_urls.csv   # Phishing Site URLs (good/bad labels)
│   └── verified_online.csv      # PhishTank verified phishing links
├── models/
│   ├── phishing_model.pkl       # Trained XGBoost model
│   └── feature_names.pkl        # Feature column names
├── reports/
│   ├── confusion_matrix.png     # Model confusion matrix
│   ├── feature_importance.png   # Top 15 feature importances
│   └── roc_curve.png            # ROC curve with AUC
├── src/
│   ├── feature_extractor.py     # 4-signal live analyzer (parallel execution)
│   ├── predict.py               # Prediction wrapper + whitelist + batch support
│   └── train_model.py           # Full training pipeline (load → clean → train → evaluate)
├── .gitignore
├── project_report.md            # Detailed academic project report
├── requirements.txt             # Python dependencies
└── README.md
```

---

## 📊 Dataset Information

| Dataset | Source | Rows | Labels | Purpose |
|---------|--------|------|--------|---------|
| `malicious_phish.csv` | ISCX | ~650K | benign / phishing / malware / defacement | Primary dataset |
| `phishing_site_urls.csv` | Kaggle | ~500K | good / bad | Supplementary phishing URLs |
| `verified_online.csv` | PhishTank | ~90K | All phishing | Verified active phishing links |

All datasets are merged, deduplicated, cleaned, and class-balanced (50-50 split) before training.

---

## ⚙️ Installation & Setup

### Prerequisites
- Python 3.8+
- Git
- pip

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/phishing-detector.git
cd phishing-detector

# 2. Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Usage

### Option 1: Streamlit Dashboard (Recommended)
```bash
streamlit run app/app.py
```
Open `http://localhost:8501` in your browser.

### Option 2: Flask REST API
```bash
python app/api.py
```
The API runs at `http://localhost:5000`.

```bash
# Single URL
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "http://suspicious-site.xyz/login"}'

# Batch (up to 100 URLs)
curl -X POST http://localhost:5000/predict_batch \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://google.com", "http://phish.xyz"]}'
```

### Option 3: Re-train the Model
```bash
python src/train_model.py
```

---

## 🧠 Model Details

| Parameter | Value |
|-----------|-------|
| Algorithm | XGBClassifier |
| Estimators | 500 |
| Max Depth | 8 |
| Learning Rate | 0.1 |
| Subsample | 0.8 |
| Col Sample by Tree | 0.8 |
| Class Balancing | Majority downsampling (50-50) |
| Train/Test Split | 80/20 (stratified) |

### 26 Engineered URL Features

| Category | Features |
|----------|----------|
| **Length** | `url_length`, `domain_length`, `path_length` |
| **Character Counts** | `num_dots`, `num_hyphens`, `num_underscores`, `num_slashes`, `num_at`, `num_question`, `num_equals`, `num_ampersand`, `num_percent`, `num_digits` |
| **Domain** | `num_subdomains`, `has_ip_address`, `is_url_shortener` |
| **Protocol** | `has_https` |
| **Keywords** | `suspicious_keyword_count`, `has_suspicious_keyword` |
| **Patterns** | `has_double_slash`, `has_hex_encoding`, `path_depth`, `has_port`, `tld_in_path` |
| **Ratios** | `digit_ratio`, `special_char_ratio` |

---

## 📈 Evaluation Metrics

| Metric | Score |
|--------|-------|
| Accuracy | ~95%+ |
| Precision | Balanced (via downsampling) |
| Recall | Balanced (via downsampling) |
| F1 Score | High |
| ROC-AUC | High |

Visual reports generated after training:
- `reports/confusion_matrix.png`
- `reports/roc_curve.png`
- `reports/feature_importance.png`

---

## 🖼️ Screenshots

> After running `streamlit run app/app.py`, the application provides three tabs:

| Tab | Description |
|-----|-------------|
| 🔍 **URL Scanner** | Paste a URL → see verdict, risk gauge, ML confidence, signal breakdown, and screenshot preview |
| 📁 **Batch Analysis** | Upload CSV → analyze all URLs → export results as CSV/JSON/TXT |
| 📊 **Dashboard** | Verdict distribution pie chart, risk histogram, feature importances, and full scan history |

---

## ☁️ Deployment (Streamlit Cloud)

1. Push this repository to GitHub.
2. Go to [share.streamlit.io](https://share.streamlit.io).
3. Connect your GitHub repository.
4. Set the **Main file path** to: `app/app.py`
5. Click **Deploy**.

> **Note:** The `.gitignore` has been configured to include `models/*.pkl` and `reports/*.png` so Streamlit Cloud has access to the trained model at runtime.

---

## 🔮 Future Improvements

- **Deep Learning**: Experiment with LSTMs or Transformers for character-level URL classification.
- **Browser Extension**: Build a Chrome/Firefox extension for real-time browsing protection.
- **Caching**: Add Redis to cache WHOIS and SSL lookups for repeated queries.
- **SHAP Integration**: Add SHAP values for per-prediction feature attribution.
- **User Authentication**: Add login and persistent history across sessions.

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/YourFeature`)
3. Commit your changes (`git commit -m 'Add YourFeature'`)
4. Push to the branch (`git push origin feature/YourFeature`)
5. Open a Pull Request

---

## 📜 License & Author

**Author:** Naman Dugar | HCIC-SI 2026 | P16  
**License:** MIT License

---

*If you find this project useful, please consider giving it a ⭐ on GitHub!*
