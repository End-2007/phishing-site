# 🛡️ Phishing Detector

An explainable, machine-learning-based system for real-time detection of phishing and malicious URLs. 

Phishing Detector moves beyond traditional, reactive blacklists by evaluating the structural, behavioral, and infrastructural characteristics of a website in real time. Built with an XGBoost classifier and a live four-signal analysis engine, the system delivers highly accurate verdicts (**Safe**, **Suspicious**, or **Phishing**) along with a plain-language explanation of why a URL was flagged.

## 🚀 Core Innovation

Instead of relying on a single model score, this system uses a hybrid ensemble approach. An ML model evaluates the URL string, while three independent concurrent workers inspect the live website.

The final risk score is a weighted fusion of four signals:

| 🚥 Signal | ⚖️ Weight | 🔍 What it analyzes |
|:---|:---:|:---|
| **🧠 Machine Learning Model** | **40%** | An XGBoost classifier trained on over 650,000 labeled URLs. It evaluates 26 structural features of the URL itself, such as length, character distribution, and suspicious keywords. |
| **📄 Live Page Content** | **25%** | Fetches the live webpage and analyzes its HTML for deceptive practices, such as external form submissions, hidden iframes, and excessive redirects. |
| **🔒 SSL Certificate** | **20%** | The site's TLS certificate is evaluated for issuer trust, domain mismatch, and issuance age. |
| **🌐 Domain Age** | **15%** | Queries the WHOIS registration record, targeting short-lived domains commonly used in phishing campaigns. |

## ✨ Key Features

- **Explainable AI**: The system doesn't just output a risk score. It provides a signal-by-signal breakdown with human-readable flags, making the decision process transparent to non-technical users.
- **Resilient Batch Processing**: Organizations can upload CSV files containing thousands of URLs. The system processes them concurrently and maintains state, allowing for pauses and resumptions without data loss.
- **Analytics Dashboard**: A built-in visualization suite tracks scan history, verdict distributions, risk score histograms, and dynamic feature importance charts.
- **Dynamic 3D Interface**: The frontend is designed with a modern, responsive glassmorphism UI, featuring interactive metric cards, animated progress indicators, and live website screenshot previews.

## 🏗️ Architecture

The system is designed for speed and modularity. The pipeline allows the heavy network-bound live checks to run concurrently while the ML model processes the URL instantly.

```mermaid
graph TD
    %% Styling
    classDef input fill:#e3f2fd,stroke:#1565c0,stroke-width:2px;
    classDef process fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px;
    classDef analysis fill:#fff8e1,stroke:#f57c00,stroke-width:2px;
    classDef fusion fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
    classDef safe fill:#c8e6c9,stroke:#1b5e20,stroke-width:2px;
    classDef suspicious fill:#ffe0b2,stroke:#e65100,stroke-width:2px;
    classDef phishing fill:#ffcdd2,stroke:#b71c1c,stroke-width:2px;

    A["<font color='black'>User Input URL</font>"]:::input --> B{"<font color='black'>Whitelist Check</font>"}:::process
    B -- Known Safe --> C(("<font color='black'>Verdict: SAFE</font>")):::safe
    B -- Unknown --> D["<font color='black'>Parallel Analysis</font>"]:::process
    
    D --> E["<font color='black'>1. ML Model extraction</font>"]:::analysis
    D --> F["<font color='black'>2. Live HTML Fetch</font>"]:::analysis
    D --> G["<font color='black'>3. SSL Inspection</font>"]:::analysis
    D --> H["<font color='black'>4. WHOIS Query</font>"]:::analysis
    
    E --> I("<font color='black'>Risk Score Fusion</font>"):::fusion
    F --> I
    G --> I
    H --> I
    
    I --> J{"<font color='black'>Score Threshold</font>"}:::process
    J -- < 50 --> K["<font color='black'>Safe</font>"]:::safe
    J -- 50-64 --> L["<font color='black'>Suspicious</font>"]:::suspicious
    J -- >= 65 --> M["<font color='black'>Phishing</font>"]:::phishing
```

## ☁️ Deployment

The application is fully containerized and compatible with Streamlit Cloud. The GitHub repository is structured so that it can be deployed directly by pointing Streamlit Community Cloud to the root entry point.

## 👤 Author

Designed and developed by **Naman Dugar**.
