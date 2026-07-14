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
    classDef input fill:#f9f9f9,stroke:#333,stroke-width:2px;
    classDef process fill:#e1f5fe,stroke:#0288d1,stroke-width:2px;
    classDef analysis fill:#fff3e0,stroke:#f57c00,stroke-width:2px;
    classDef fusion fill:#e8f5e9,stroke:#388e3c,stroke-width:2px;
    classDef safe fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px,color:#1b5e20;
    classDef suspicious fill:#ffe0b2,stroke:#f57c00,stroke-width:2px,color:#e65100;
    classDef phishing fill:#ffcdd2,stroke:#d32f2f,stroke-width:2px,color:#b71c1c;

    A[User Input URL]:::input --> B{Whitelist Check}:::process
    B -- Known Safe --> C((Verdict: SAFE)):::safe
    B -- Unknown --> D[Parallel Analysis]:::process
    
    D --> E[1. ML Model extraction]:::analysis
    D --> F[2. Live HTML Fetch]:::analysis
    D --> G[3. SSL Inspection]:::analysis
    D --> H[4. WHOIS Query]:::analysis
    
    E --> I(Risk Score Fusion):::fusion
    F --> I
    G --> I
    H --> I
    
    I --> J{Score Threshold}:::process
    J -- < 50 --> K[Safe]:::safe
    J -- 50-64 --> L[Suspicious]:::suspicious
    J -- >= 65 --> M[Phishing]:::phishing
```

## ☁️ Deployment

The application is fully containerized and compatible with Streamlit Cloud. The GitHub repository is structured so that it can be deployed directly by pointing Streamlit Community Cloud to the root entry point.

## 👤 Author

Designed and developed by **Naman Dugar**.
