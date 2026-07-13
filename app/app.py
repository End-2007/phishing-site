# Phishing Detector - Streamlit Frontend
# Author: Naman Dugar | HCIC-SI 2026 | P16

import streamlit as st
import sys
import os
import json
import time
from datetime import datetime
from urllib.parse import urlparse

import pandas as pd
import plotly.graph_objects as go
import plotly.express as px

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT_DIR, 'src'))


@st.cache_resource(show_spinner=False)
def load_model():
    try:
        from predict import predict as _predict
        from predict import predict_batch as _predict_batch
        from predict import get_summary as _get_summary
        return _predict, _predict_batch, _get_summary, True, ""
    except Exception as e:
        return None, None, None, False, str(e)


predict_fn, predict_batch_fn, get_summary_fn, MODEL_OK, MODEL_ERR = load_model()

st.set_page_config(
    page_title="Phishing Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap');
html, body, [class*="css"] { font-family: 'Inter', sans-serif; }

@keyframes float {
    0%, 100% { transform: translateY(0px); }
    50% { transform: translateY(-12px); }
}
@keyframes float-slow {
    0%, 100% { transform: translateY(0px) rotate(0deg); }
    50% { transform: translateY(-6px) rotate(2deg); }
}
@keyframes shimmer {
    0% { background-position: -200% center; }
    100% { background-position: 200% center; }
}
@keyframes gradient-shift {
    0% { background-position: 0% 50%; }
    50% { background-position: 100% 50%; }
    100% { background-position: 0% 50%; }
}
@keyframes pulse-green {
    0%, 100% { box-shadow: 0 8px 32px rgba(5, 150, 105, 0.3), 0 0 0 0 rgba(52, 211, 153, 0.4); }
    50% { box-shadow: 0 8px 32px rgba(5, 150, 105, 0.5), 0 0 20px 4px rgba(52, 211, 153, 0.2); }
}
@keyframes pulse-red {
    0%, 100% { box-shadow: 0 8px 32px rgba(220, 38, 38, 0.3), 0 0 0 0 rgba(248, 113, 113, 0.4); }
    50% { box-shadow: 0 8px 32px rgba(220, 38, 38, 0.5), 0 0 20px 4px rgba(248, 113, 113, 0.2); }
}
@keyframes pulse-orange {
    0%, 100% { box-shadow: 0 8px 32px rgba(217, 119, 6, 0.3), 0 0 0 0 rgba(251, 191, 36, 0.4); }
    50% { box-shadow: 0 8px 32px rgba(217, 119, 6, 0.5), 0 0 20px 4px rgba(251, 191, 36, 0.2); }
}
@keyframes slide-up {
    0% { opacity: 0; transform: translateY(30px); }
    100% { opacity: 1; transform: translateY(0); }
}
@keyframes bar-fill {
    0% { width: 0%; }
}
@keyframes border-glow {
    0%, 100% { border-color: rgba(99, 102, 241, 0.3); }
    50% { border-color: rgba(99, 102, 241, 0.7); }
}
@keyframes orb-float-1 {
    0%, 100% { transform: translate(0, 0) scale(1); }
    33% { transform: translate(30px, -20px) scale(1.05); }
    66% { transform: translate(-20px, 15px) scale(0.95); }
}
@keyframes orb-float-2 {
    0%, 100% { transform: translate(0, 0) scale(1); }
    33% { transform: translate(-25px, 20px) scale(1.08); }
    66% { transform: translate(15px, -25px) scale(0.92); }
}

.app-header {
    text-align: center;
    padding: 2rem 0 1rem;
    position: relative;
    overflow: hidden;
}
.app-header::before {
    content: '';
    position: absolute;
    top: -60px; left: 20%;
    width: 200px; height: 200px;
    background: radial-gradient(circle, rgba(99, 102, 241, 0.15), transparent 70%);
    border-radius: 50%;
    animation: orb-float-1 8s ease-in-out infinite;
    pointer-events: none;
}
.app-header::after {
    content: '';
    position: absolute;
    top: -40px; right: 15%;
    width: 160px; height: 160px;
    background: radial-gradient(circle, rgba(6, 182, 212, 0.12), transparent 70%);
    border-radius: 50%;
    animation: orb-float-2 10s ease-in-out infinite;
    pointer-events: none;
}
.header-icon {
    font-size: 3.5rem;
    display: inline-block;
    animation: float 3s ease-in-out infinite;
    filter: drop-shadow(0 8px 24px rgba(99, 102, 241, 0.4));
}
.app-header h1 {
    font-size: 2.8rem;
    font-weight: 900;
    background: linear-gradient(135deg, #818cf8, #06b6d4, #a78bfa, #818cf8);
    background-size: 200% auto;
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    animation: shimmer 4s linear infinite;
    margin: 0.3rem 0 0.2rem;
    letter-spacing: -0.5px;
}
.app-header p {
    color: #64748b;
    font-size: 1.05rem;
    margin-top: 0;
}

.verdict-box {
    padding: 28px 24px;
    border-radius: 20px;
    text-align: center;
    color: white;
    font-weight: 800;
    font-size: 1.6rem;
    letter-spacing: 3px;
    transform: perspective(800px) rotateX(2deg);
    transition: transform 0.4s ease;
    position: relative;
    overflow: hidden;
}
.verdict-box::before {
    content: '';
    position: absolute;
    top: -50%; left: -50%;
    width: 200%; height: 200%;
    background: linear-gradient(45deg, transparent 30%, rgba(255,255,255,0.08) 50%, transparent 70%);
    animation: shimmer 3s linear infinite;
    pointer-events: none;
}
.verdict-box:hover {
    transform: perspective(800px) rotateX(0deg) scale(1.02);
}
.verdict-SAFE {
    background: linear-gradient(135deg, #059669, #34d399, #10b981);
    background-size: 200% 200%;
    animation: pulse-green 2s ease-in-out infinite, gradient-shift 4s ease infinite;
}
.verdict-SUSPICIOUS {
    background: linear-gradient(135deg, #d97706, #fbbf24, #f59e0b);
    background-size: 200% 200%;
    animation: pulse-orange 2s ease-in-out infinite, gradient-shift 4s ease infinite;
}
.verdict-PHISHING {
    background: linear-gradient(135deg, #dc2626, #f87171, #ef4444);
    background-size: 200% 200%;
    animation: pulse-red 2s ease-in-out infinite, gradient-shift 4s ease infinite;
}
.verdict-INVALID {
    background: linear-gradient(135deg, #475569, #94a3b8);
}
.verdict-emoji {
    font-size: 2.5rem;
    display: block;
    margin-bottom: 6px;
    filter: drop-shadow(0 4px 12px rgba(0,0,0,0.3));
}

.metric-card-3d {
    background: linear-gradient(145deg, rgba(30,41,59,0.9), rgba(51,65,85,0.7));
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border: 1px solid rgba(99, 102, 241, 0.15);
    border-radius: 18px;
    padding: 24px 16px;
    text-align: center;
    transform: perspective(600px) rotateX(2deg) rotateY(-1deg);
    transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
    box-shadow: 0 4px 6px rgba(0,0,0,0.1), 0 10px 30px rgba(0,0,0,0.2),
                inset 0 1px 0 rgba(255,255,255,0.06);
    position: relative;
    overflow: hidden;
    animation: slide-up 0.6s ease-out;
}
.metric-card-3d::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    background: linear-gradient(90deg, transparent, var(--accent-color, #6366f1), transparent);
    opacity: 0.8;
}
.metric-card-3d:hover {
    transform: perspective(600px) rotateX(0deg) rotateY(0deg) translateY(-6px) scale(1.03);
    box-shadow: 0 8px 16px rgba(0,0,0,0.15), 0 20px 50px rgba(0,0,0,0.3),
                0 0 30px rgba(99, 102, 241, 0.15), inset 0 1px 0 rgba(255,255,255,0.1);
    border-color: rgba(99, 102, 241, 0.35);
}
.metric-card-3d .value {
    font-size: 2.2rem;
    font-weight: 800;
    line-height: 1.2;
    text-shadow: 0 2px 8px rgba(0,0,0,0.3);
}
.metric-card-3d .label {
    color: #64748b;
    font-size: 0.8rem;
    margin-top: 8px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1px;
}

.signal-card-3d {
    background: linear-gradient(145deg, rgba(30,41,59,0.95), rgba(15,23,42,0.9));
    backdrop-filter: blur(16px);
    border-radius: 16px;
    padding: 20px 22px;
    margin: 12px 0;
    border: 1px solid rgba(255,255,255,0.05);
    border-left: 5px solid;
    box-shadow: 0 4px 6px rgba(0,0,0,0.1), 0 10px 30px rgba(0,0,0,0.15),
                inset 0 1px 0 rgba(255,255,255,0.04);
    transform: perspective(800px) rotateY(-1deg);
    transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
    animation: slide-up 0.5s ease-out;
}
.signal-card-3d:hover {
    transform: perspective(800px) rotateY(0deg) translateX(6px) translateZ(10px);
    box-shadow: 0 8px 16px rgba(0,0,0,0.2), 0 20px 50px rgba(0,0,0,0.25),
                inset 0 1px 0 rgba(255,255,255,0.08);
    border-left-width: 6px;
}
.signal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.signal-title { font-size: 1.05rem; font-weight: 700; color: #e2e8f0; text-shadow: 0 1px 4px rgba(0,0,0,0.2); }
.signal-score-badge {
    font-size: 0.9rem; font-weight: 800; padding: 4px 14px; border-radius: 20px;
    color: white; box-shadow: 0 2px 8px rgba(0,0,0,0.3); text-shadow: 0 1px 2px rgba(0,0,0,0.3);
}
.signal-bar-bg {
    background: rgba(15,23,42,0.8); border-radius: 6px; height: 8px;
    margin: 12px 0; overflow: hidden; box-shadow: inset 0 2px 4px rgba(0,0,0,0.3);
}
.signal-bar-fill { height: 100%; border-radius: 6px; animation: bar-fill 1s ease-out; box-shadow: 0 0 10px currentColor; }
.signal-flags { color: #94a3b8; font-size: 0.88rem; line-height: 1.8; }
.flag-warn { color: #fbbf24; }
.flag-ok   { color: #34d399; }
.flag-info { color: #60a5fa; }

.screenshot-frame {
    border: 2px solid rgba(99, 102, 241, 0.3);
    border-radius: 16px;
    overflow: hidden;
    box-shadow: 0 12px 48px rgba(0,0,0,0.4);
    transform: perspective(600px) rotateX(1deg);
    transition: all 0.4s ease;
    animation: border-glow 3s ease-in-out infinite;
}
.screenshot-frame:hover {
    transform: perspective(600px) rotateX(0deg) scale(1.01);
    box-shadow: 0 16px 56px rgba(0,0,0,0.5), 0 0 20px rgba(99, 102, 241, 0.15);
}

.stTabs [data-baseweb="tab-list"] { gap: 8px; }
.stTabs [data-baseweb="tab"] {
    padding: 12px 28px; border-radius: 12px 12px 0 0;
    font-weight: 600; font-size: 0.95rem; transition: all 0.3s ease;
}
.stTabs [data-baseweb="tab"]:hover { background: rgba(99, 102, 241, 0.1); }

section[data-testid="stSidebar"] .stMarkdown h2 {
    background: linear-gradient(135deg, #818cf8, #06b6d4);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    font-weight: 800;
}

footer { visibility: hidden; }

hr {
    border: none; height: 1px;
    background: linear-gradient(90deg, transparent, rgba(99, 102, 241, 0.3), transparent);
}
</style>
""", unsafe_allow_html=True)


# Session state defaults
for key, default in {"history": [], "_bf_id": None, "_bf_urls": [], "_bf_results": []}.items():
    if key not in st.session_state:
        st.session_state[key] = default


# Helpers

def normalize_url(url):
    url = url.strip().strip('"').strip("'")
    if url and not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    return url


def verdict_emoji(v):
    return {"SAFE": "✅", "SUSPICIOUS": "⚠️", "PHISHING": "🚨", "INVALID": "❓"}.get(v, "❓")


def signal_icon(s):
    return {"url_features": "🔗", "page_content": "📄", "ssl_certificate": "🔒", "domain_age": "🌐"}.get(s, "📌")


def signal_label(s):
    return {"url_features": "URL Features", "page_content": "Page Content",
            "ssl_certificate": "SSL Certificate", "domain_age": "Domain Age"}.get(s, s)


def score_color(s):
    if s >= 65: return "#ef4444"
    if s >= 50: return "#f59e0b"
    return "#22c55e"


def safe_style(styler, func, **kwargs):
    """Handles both old (applymap) and new (map) pandas API."""
    if hasattr(styler, 'map'):
        return styler.map(func, **kwargs)
    return styler.applymap(func, **kwargs)


def make_gauge(value):
    color = score_color(value)
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        number={"suffix": "/100", "font": {"size": 36, "color": "white", "family": "Inter"}},
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#475569",
                     "tickfont": {"color": "#64748b", "size": 11}},
            "bar": {"color": color, "thickness": 0.3},
            "bgcolor": "#1e293b",
            "borderwidth": 0,
            "steps": [
                {"range": [0, 50],  "color": "rgba(34,197,94,0.1)"},
                {"range": [50, 65], "color": "rgba(245,158,11,0.1)"},
                {"range": [65, 100],"color": "rgba(239,68,68,0.1)"},
            ],
            "threshold": {"line": {"color": color, "width": 3}, "thickness": 0.8, "value": value},
        },
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "white", "family": "Inter"},
        height=270, margin=dict(l=30, r=30, t=40, b=10),
    )
    return fig


def make_signal_chart(signals):
    labels, scores, colors = [], [], []
    for k in ["url_features", "page_content", "ssl_certificate", "domain_age"]:
        if k in signals:
            labels.append(f"{signal_icon(k)} {signal_label(k)}")
            s = signals[k]["score"]
            scores.append(s)
            colors.append(score_color(s))
    fig = go.Figure(go.Bar(
        x=scores, y=labels, orientation="h", marker_color=colors,
        text=[f"{s}/100" for s in scores], textposition="auto",
        textfont=dict(color="white", size=13, family="Inter"),
    ))
    fig.update_layout(
        title={"text": "Signal Contribution", "font": {"size": 15, "color": "#94a3b8"}},
        xaxis={"range": [0, 100], "title": "", "color": "#64748b", "gridcolor": "#1e293b",
               "showgrid": True, "zeroline": False},
        yaxis={"color": "#e2e8f0", "autorange": "reversed"},
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "white", "family": "Inter"},
        height=270, margin=dict(l=10, r=20, t=45, b=20),
    )
    return fig


def render_metric(value, label, color="white"):
    st.markdown(f"""
    <div class="metric-card-3d" style="--accent-color: {color};">
        <div class="value" style="color: {color};">{value}</div>
        <div class="label">{label}</div>
    </div>
    """, unsafe_allow_html=True)


def render_signal_card(sig_key, sig_data):
    icon = signal_icon(sig_key)
    label = signal_label(sig_key)
    s = sig_data["score"]
    color = score_color(s)

    warn_words = ["error", "failed", "could not", "fake", "suspicious", "external",
                  "mismatch", "hidden", "no https", "ip address", "self-signed",
                  "not available", "redirect", "password", "iframe", "expired"]
    ok_words = ["valid", "legitimate", "normal", "looks", "verified", "year",
                "no suspicious", "no issues"]

    flags_html = ""
    for flag in sig_data.get("flags", []):
        fl = flag.lower()
        if any(w in fl for w in warn_words):
            flags_html += f'<div class="flag-warn">⚠️ {flag}</div>'
        elif any(w in fl for w in ok_words):
            flags_html += f'<div class="flag-ok">✅ {flag}</div>'
        else:
            flags_html += f'<div class="flag-info">ℹ️ {flag}</div>'

    st.markdown(f"""
    <div class="signal-card-3d" style="border-left-color: {color};">
        <div class="signal-header">
            <span class="signal-title">{icon} {label}</span>
            <span class="signal-score-badge" style="background: {color};">{s}/100</span>
        </div>
        <div class="signal-bar-bg">
            <div class="signal-bar-fill" style="width: {s}%; background: {color}; color: {color};"></div>
        </div>
        <div class="signal-flags">{flags_html}</div>
    </div>
    """, unsafe_allow_html=True)


def add_to_history(result):
    st.session_state.history.append({
        "time": datetime.now().strftime("%H:%M:%S"),
        "url": result.get("url", ""),
        "verdict": result.get("verdict", "UNKNOWN"),
        "risk_score": result.get("risk_score", 0),
        "confidence": result.get("ml_confidence", "N/A"),
        "detection_time": result.get("detection_time", "N/A"),
    })


def find_url_column(df):
    for c in df.columns:
        if c.strip().lower() in ("url", "urls", "link", "links", "website"):
            return c
    return None


def color_verdict_cell(val):
    cmap = {"SAFE": "#166534", "SUSPICIOUS": "#92400e", "PHISHING": "#991b1b"}
    bg = cmap.get(val, "")
    return f"background-color: {bg}; color: white; font-weight: 600;" if bg else ""


# Sidebar

with st.sidebar:
    st.markdown("## 🛡️ Phishing Detector")
    st.caption("ML-powered phishing URL scanner with live 4-signal analysis.")
    st.divider()

    _sidebar_stats = st.empty()

    st.divider()
    st.markdown("**How it works**")
    st.markdown(
        "The system runs **4 parallel signals** and combines them with an "
        "**XGBoost ML model** into a weighted risk score.\n\n"
        "| Signal | Weight |\n|---|---|\n"
        "| 🧠 ML Model | 40% |\n| 📄 Page Content | 25% |\n"
        "| 🔒 SSL Cert | 20% |\n| 🌐 Domain Age | 15% |"
    )
    st.divider()
    st.caption("Built by **Naman Dugar**")
    if st.button("🗑️ Clear History"):
        st.session_state.history = []
        st.rerun()


# Header

st.markdown("""
<div class="app-header">
    <div class="header-icon">🛡️</div>
    <h1>Phishing Detector</h1>
    <p>Instantly detect phishing, malware &amp; suspicious URLs with explainable AI</p>
</div>
""", unsafe_allow_html=True)

if not MODEL_OK:
    st.error(f"Model not loaded. Run `python src/train_model.py` first.\n\nError: `{MODEL_ERR}`")
    st.stop()


# Main tabs

tab_scan, tab_batch, tab_dashboard = st.tabs([
    "🔍  URL Scanner",
    "📁  Batch Analysis",
    "📊  Dashboard & History",
])


# Tab 1: Single URL Scanner

with tab_scan:
    st.markdown("#### Paste a URL to check if it's safe or a phishing attempt")

    url_input = st.text_input(
        "Enter URL",
        placeholder="e.g.  https://example.com  or  suspicious-site.xyz/login",
        label_visibility="collapsed",
    )
    scan_clicked = st.button("🔍  Scan URL", type="primary", use_container_width=True)

    st.caption("⚡ Quick test:")
    qt1, qt2, qt3 = st.columns(3)
    quick_url = None
    with qt1:
        if st.button("✅ google.com", use_container_width=True):
            quick_url = "https://www.google.com"
    with qt2:
        if st.button("⚠️ Suspicious IP", use_container_width=True):
            quick_url = "http://192.168.1.1/bank/login"
    with qt3:
        if st.button("🚨 Phishing Sample", use_container_width=True):
            quick_url = "http://paypal-secure-login-verify.xyz/account/confirm"

    target_url = None
    if scan_clicked and url_input:
        target_url = url_input
    elif quick_url:
        target_url = quick_url

    if target_url:
        target_url = normalize_url(target_url)

        with st.status("🔍 Analyzing URL …", expanded=True) as status:
            st.write("🔗 Normalizing URL …")
            time.sleep(0.2)
            st.write("🧠 Running ML model + live 4-signal analysis …")
            st.write("&nbsp;&nbsp;&nbsp; ⚡ URL feature extraction", unsafe_allow_html=True)
            st.write("&nbsp;&nbsp;&nbsp; 📄 Fetching live page content", unsafe_allow_html=True)
            st.write("&nbsp;&nbsp;&nbsp; 🔒 Checking SSL certificate", unsafe_allow_html=True)
            st.write("&nbsp;&nbsp;&nbsp; 🌐 WHOIS domain age lookup", unsafe_allow_html=True)
            result = predict_fn(target_url)
            v = result.get("verdict", "UNKNOWN")
            status.update(label=f"{verdict_emoji(v)} Analysis complete — {v}", state="complete")

        add_to_history(result)
        st.divider()

        risk = result["risk_score"]
        conf = result.get("ml_confidence", "N/A")
        det_time = result.get("detection_time", "N/A")

        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.markdown(f"""
            <div class="verdict-box verdict-{v}">
                <span class="verdict-emoji">{verdict_emoji(v)}</span>
                {v}
            </div>
            """, unsafe_allow_html=True)
        with m2:
            render_metric(f"{risk}/100", "Risk Score", score_color(risk))
        with m3:
            render_metric(conf, "ML Confidence", "#818cf8")
        with m4:
            render_metric(det_time, "Detection Time", "#06b6d4")

        st.markdown("<br>", unsafe_allow_html=True)

        ch1, ch2 = st.columns(2)
        with ch1:
            st.plotly_chart(make_gauge(risk), key="gauge_single")
        with ch2:
            if "signals" in result:
                st.plotly_chart(make_signal_chart(result["signals"]), key="sig_chart_single")

        # Signal breakdown (explainable AI)
        st.markdown("#### 🧠 Explainable AI — Why this verdict?")
        signals = result.get("signals", {})
        s1, s2 = st.columns(2)
        for idx, sk in enumerate(["url_features", "page_content", "ssl_certificate", "domain_age"]):
            if sk in signals:
                with (s1 if idx % 2 == 0 else s2):
                    render_signal_card(sk, signals[sk])

        st.markdown("#### 🖼️ Website Preview")
        try:
            thumb = f"https://image.thum.io/get/width/800/{result['url']}"
            st.markdown('<div class="screenshot-frame">', unsafe_allow_html=True)
            st.image(thumb, caption=f"Live preview of {result['url']}", width="stretch")
            st.markdown('</div>', unsafe_allow_html=True)
        except Exception:
            st.info("Screenshot preview is not available for this URL.")

    elif scan_clicked and not url_input:
        st.warning("Please enter a URL to scan.")


# Tab 2: Batch Analysis (uses @st.fragment to prevent page reloads during processing)

with tab_batch:

    @st.fragment
    def batch_analysis_fragment():
        st.markdown("#### 📁 Upload a CSV file with URLs")
        st.caption(
            "Your CSV must have a column named **url**, **URL**, **link**, or **website**. "
            "All URLs will be processed — no limit."
        )

        uploaded = st.file_uploader("Choose CSV file", type=["csv"], key="batch_csv_upload")

        if uploaded is None:
            st.session_state._bf_id = None
            st.session_state._bf_urls = []
            st.session_state._bf_results = []
            return

        # Parse file once and cache in session state
        file_id = f"{uploaded.name}_{uploaded.size}"
        if st.session_state.get("_bf_id") != file_id:
            try:
                df = pd.read_csv(uploaded)
            except Exception as e:
                st.error(f"Could not read CSV: {e}")
                return
            url_col = find_url_column(df)
            if url_col is None:
                st.error("No URL column found. Ensure your CSV has a column named **url**, **link**, or **website**.")
                return
            urls = df[url_col].dropna().astype(str).str.strip().tolist()
            urls = [u for u in urls if len(u) >= 4]
            st.session_state._bf_id = file_id
            st.session_state._bf_urls = urls
            st.session_state._bf_results = []

        urls = st.session_state._bf_urls
        results = st.session_state._bf_results
        total = len(urls)
        done = len(results)

        if total == 0:
            st.warning("No valid URLs found in the uploaded file.")
            return

        if done == 0:
            st.success(f"📋 Found **{total}** URLs ready for analysis")
        elif done < total:
            st.info(f"📋 **{done}/{total}** URLs analyzed. Click below to continue.")
        else:
            st.success(f"✅ All **{total}** URLs analyzed!")

        # Process remaining URLs
        if done < total:
            btn_label = "🚀  Analyze All URLs" if done == 0 else f"▶️  Continue ({total - done} remaining)"
            if st.button(btn_label, type="primary", use_container_width=True, key="batch_go"):
                progress = st.progress(done / total, text=f"Starting from URL {done + 1} …")
                status_line = st.empty()

                for i in range(done, total):
                    url = normalize_url(urls[i])
                    try:
                        r = predict_fn(url)
                        row = {
                            "url": r.get("url", url),
                            "verdict": r.get("verdict", "ERROR"),
                            "risk_score": r.get("risk_score", 0),
                            "confidence": r.get("ml_confidence", "N/A"),
                            "time": r.get("detection_time", "N/A"),
                        }
                    except Exception:
                        row = {"url": url, "verdict": "ERROR", "risk_score": 0,
                               "confidence": "N/A", "time": "N/A"}

                    st.session_state._bf_results.append(row)
                    add_to_history({"url": row["url"], "verdict": row["verdict"],
                                    "risk_score": row["risk_score"],
                                    "ml_confidence": row["confidence"],
                                    "detection_time": row["time"]})

                    progress.progress(
                        (i + 1) / total,
                        text=f"✅ {i + 1}/{total}  —  {row['verdict']}: {row['url'][:50]}"
                    )
                    status_line.caption(f"⏱️ {row['time']}")

                progress.progress(1.0, text=f"✅ Batch complete! Analyzed {total} URLs.")
                time.sleep(0.5)
                st.rerun(scope="fragment")

        # Display results
        if results:
            st.divider()

            df_res = pd.DataFrame(results)
            bc1, bc2, bc3, bc4 = st.columns(4)
            with bc1: render_metric(len(df_res), "Total URLs", "white")
            with bc2: render_metric(int((df_res["verdict"] == "SAFE").sum()), "Safe ✅", "#22c55e")
            with bc3: render_metric(int((df_res["verdict"] == "SUSPICIOUS").sum()), "Suspicious ⚠️", "#f59e0b")
            with bc4: render_metric(int((df_res["verdict"] == "PHISHING").sum()), "Phishing 🚨", "#ef4444")

            st.markdown("")
            styled = safe_style(df_res.style, color_verdict_cell, subset=["verdict"])
            st.dataframe(styled, height=400)

            st.markdown("##### 📥 Export Results")
            ex1, ex2, ex3 = st.columns(3)
            with ex1:
                st.download_button("⬇️ CSV", data=df_res.to_csv(index=False),
                                   file_name="phishing_results.csv", mime="text/csv", key="dl_csv")
            with ex2:
                st.download_button("⬇️ JSON", data=json.dumps(results, indent=2),
                                   file_name="phishing_results.json", mime="application/json", key="dl_json")
            with ex3:
                report = f"PHISHING DETECTION REPORT\nGenerated: {datetime.now()}\n{'='*50}\n\n"
                for r in results:
                    report += f"URL: {r['url']}\nVerdict: {r['verdict']} | Risk: {r['risk_score']}/100 | Conf: {r['confidence']}\n{'-'*50}\n"
                st.download_button("⬇️ Report (.txt)", data=report,
                                   file_name="phishing_report.txt", mime="text/plain", key="dl_txt")

    batch_analysis_fragment()


# Tab 3: Dashboard and History

with tab_dashboard:
    st.markdown("#### 📊 Analytics Dashboard")
    history = st.session_state.history

    if not history:
        st.info("No scans yet. Use the **URL Scanner** or **Batch Analysis** tab to start scanning!")
    else:
        df_hist = pd.DataFrame(history)

        d1, d2, d3, d4 = st.columns(4)
        with d1: render_metric(len(df_hist), "Total Scans", "white")
        with d2: render_metric(int((df_hist["verdict"] == "SAFE").sum()), "Safe URLs", "#22c55e")
        with d3: render_metric(int((df_hist["verdict"] == "PHISHING").sum()), "Threats Found", "#ef4444")
        avg_risk = df_hist["risk_score"].mean()
        with d4: render_metric(f"{avg_risk:.1f}", "Avg Risk Score", score_color(int(avg_risk)))

        st.markdown("<br>", unsafe_allow_html=True)

        chart1, chart2 = st.columns(2)
        with chart1:
            vc = df_hist["verdict"].value_counts()
            cmap = {"SAFE": "#22c55e", "SUSPICIOUS": "#f59e0b", "PHISHING": "#ef4444", "INVALID": "#94a3b8"}
            fig_pie = px.pie(names=vc.index, values=vc.values, title="Verdict Distribution",
                             color=vc.index, color_discrete_map=cmap, hole=0.5)
            fig_pie.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font={"color": "#94a3b8", "family": "Inter"},
                height=350, margin=dict(l=20, r=20, t=50, b=20),
            )
            st.plotly_chart(fig_pie)

        with chart2:
            fig_hist = px.histogram(df_hist, x="risk_score", nbins=20, title="Risk Score Distribution",
                                    color_discrete_sequence=["#818cf8"])
            fig_hist.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font={"color": "#94a3b8", "family": "Inter"},
                xaxis={"title": "Risk Score", "color": "#94a3b8", "gridcolor": "#1e293b"},
                yaxis={"title": "Count", "color": "#94a3b8", "gridcolor": "#1e293b"},
                height=350, margin=dict(l=20, r=20, t=50, b=30),
            )
            st.plotly_chart(fig_hist)

        # Feature importance from trained model
        st.markdown("#### 🧠 Model Feature Importances")
        try:
            import joblib
            _model = joblib.load(os.path.join(ROOT_DIR, "models", "phishing_model.pkl"))
            _fnames = joblib.load(os.path.join(ROOT_DIR, "models", "feature_names.pkl"))
            imp = pd.Series(_model.feature_importances_, index=_fnames).sort_values(ascending=False).head(15)
            fig_imp = go.Figure(go.Bar(
                x=imp.values, y=imp.index, orientation="h",
                marker=dict(color=imp.values, colorscale=[[0, "#6366f1"], [1, "#06b6d4"]]),
                text=[f"{v:.3f}" for v in imp.values],
                textposition="auto", textfont=dict(color="white", size=12),
            ))
            fig_imp.update_layout(
                title={"text": "Top 15 Feature Importances (XGBoost)", "font": {"color": "#94a3b8"}},
                xaxis={"title": "Importance", "color": "#64748b", "gridcolor": "#1e293b"},
                yaxis={"color": "#94a3b8", "autorange": "reversed"},
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font={"color": "white", "family": "Inter"},
                height=420, margin=dict(l=10, r=20, t=45, b=30),
            )
            st.plotly_chart(fig_imp)
        except Exception:
            feat_img = os.path.join(ROOT_DIR, "reports", "feature_importance.png")
            if os.path.exists(feat_img):
                st.image(feat_img, caption="Top Feature Importances")

        st.markdown("#### 📜 Full Scan History")
        display_df = df_hist[::-1].reset_index(drop=True)
        styled_hist = safe_style(display_df.style, color_verdict_cell, subset=["verdict"])
        st.dataframe(styled_hist, height=350)

        st.download_button("⬇️ Export History (CSV)", data=df_hist.to_csv(index=False),
                           file_name="scan_history.csv", mime="text/csv", key="dl_history")


# Deferred sidebar stats (renders after all tabs, so counts are always current)
with _sidebar_stats.container():
    total = len(st.session_state.history)
    safe_n = sum(1 for h in st.session_state.history if h["verdict"] == "SAFE")
    phish_n = sum(1 for h in st.session_state.history if h["verdict"] == "PHISHING")
    susp_n = sum(1 for h in st.session_state.history if h["verdict"] == "SUSPICIOUS")

    st.metric("Total Scans", total)
    ca, cb, cc = st.columns(3)
    ca.metric("✅ Safe", safe_n)
    cb.metric("⚠️ Susp.", susp_n)
    cc.metric("🚨 Phish", phish_n)
