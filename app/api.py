# Phishing Detector - Flask REST API
# Author: Naman Dugar | HCIC-SI 2026 | P16

import sys
import os

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT_DIR, 'src'))

from flask import Flask, request, jsonify
from predict import predict, predict_batch, get_summary

app = Flask(__name__)


@app.route('/', methods=['GET'])
def health():
    """Health-check endpoint."""
    return jsonify({
        "status": "ok",
        "service": "Phishing Detector API",
        "version": "1.0.0"
    })


@app.route('/predict', methods=['POST'])
def predict_single():
    """
    Predict phishing risk for a single URL.

    Request:  { "url": "https://example.com" }
    Response: Full result dictionary from predict().
    """
    data = request.get_json(silent=True)

    if not data or 'url' not in data:
        return jsonify({"error": "Missing 'url' in request body"}), 400

    url = data['url'].strip()

    if not url:
        return jsonify({"error": "Empty URL provided"}), 400

    result = predict(url)
    result['summary'] = get_summary(result)

    return jsonify(result)


@app.route('/predict_batch', methods=['POST'])
def predict_batch_endpoint():
    """
    Predict phishing risk for multiple URLs.

    Request:  { "urls": ["https://example.com", "http://phish.xyz"] }
    Response: List of result dictionaries.
    """
    data = request.get_json(silent=True)

    if not data or 'urls' not in data:
        return jsonify({"error": "Missing 'urls' in request body"}), 400

    urls = data['urls']

    if not isinstance(urls, list) or len(urls) == 0:
        return jsonify({"error": "'urls' must be a non-empty list"}), 400

    if len(urls) > 100:
        return jsonify({"error": "Maximum 100 URLs per batch request"}), 400

    results = predict_batch(urls)

    for r in results:
        r['summary'] = get_summary(r)

    return jsonify({"count": len(results), "results": results})


if __name__ == '__main__':
    print("\nPhishing Detector API")
    print(f"Running on http://127.0.0.1:5000\n")
    app.run(debug=True, host='0.0.0.0', port=5000)
