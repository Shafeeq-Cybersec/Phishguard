import os
import sys

from flask import Flask, jsonify, render_template, request

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from model.predict import get_metadata, scan_url, warmup

app = Flask(__name__)
app.json.sort_keys = False
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

MAX_URL_LENGTH = 2048

warmup()


@app.route("/model")
def model_details():
    return render_template("model.html")


@app.route("/")
def index():
    try:
        return render_template("index.html")
    except Exception:
        return "PhishGuard backend is running.", 200


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "model_loaded": True})


@app.route("/api/stats")
def stats():
    return jsonify(get_metadata())


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Request body must be JSON like {\"url\": \"...\"}"}), 400

    url = data.get("url")
    if not isinstance(url, str) or not url.strip():
        return jsonify({"error": "Field 'url' is required and must be a non-empty string."}), 400
    url = url.strip()
    if len(url) > MAX_URL_LENGTH:
        return jsonify({"error": f"URL too long (max {MAX_URL_LENGTH} characters)."}), 400

    try:
        result = scan_url(url)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        app.logger.exception("scan failed for url=%r", url)
        return jsonify({"error": "Internal error while scanning the URL."}), 500

    return jsonify(result), 200


@app.errorhandler(404)
def not_found(_):
    return jsonify({"error": "Not found."}), 404


@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": "Request body too large."}), 413


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
