from flask import Flask, jsonify, request
from flask_cors import CORS

# Import endpoint handler dari modul lain
from api_url import (
    url_predict,
    url_predict_batch,
    url_model_info_endpoint,
    url_debug_url,
    load_model_url
)
from api_email import email_predict, email_home
from api_llm import llm_analyzer, llm_home

app = Flask(__name__)
CORS(app)

@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Unified API Aktif"}), 200

# Endpoint untuk URL Phishing Detection
@app.route("/url-predict", methods=["POST"])
def predict_url_route():
    return url_predict()

@app.route("/url-predict/batch", methods=["POST"])
def predict_url_batch_route():
    return url_predict_batch()

@app.route("/url-model/info", methods=["GET"])
def url_model_info_route():
    return url_model_info_endpoint()

@app.route("/url-debug", methods=["POST"])
def url_debug_route():
    return url_debug_url()

# Endpoint untuk Email Phishing Detection
@app.route("/email", methods=["GET"])
def email_index():
    return email_home()

@app.route("/email-predict", methods=["POST"])
def predict_email():
    return email_predict()
    
# Endpoint untuk LLM Insight
@app.route("/llm", methods=["GET"])
def llm_index():
    return llm_home()

@app.route("/llm-analyzer", methods=["POST"])
def analyze_with_llm():
    return llm_analyzer()

if __name__ == "__main__":
    load_model_url()
    app.run(host="0.0.0.0", port=8080, debug=True)
