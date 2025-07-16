from flask import Flask, request, jsonify
import re
import tldextract
import joblib
import numpy as np
import pandas as pd

# Load model, scaler, dan top_domains
model = joblib.load('model/email_phishing_model.pkl')
top_domains = joblib.load('model/top_domains.pkl')

app = Flask(__name__)

def email_extract_features(email):
    ext = tldextract.extract(email)
    username, _, _ = email.partition('@')
    domain = (ext.domain + '.' + ext.suffix).lower()
    suffix = ext.suffix
    subdomain = ext.subdomain

    length_username = len(username)
    length_domain = len(domain)
    nb_digits_username = len(re.findall(r'\d', username))
    is_long_subdomain = 1 if len(subdomain) > 3 else 0
    is_common_domain = 1 if domain in top_domains else 0
    username_to_domain_ratio = length_username / (length_domain + 1)
    nb_digits_domain = len(re.findall(r'\d', domain))

    features = {
        'length_username': length_username,
        'length_domain': length_domain,
        'nb_digits_username': nb_digits_username,
        'is_long_subdomain': is_long_subdomain,
        'is_common_domain': is_common_domain,
        'username_to_domain_ratio': username_to_domain_ratio,
        'nb_digits_domain': nb_digits_domain,
    }

    # Data tambahan untuk output
    extra_info = {
        'domain': domain
    }
    
    return features, extra_info

def email_predict():
    data = request.get_json()

    if not data or 'email' not in data or not data['email']:
        return jsonify({'error': 'No email address provided'}), 400

    email = data['email']

    if not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
        return jsonify({'error': 'Invalid email format'}), 400
    
    features, extra_info = email_extract_features(email)

    df = pd.DataFrame([features])

    # Predict
    proba = model.predict_proba(df)[0]
    pred = model.predict(df)[0]
    label = 'phishing' if pred == 1 else 'legitimate'
    score = round(max(proba), 3)

    return jsonify({'email': email,
                    'prediction': label,
                    'confidence': score,
                    'features': features,
                    'domain': extra_info['domain']})

def email_home():
    return jsonify({"message": "Flask Email Prediction Server Aktif"}), 200