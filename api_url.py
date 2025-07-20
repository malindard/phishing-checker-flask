from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pickle
import pandas as pd
import numpy as np
import re
import urllib
import requests
import tldextract
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import logging
from datetime import datetime

from url_nameserver_scrape import get_nameservers

from url_feature_extractor import (
    url_length as fe_url_length, 
    get_domain as fe_get_domain, 
    having_ip_address as fe_having_ip_address, 
    count_dots as fe_count_dots, 
    count_exclamination as fe_count_exclamination,
    count_equal as fe_count_equal, 
    count_slash as fe_count_slash, 
    check_www as fe_check_www, 
    ratio_digits as fe_ratio_digits, 
    tld_in_subdomain as fe_tld_in_subdomain,
    prefix_suffix as fe_prefix_suffix, 
    shortest_word_length as fe_shortest_word_length, 
    longest_word_length as fe_longest_word_length, 
    phish_hints as fe_phish_hints,
    is_URL_accessible as fe_is_URL_accessible, 
    extract_data_from_URL as fe_extract_data_from_URL, 
    h_total as fe_h_total, 
    internal_hyperlinks as fe_internal_hyperlinks,
    empty_title as fe_empty_title, 
    domain_in_title as fe_domain_in_title, 
    domain_age as fe_domain_age, 
    google_index as fe_google_index, 
    page_rank as fe_page_rank,
    words_raw_extraction as fe_words_raw_extraction, 
    HINTS as FE_HINTS
)

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global variables for model and components
model = None
scaler = None
features = None
model_info = None

def convert_numpy_types(obj):
    """Convert numpy types to Python native types for JSON serialization"""
    if isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {key: convert_numpy_types(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_numpy_types(item) for item in obj]
    else:
        return obj

def load_model_url():
    """Load the saved model and related components"""
    global model, scaler, features, model_info
    
    try:
        # Load the model
        model = joblib.load('model/url_phishing_model.pkl')
        logger.info("✓ Model loaded successfully")
        
        # Load the scaler
        scaler = joblib.load('model/scaler.pkl')
        logger.info("✓ Scaler loaded successfully")
        
        # Load the features
        with open('model/selected_features.pkl', 'rb') as f:
            features = pickle.load(f)
        logger.info("✓ Features loaded successfully")
        
        # Load model info
        with open('model/model_info.pkl', 'rb') as f:
            model_info = pickle.load(f)
        logger.info("✓ Model info loaded successfully")
        
        return True
        
    except FileNotFoundError as e:
        logger.error(f"❌ Error: {e}")
        logger.error("Make sure you have the following files:")
        logger.error("- url_phishing_model.pkl")
        logger.error("- scaler.pkl")
        logger.error("- selected_features.pkl")
        logger.error("- model_info.pkl")
        return False

def extract_features_from_url(url):
    """Extract features from a URL using functions from feature_extractor.py"""
    logger.info(f"Extracting features from: {url}")
    
    # Basic URL parsing using feature_extractor functions
    hostname, domain, path = fe_get_domain(url)
    extracted_domain = tldextract.extract(url)
    domain_name = extracted_domain.domain + '.' + extracted_domain.suffix
    subdomain = extracted_domain.subdomain
    tld = extracted_domain.suffix
    
    # Extract words using feature_extractor function
    words_raw, words_raw_host, words_raw_path = fe_words_raw_extraction(
        extracted_domain.domain, subdomain, path
    )
    
    # Initialize features dictionary
    features_dict = {}
    
    # Extract basic features using feature_extractor functions
    features_dict['length_url'] = fe_url_length(url)
    features_dict['length_hostname'] = len(hostname) if hostname else 0
    features_dict['ip'] = fe_having_ip_address(url)
    features_dict['nb_dots'] = fe_count_dots(hostname) if hostname else 0
    features_dict['nb_qm'] = fe_count_exclamination(url)
    features_dict['nb_eq'] = fe_count_equal(url)
    features_dict['nb_slash'] = fe_count_slash(url)
    features_dict['nb_www'] = fe_check_www(words_raw)
    features_dict['ratio_digits_url'] = fe_ratio_digits(url)
    features_dict['ratio_digits_host'] = fe_ratio_digits(hostname) if hostname else 0
    features_dict['tld_in_subdomain'] = fe_tld_in_subdomain(tld, subdomain)
    features_dict['prefix_suffix'] = fe_prefix_suffix(hostname) if hostname else 0
    features_dict['shortest_word_host'] = fe_shortest_word_length(words_raw_host)
    features_dict['longest_words_raw'] = fe_longest_word_length(words_raw)
    features_dict['longest_word_path'] = fe_longest_word_length(words_raw_path)
    features_dict['phish_hints'] = fe_phish_hints(url)

    
    
    # Try to access URL for additional features
    state, url_accessible, page = fe_is_URL_accessible(url)
    extracted_content = {}
    
    if state and page:
        try:
            content = page.content
            
            # Handle different content types and encodings
            if not content or len(content) == 0:
                logger.warning(f"Empty content received for URL: {url}")
                extracted_content = {
                    'body': [],
                    'heads': [],
                    'titles': [],
                    'scripts': [],
                    'error': 'Empty content received'
                }
            else:
                # Try different encodings if the default fails
                try:
                    soup = BeautifulSoup(content, 'html.parser')
                except Exception as e:
                    logger.warning(f"Failed to parse with default encoding for {url}: {e}")
                    try:
                        # Try with different encoding
                        soup = BeautifulSoup(content, 'html.parser', from_encoding='utf-8')
                    except Exception as e2:
                        logger.warning(f"Failed to parse with UTF-8 encoding for {url}: {e2}")
                        try:
                            # Try with latin-1 encoding
                            soup = BeautifulSoup(content, 'html.parser', from_encoding='latin-1')
                        except Exception as e3:
                            logger.error(f"Failed to parse content for {url} with all encodings: {e3}")
                            soup = None
                
                if soup:
                    # Extract content with error handling
                    try:
                        extracted_content['body'] = [str(body) for body in soup.find_all('p')]
                    except Exception as e:
                        logger.warning(f"Error extracting body from {url}: {e}")
                        extracted_content['body'] = []
                    
                    try:
                        extracted_content['heads'] = [str(head) for head in soup.find_all('head')]
                    except Exception as e:
                        logger.warning(f"Error extracting heads from {url}: {e}")
                        extracted_content['heads'] = []
                    
                    try:
                        extracted_content['titles'] = [title.get_text() for title in soup.find_all('title')]
                    except Exception as e:
                        logger.warning(f"Error extracting titles from {url}: {e}")
                        extracted_content['titles'] = []
                    
                    try:
                        extracted_content['scripts'] = [script.get_text() for script in soup.find_all('script')]
                    except Exception as e:
                        logger.warning(f"Error extracting scripts from {url}: {e}")
                        extracted_content['scripts'] = []
                else:
                    extracted_content = {
                        'body': [],
                        'heads': [],
                        'titles': [],
                        'scripts': [],
                        'error': 'Failed to parse HTML content'
                    }
                
                # Initialize data structures for extract_data_from_URL
                Href = {'internals': [], 'externals': [], 'null': []}
                Link = {'internals': [], 'externals': [], 'null': []}
                Anchor = {'safe': [], 'unsafe': [], 'null': []}
                Media = {'internals': [], 'externals': [], 'null': []}
                Form = {'internals': [], 'externals': [], 'null': []}
                CSS = {'internals': [], 'externals': [], 'null': []}
                Favicon = {'internals': [], 'externals': [], 'null': []}
                IFrame = {'visible': [], 'invisible': [], 'null': []}
                Title = ''
                Text = ''
                Body = ''
                
                # Extract data using feature_extractor function
                try:
                    Href, Link, Anchor, Media, Form, CSS, Favicon, IFrame, Title, Text, Body = fe_extract_data_from_URL(
                        hostname, content, domain_name, Href, Link, Anchor, Media, Form, CSS, Favicon, IFrame, Title, Text, Body
                    )
                except Exception as e:
                    logger.warning(f"Error in extract_data_from_URL for {url}: {e}")
                    # Keep default empty values
                
                features_dict['nb_hyperlinks'] = fe_h_total(Href, Link, Media, Form, CSS, Favicon)
                features_dict['ratio_intHyperlinks'] = fe_internal_hyperlinks(Href, Link, Media, Form, CSS, Favicon)
                features_dict['empty_title'] = fe_empty_title(Title)
                features_dict['domain_in_title'] = fe_domain_in_title(domain_name, Title)
                
        except Exception as e:
            logger.error(f"Error processing content for {url}: {e}")
            extracted_content = {
                'body': [],
                'heads': [],
                'titles': [],
                'scripts': [],
                'error': f'Content processing error: {str(e)}'
            }
            # Set default values for features
            features_dict['nb_hyperlinks'] = 1
            features_dict['ratio_intHyperlinks'] = 0.5
            features_dict['empty_title'] = 0
            features_dict['domain_in_title'] = 0
    else:
        # Default values if URL is not accessible - use more neutral values
        features_dict['nb_hyperlinks'] = 1  # Assume at least one hyperlink
        features_dict['ratio_intHyperlinks'] = 0.5  # Neutral ratio
        features_dict['empty_title'] = 0  # Assume title exists
        features_dict['domain_in_title'] = 0  # Assume domain is in title
    
    # Additional features using feature_extractor functions
    features_dict['domain_age'] = fe_domain_age(domain_name)
    features_dict['google_index'] = fe_google_index(url)
    features_dict['page_rank'] = fe_page_rank('g08gow00ok4c4o0wocko8kkkok040okcsg0k0oso', domain_name)
    
    return features_dict, extracted_content, domain_name

def url_predict_phishing(url_features):
    """
    Predict if a URL is phishing or legitimate
    
    Args:
        url_features: Dictionary with extracted features
    
    Returns:
        prediction: 1 for phishing, 0 for legitimate
        probability: Probability of being phishing
    """
    global model, scaler, features
    
    if model is None:
        raise Exception("Model not loaded")
    
    # Create DataFrame with only the required features
    feature_df = pd.DataFrame([url_features])
    
    # Select only the features used by the model
    X = feature_df[features]
    
    # Scale the features
    X_scaled = scaler.transform(X)
    
    # Make prediction
    prediction = model.predict(X_scaled)[0]
    probability = model.predict_proba(X_scaled)[0][1]  # Probability of phishing
    
    return prediction, probability

def url_predict():
    """Main prediction endpoint"""
    try:
        # Get JSON data from request
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'error': 'URL is required',
                'status': 'error'
            }), 400
        
        url = data['url'].strip()
        
        if not url:
            return jsonify({
                'error': 'URL cannot be empty',
                'status': 'error'
            }), 400
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url  # Try HTTPS first for better compatibility

        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            return jsonify({
                'error': 'Invalid URL format',
                'status': 'error',
                'timestamp': datetime.now().isoformat()
            }), 400

        # Try to normalize the URL properly
        original_url = url
        if not hostname.startswith('www.'):
            parts = hostname.split('.')
            if len(parts) == 2 or (len(parts) == 3 and parts[1] in ['co', 'com', 'net', 'org', 'gov', 'edu']):
                url = parsed._replace(netloc='www.' + hostname).geturl()
        
        # Test if the normalized URL works, if not, try the original
        try:
            test_response = requests.head(url, timeout=5, allow_redirects=True)
            if test_response.status_code >= 400:
                # If normalized URL fails, try original without www
                url = original_url
        except:
            # If there's any error, use the original URL
            url = original_url
        
        # Extract features
        url_features, extracted_content, domain_name = extract_features_from_url(url)
        
        # Add debugging information
        logger.info(f"URL processed: {url}")
        logger.info(f"Domain: {domain_name}")
        logger.info(f"URL accessible: {extracted_content.get('error') is None}")
        logger.info(f"Key features: nb_hyperlinks={url_features.get('nb_hyperlinks')}, empty_title={url_features.get('empty_title')}, domain_in_title={url_features.get('domain_in_title')}")
        
        # Make prediction
        prediction, probability = url_predict_phishing(url_features)
        
        # Prepare response
        result = "phishing" if prediction == 1 else "legitimate"
        confidence = probability if prediction == 1 else (1 - probability)
        # extracted_domain = tldextract.extract(url)
        # domain_name = extracted_domain.domain + '.'+ extracted_domain.suffix
        nameservers = get_nameservers(url)
        
        response = {
            'url': url,
            'prediction': result,
            'confidence': round(float(confidence), 4),
            'domain': domain_name,
            'nameservers': nameservers,
            'phishing_probability': round(float(probability), 4),
            'timestamp': datetime.now().isoformat(),
            'features': {
                'length_url': int(url_features.get('length_url', 0)),
                'ip_address': bool(url_features.get('ip', 0)),
                'nb_dots': int(url_features.get('nb_dots', 0)),
                'phish_hints': int(url_features.get('phish_hints', 0)),
                'nb_hyperlinks': int(url_features.get('nb_hyperlinks', 0)),
                'empty_title': bool(url_features.get('empty_title', 1))
            },
            'extracted_content': extracted_content,
            'status': 'success'
        }
        
        # Convert any remaining numpy types to Python native types
        response = convert_numpy_types(response)
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error in prediction: {str(e)}")
        return jsonify({
            'error': f'Prediction failed: {str(e)}',
            'status': 'error',
            'timestamp': datetime.now().isoformat()
        }), 500
    
def url_predict_batch():
    """Batch prediction endpoint for multiple URLs"""
    try:
        # Get JSON data from request
        data = request.get_json()
        
        if not data or 'urls' not in data:
            return jsonify({
                'error': 'URLs array is required',
                'status': 'error'
            }), 400
        
        urls = data['urls']
        
        if not isinstance(urls, list):
            return jsonify({
                'error': 'URLs must be an array',
                'status': 'error'
            }), 400
        
        if len(urls) > 100:  # Limit batch size
            return jsonify({
                'error': 'Maximum 100 URLs allowed per batch',
                'status': 'error'
            }), 400
        
        results = []
        
        for url in urls:
            try:
                url = url.strip()
                
                if not url:
                    results.append({
                        'url': url,
                        'error': 'URL is empty',
                        'status': 'error'
                    })
                    continue
                
                # Add protocol if missing
                if not url.startswith(('http://', 'https://')):
                    url = 'http://' + url
                
                # Extract features
                #url_features = extract_features_from_url(url)
                features_dict, extracted_content, domain_name = extract_features_from_url(url)
                
                # Make prediction
                prediction, probability = url_predict_phishing(features_dict)
                
                # Prepare result
                result = "phishing" if prediction == 1 else "legitimate"
                confidence = probability if prediction == 1 else (1 - probability)
                nameservers = get_nameservers(url)
                
                results.append({
                    'url': url,
                    'prediction': result,
                    'nameservers': nameservers,
                    'confidence': round(float(confidence), 4),
                    'phishing_probability': round(float(probability), 4),
                    'status': 'success'
                })
                
            except Exception as e:
                results.append({
                    'url': url,
                    'error': str(e),
                    'status': 'error'
                })
        
        response = {
            'results': results,
            'total_urls': len(urls),
            'timestamp': datetime.now().isoformat(),
            'status': 'success'
        }
        
        # Convert any remaining numpy types to Python native types
        response = convert_numpy_types(response)
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error in batch prediction: {str(e)}")
        return jsonify({
            'error': f'Batch prediction failed: {str(e)}',
            'status': 'error',
            'timestamp': datetime.now().isoformat()
        }), 500
    
def url_model_info_endpoint():
    """Get model information"""
    global model_info
    
    if model_info is None:
        return jsonify({
            'error': 'Model not loaded',
            'status': 'error'
        }), 500
    
    response = {
        'model_type': model_info.get('model_type', 'Unknown'),
        'feature_count': model_info.get('feature_count', 0),
        'features': model_info.get('features', []),
        'accuracy': model_info.get('accuracy', 0),
        'training_samples': model_info.get('training_samples', 0),
        'test_samples': model_info.get('test_samples', 0),
        'model_parameters': model_info.get('model_parameters', {}),
        'status': 'success'
    }
    
    # Convert any remaining numpy types to Python native types
    response = convert_numpy_types(response)
    
    return jsonify(response)

def url_debug_url():
    """Debug endpoint to analyze URL extraction issues"""
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'error': 'URL is required',
                'status': 'error'
            }), 400
        
        url = data['url'].strip()
        
        if not url:
            return jsonify({
                'error': 'URL cannot be empty',
                'status': 'error'
            }), 400
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        debug_info = {
            'original_url': data['url'],
            'processed_url': url,
            'url_accessible': False,
            'content_length': 0,
            'parsing_success': False,
            'extracted_elements': {},
            'errors': []
        }
        
        # Test URL accessibility
        try:
            state, url_accessible, page = fe_is_URL_accessible(url)
            debug_info['url_accessible'] = state
            debug_info['final_url'] = url_accessible
            
            if state and page:
                debug_info['content_length'] = len(page.content)
                debug_info['status_code'] = page.status_code
                debug_info['content_type'] = page.headers.get('content-type', 'unknown')
                debug_info['response_headers'] = dict(page.headers)
                
                # Try to parse content
                try:
                    soup = BeautifulSoup(page.content, 'html.parser')
                    debug_info['parsing_success'] = True
                    
                    # Count elements
                    debug_info['extracted_elements'] = {
                        'body': len(soup.find_all('p')),
                        'heads': len(soup.find_all('head')),
                        'titles': len(soup.find_all('title')),
                        'scripts': len(soup.find_all('script')),
                        'links': len(soup.find_all('a')),
                        'images': len(soup.find_all('img'))
                    }
                    
                    # Check for common issues
                    if debug_info['extracted_elements']['titles'] == 0:
                        debug_info['errors'].append('No title tags found')
                    
                    if debug_info['extracted_elements']['body'] == 0:
                        debug_info['errors'].append('No body tags found')
                    
                    if debug_info['content_length'] < 100:
                        debug_info['errors'].append('Content seems too short')
                        
                except Exception as e:
                    debug_info['errors'].append(f'Parsing error: {str(e)}')
            else:
                # Try to get more information about why it failed
                try:
                    # Try a simple HEAD request to see what status we get
                    test_response = requests.head(url, timeout=10, allow_redirects=True)
                    debug_info['test_status_code'] = test_response.status_code
                    debug_info['test_headers'] = dict(test_response.headers)
                    debug_info['errors'].append(f'URL not accessible - Status: {test_response.status_code}')
                except Exception as e:
                    debug_info['errors'].append(f'URL not accessible - Error: {str(e)}')
                
        except Exception as e:
            debug_info['errors'].append(f'Access error: {str(e)}')
        
        return jsonify({
            'debug_info': debug_info,
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Debug failed: {str(e)}',
            'status': 'error'
        }), 500