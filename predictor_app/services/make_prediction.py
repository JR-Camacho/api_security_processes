from predictor_app.utils.parser_email import Parser
from predictor_app.utils.process_url import get_url_phishing_features, get_url_malware_features, get_url_spam_features

import numpy as np
import pickle
import joblib
import os

HAM_SPAM_VECTORIZER_PATH = os.path.join(os.path.dirname(
    __file__), '..', 'ml_models/spam_detection/vectorizer', 'vectorizer.pkl')
HAM_SPAM_MODEL_PATH = os.path.join(os.path.dirname(
    __file__), '..', 'ml_models/spam_detection/naive_bayes', 'spam_ham_detection.pkl')

PHISHING_MODEL_PATH = os.path.join(os.path.dirname(
    __file__), '..', 'ml_models/phishing_detection/decision_tree', 'phishing_url_detection.pkl')
MALWARE_MODEL_PATH = os.path.join(os.path.dirname(
    __file__), '..', 'ml_models/malware_detection/svm', 'malware_url_detection.pkl')
SPAM_MODEL_PATH = os.path.join(os.path.dirname(
    __file__), '..', 'ml_models/url_spam_detection/decision_tree', 'spam_url_detection_optimized.pkl')

with open(HAM_SPAM_VECTORIZER_PATH, 'rb') as f:
    ham_spam_vectorizer = pickle.load(f)
ham_spam_model = joblib.load(HAM_SPAM_MODEL_PATH)

phishing_model = joblib.load(PHISHING_MODEL_PATH)
malware_model = joblib.load(MALWARE_MODEL_PATH)
spam_model = joblib.load(SPAM_MODEL_PATH)

def process_email(email, is_file=False):
    parser = Parser()
    parse_email = parser.parse(email, is_file=is_file)
    joined_email = np.array(
        [" ".join(parse_email['subject']) + " ".join(parse_email['body'])])
    vectorize_email = ham_spam_vectorizer.transform(joined_email)
    return vectorize_email.toarray()

def make_email_prediction(email, is_file=False):
    return ham_spam_model.predict(process_email(email, is_file=is_file))

def make_url_phishing_prediction(url):
    return phishing_model.predict(get_url_phishing_features(url))

def make_url_malware_prediction(url):
    return malware_model.predict(get_url_malware_features(url))

def make_url_spam_prediction(url):
    return spam_model.predict(get_url_spam_features(url))