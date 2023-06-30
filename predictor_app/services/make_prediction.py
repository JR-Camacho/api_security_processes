from predictor_app.utils.parser_email import Parser

import numpy as np
import pickle
import joblib
import os

VECTORIZER_PATH = os.path.join(os.path.dirname(
    __file__), '..', 'ml_models/spam_detection/vectorizer', 'vectorizer.pkl')
MODEL_PATH = os.path.join(os.path.dirname(
    __file__), '..', 'ml_models/spam_detection/logistic_regression', 'spam_ham_detection.pkl')

with open(VECTORIZER_PATH, 'rb') as f:
    vectorizer = pickle.load(f)

model = joblib.load(MODEL_PATH)


def process_email(email, is_file=False):
    parser = Parser()
    parse_email = parser.parse(email, is_file=is_file)
    joined_email = np.array(
        [" ".join(parse_email['subject']) + " ".join(parse_email['body'])])
    print(parse_email)
    vectorize_email = vectorizer.transform(joined_email)
    return vectorize_email.toarray()


def make_email_prediction(email, is_file=False):
    return model.predict(process_email(email, is_file=is_file))
