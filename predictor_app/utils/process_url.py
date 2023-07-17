from urllib.parse import urlparse
import numpy as np
import os

tld_mapping = {
    2: "com",
    3: "net",
    4: "org",
    5: "edu",
    6: "gov",
    7: "mil",
    8: "int",
    9: "xyz",
    10: "info",
    11: "biz",
    12: "io",
    13: "co",
    14: "uk",
    15: "ca",
    16: "de",
    17: "au",
    18: "fr",
    19: "jp"
}

def extract_url_info(url):
    parsed_url = urlparse(url)

    # Obtain the domain
    domain_or_ip = parsed_url.netloc if parsed_url.netloc else "No Domain"

    # Obtain the url length
    url_length = len(url)

    # Obtain the symbol count in the URL
    symbol_count = sum(c.isalnum() == False for c in url)

    # Obtain the protocol (HTTP o HTTPS)
    protocol = parsed_url.scheme if parsed_url.scheme else "No Protocol"

    url_info = {
        "domain_or_ip": domain_or_ip,
        "url_length": url_length,
        "symbol_count": symbol_count,
        "protocol": protocol
    }

    return url_info


def calculate_character_continuity_rate(url):
    domain = urlparse(url).netloc

    character_types = {
        'letter': 0,
        'digit': 0,
        'symbol': 0
    }

    current_type = None
    current_length = 0
    max_length = 0

    for char in domain:
        if char.isalpha():
            if current_type != 'letter':
                current_type = 'letter'
                current_length = 1
            else:
                current_length += 1
        elif char.isdigit():
            if current_type != 'digit':
                current_type = 'digit'
                current_length = 1
            else:
                current_length += 1
        else:
            if current_type != 'symbol':
                current_type = 'symbol'
                current_length = 1
            else:
                current_length += 1

        if current_length > max_length:
            max_length = current_length

        character_types[current_type] = max(character_types[current_type], current_length)

    total_length = sum(character_types.values())

    return max_length / total_length if total_length != 0 else 0.0

def get_url_phishing_features(url):

    parsed_url = urlparse(url)

    domain_url_ratio = len(parsed_url.netloc) / len(url)
    tld = parsed_url.netloc.split('.')[-1]
    tld_number = next(
        (key for key, value in tld_mapping.items() if value == tld), 0)
    domain_length = len(parsed_url.netloc)
    symbol_count = sum(
        c in "!@#$%^&*()_+{}:\"<>?|'\\/~`=://.:/?=,;()[]" for c in url)
    path_domain_ratio = len(parsed_url.path) / len(parsed_url.netloc)
    is_port_eighty = 0 if parsed_url.port == 80 else -1
    domain_token_count = len(parsed_url.netloc.split('.'))
    path_url_ratio = len(parsed_url.path) / len(url)
    query = parsed_url.query
    query_letter_count = -1 if not query else sum(c.isalpha() for c in query)
    url_letter_count = sum(c.isalpha() for c in url)
    url_len = len(url)
    path_length = len(parsed_url.path)
    arg_domain_ratio = len(parsed_url.query) / len(parsed_url.netloc)

    return np.array([[domain_url_ratio, tld_number, domain_length, symbol_count, path_domain_ratio, is_port_eighty, domain_token_count, path_url_ratio, query_letter_count, url_letter_count, url_len, path_length, arg_domain_ratio]])


def get_url_malware_features(url):
    parsed_url = urlparse(url)

    # NumberRate_AfterPath calculation
    after_path = parsed_url.path.split('/')[-1]  # Get the part after the path
    number_rate_after_path = sum(
        c.isdigit() for c in after_path) / len(after_path) if after_path else -1.0

    is_port_eighty = 0 if parsed_url.port == 80 else -1
    domain_length = len(parsed_url.netloc)
    symbol_count = sum(
        c in "!@#$%^&*()_+{}:\"<>?|'\\/~`=://.:/?=,;()[]" for c in url)
    domain_token_count = len(parsed_url.netloc.split('.'))

    tld = parsed_url.netloc.split('.')[-1]
    tld_number = next(
        (key for key, value in tld_mapping.items() if value == tld), 0)

    arg_domain_ratio = len(parsed_url.query) / len(parsed_url.netloc)
    is_ip_address_in_domain_name = - \
        1 if not int(parsed_url.netloc.replace('.', '').isdigit()) else 0
    url_len = len(url)
    longest_path_token_length = max(len(token)
                                    for token in parsed_url.path.split('/'))
    url_letter_count = sum(c.isalpha() for c in url)
    avg_domain_token_length = sum(
        len(token) for token in parsed_url.netloc.split('.')) / domain_token_count
    path_domain_ratio = len(parsed_url.path) / len(parsed_url.netloc)

    return np.array([[number_rate_after_path, is_port_eighty, domain_length, symbol_count, domain_token_count, tld_number, arg_domain_ratio, is_ip_address_in_domain_name, url_len, longest_path_token_length, url_letter_count, avg_domain_token_length, path_domain_ratio]])


def get_url_spam_features(url):

    parsed_url = urlparse(url)

    tld = parsed_url.netloc.split('.')[-1]
    tld_number = next(
        (key for key, value in tld_mapping.items() if value == tld), 0)
    symbol_count_domain = sum(
        c in parsed_url.netloc for c in "!@#$%^&*()_+-{}.:\"<>?|'\\/~`=[]")
    num_dots_in_url = parsed_url.geturl().count('.')
    domain_token_count = len(parsed_url.netloc.split('.'))
    symbol_count_url = sum(
        c in "!@#$%^&*()_+-{}:\"<>?|'\\/~`=://.:/?=,;()[]" for c in url)
    arg_url_ratio = len(parsed_url.query) / len(url) if len(url) > 0 else 0
    arg_path_ratio = len(parsed_url.query) / \
        len(parsed_url.path) if len(parsed_url.path) > 0 else 0
    symbol_count_filename = sum(c in "!@#$%^&*()_-+{}.:\"<>?|'\\/~`" for c in os.path.basename(
        parsed_url.path)) if os.path.basename(parsed_url.path) else -1
    symbol_count_extension = sum(c in "!@#$%^&*()_-+{}.:\"<>?|'\\/~`" for c in os.path.splitext(
        parsed_url.path)[1]) if os.path.splitext(parsed_url.path)[1] else -1
    digit_count_extension = sum(c.isdigit() for c in os.path.splitext(
        parsed_url.path)[-2]) if os.path.splitext(parsed_url.path)[-1] else -1
    symbol_count_after_path = sum(c in "!@#$%^&*()_-+{}.:\"<>?|'\\/~`" for c in (
        parsed_url.query + parsed_url.fragment)) if (parsed_url.query + parsed_url.fragment) else -1
    domain_length = len(parsed_url.netloc)

    return np.array([[tld_number, symbol_count_domain, num_dots_in_url, domain_token_count, calculate_character_continuity_rate(url), symbol_count_url, arg_url_ratio, arg_path_ratio, symbol_count_filename, symbol_count_extension, digit_count_extension, symbol_count_after_path, domain_length]])
