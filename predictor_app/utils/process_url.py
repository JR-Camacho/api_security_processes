from urllib.parse import urlparse
import numpy as np

def get_url_features(url):
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

    return np.array([[domain_url_ratio, tld_number, domain_length, symbol_count, path_domain_ratio, is_port_eighty, domain_token_count, path_url_ratio]])
