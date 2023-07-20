import email
import string
import nltk
import ssl
import re
from email.header import decode_header
from langdetect import detect
from html.parser import HTMLParser

# Downlodad stopwords from nltl
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context
nltk.download('stopwords')

# Define MLStripper class inheriting from HTMLParser class
class MLStripper(HTMLParser):
    def __init__(self):
        self.reset()
        self.strict = False
        self.convert_charrefs = True
        self.fed = []

    def handle_data(self, d):
        self.fed.append(d)

    def get_data(self):
        return ''.join(self.fed)

# This function is responsible for removing the HTML tags found in the text of the email
def strip_tags(html):
    s = MLStripper()
    s.feed(html)
    return s.get_data()

# Define Parser class
class Parser:
    def __init__(self):
        self.stemmer = nltk.PorterStemmer()
        self.stopwords = set(nltk.corpus.stopwords.words('english'))
        self.punctuation = list(string.punctuation)

    def parse(self, email_content, is_file=False):
        """Parse an email."""
        if (is_file):
            msg = email.message_from_bytes(email_content)
        else:
            msg = email.message_from_string(email_content)

        return None if not msg else self.get_email_content(msg)

    def get_email_content(self, msg):
        """Extract the email content."""
        subject = self.tokenize(msg['Subject']) if msg['Subject'] else []
        body = self.get_email_body(msg.get_payload(),
                                   msg.get_content_type())
        content_type = msg.get_content_type()
        # Returning the content of the email
        return {"subject": subject,
                "body": body,
                "content_type": content_type}

    def get_email_body(self, payload, content_type):
        """Extract the body of the email."""
        body = []
        if type(payload) is str and content_type == 'text/plain':
            return self.tokenize(payload)
        elif type(payload) is str and content_type == 'text/html':
            return self.tokenize(strip_tags(payload))
        elif type(payload) is list:
            for p in payload:
                body += self.get_email_body(p.get_payload(),
                                            p.get_content_type())
        return body

    def tokenize(self, text):
        """Transform a text string in tokens. Perform two main actions,
        clean the punctuation symbols and do stemming of the text."""
        for c in self.punctuation:
            text = text.replace(c, "")
        text = text.replace("\t", " ")
        text = text.replace("\n", " ")
        tokens = list(filter(None, text.split(" ")))
        # Stemming of the tokens
        return [self.stemmer.stem(w) for w in tokens if w not in self.stopwords]


def extract_email_info(email_content, is_file=False):
    # Parse the email content using the email library
    if (is_file):
        msg = email.message_from_bytes(email_content)
    else:
        msg = email.message_from_string(email_content)

    # Extract sender (From) and decode the sender's name if available
    sender = msg["From"]
    sender_name, encoding = decode_header(sender)[0]
    if isinstance(sender_name, bytes):
        sender_name = sender_name.decode(encoding or "utf-8")
    sender = f"{sender_name} <{msg['From']}>"

    # Extract recipients (To, Cc, Bcc) and decode recipient names if available
    recipients = [msg["To"], msg["Cc"], msg["Bcc"]]
    decoded_recipients = []
    for recipients_list in recipients:
        if recipients_list:
            decoded_list = decode_header(recipients_list)
            recipients_str = ""
            for recipient, encoding in decoded_list:
                if isinstance(recipient, bytes):
                    recipient = recipient.decode(encoding or "utf-8")
                recipients_str += f"{recipient}, "
            decoded_recipients.append(recipients_str.rstrip(", "))

 
    # Extract date and time
    date_time = msg["Date"]

    # Extract number of HTML tags using regex
    html_tags_count = len(re.findall(r'<[^>]*>', email_content.decode('utf-8') if is_file else email_content))

    # Extract number of words in the email content
    words_count = len(re.findall(r'\w+', email_content.decode('utf-8') if is_file else email_content))

    # Detect the language of the email content
    language = detect(email_content.decode('utf-8') if is_file else email_content)

    return {
        "sender": sender,
        "recipients": decoded_recipients,
        "date_time": date_time,
        "html_tags_count": html_tags_count,
        "words_count": words_count,
        "language": language
    }
