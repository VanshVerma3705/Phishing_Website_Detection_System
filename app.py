from flask import Flask, render_template, request
import pickle
import re
from urllib.parse import urlparse
import whois
from datetime import datetime

app = Flask(__name__)

model = pickle.load(open("phishing_model.pkl", "rb"))

# Trusted domains to prevent false positives
trusted_domains = [
    "google.com",
    "openai.com",
    "chatgpt.com",
    "wikipedia.org",
    "amazon.com",
    "microsoft.com",
    "apple.com"
]


def extract_features(url):

    url_length = len(url)
    dot_count = url.count(".")
    https = 1 if "https" in url else 0
    hyphen = 1 if "-" in url else 0
    at_symbol = 1 if "@" in url else 0
    digit_count = sum(c.isdigit() for c in url)
    slash_count = url.count("/")

    suspicious_words = ["login", "verify", "update", "secure", "account", "bank"]
    suspicious = 1 if any(word in url.lower() for word in suspicious_words) else 0

    parsed = urlparse(url)
    domain = parsed.netloc.replace("www.", "")
    domain_length = len(domain)

    ip_address = 1 if re.match(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", domain) else 0

    return [[
        url_length,
        dot_count,
        https,
        hyphen,
        at_symbol,
        digit_count,
        slash_count,
        suspicious,
        domain_length,
        ip_address
    ]]


def get_domain_info(url):

    try:
        domain = urlparse(url).netloc.replace("www.", "")
        info = whois.whois(domain)

        registrar = info.registrar
        creation_date = info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        domain_age = "Unknown"

        if creation_date:
            domain_age = datetime.now().year - creation_date.year
            creation_date = creation_date.strftime("%Y-%m-%d")

        return registrar, creation_date, domain_age

    except:
        return "Unknown", "Unknown", "Unknown"


@app.route("/")
def home():
    return render_template(
        "index.html",
        risk_score=None,
        prediction_text=None,
        registrar=None,
        creation_date=None,
        domain_age=None,
        url=""
    )


@app.route("/predict", methods=["POST"])
def predict():

    url = request.form["url"]

    parsed = urlparse(url)
    domain = parsed.netloc.replace("www.", "")

    registrar, creation_date, domain_age = get_domain_info(url)

    # Trusted domain check
    if domain in trusted_domains:
        result = "Legitimate Website ✅"
        risk_score = 1

    else:
        features = extract_features(url)

        prediction = model.predict(features)

        probability = model.predict_proba(features)[0][1]

        risk_score = round((1 - probability) * 100, 2)

        if prediction[0] == 1:
            result = "Legitimate Website ✅"
        else:
            result = "Phishing Website ⚠️"

    return render_template(
        "index.html",
        prediction_text=result,
        risk_score=risk_score,
        registrar=registrar,
        creation_date=creation_date,
        domain_age=domain_age,
        url=url
    )


if __name__ == "__main__":
    app.run(debug=True)
