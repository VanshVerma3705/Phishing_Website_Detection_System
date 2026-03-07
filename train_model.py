import pandas as pd
import re
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import pickle

data = pd.read_csv("PhiUSIIL_Phishing_URL_Dataset.csv")

data = data[["URL","label"]]

def extract_features(url):

    url_length = len(url)
    dot_count = url.count(".")
    https = 1 if "https" in url else 0
    hyphen = 1 if "-" in url else 0
    at_symbol = 1 if "@" in url else 0
    digit_count = sum(c.isdigit() for c in url)
    slash_count = url.count("/")
    
    suspicious_words = ["login","verify","update","secure","account","bank"]
    suspicious = 1 if any(word in url.lower() for word in suspicious_words) else 0

    parsed = urlparse(url)
    domain_length = len(parsed.netloc)

    ip_address = 1 if re.match(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", parsed.netloc) else 0

    return [
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
    ]

features = data["URL"].apply(extract_features)

X = pd.DataFrame(features.tolist(), columns=[
    "url_length",
    "dot_count",
    "https",
    "hyphen",
    "at_symbol",
    "digit_count",
    "slash_count",
    "suspicious",
    "domain_length",
    "ip_address"
])

y = data["label"]

X_train,X_test,y_train,y_test = train_test_split(
    X,y,test_size=0.2,random_state=42
)

model = RandomForestClassifier(n_estimators=100)
model.fit(X_train,y_train)

pickle.dump(model,open("phishing_model.pkl","wb"))

print("Model trained successfully")