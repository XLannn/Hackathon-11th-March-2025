from flask import Flask, render_template, request, jsonify
import requests
import os
from dotenv import load_dotenv
from bs4 import BeautifulSoup
from pymongo import MongoClient
import re
from urllib.parse import urlparse
from datetime import datetime

# Load environment variables
load_dotenv()

# Flask App Setup
app = Flask(__name__)

# Google Safe Browsing API Key
SAFE_BROWSING_API = os.getenv("SAFE_BROWSING_API")
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# MongoDB Configuration (Anonymous Crime Reports)
client = MongoClient("mongodb://localhost:27017/")
db = client["crime_reports"]
collection = db["reports"]

# --------------------------------------
# PHISHING CHECKER
# --------------------------------------
def check_phishing(url):
    try:
        parsed_url = urlparse(url.strip())
        domain = parsed_url.netloc.lower()
        if not domain:
            return {"safe": False, "status": "Invalid URL"}

    except:
        return {"safe": False, "status": "Invalid URL"}

    suspicious_patterns = [
        r"\b(login|verify|update|secure|account|paypal|bank|free-money|win-prize|click-here)\b"
    ]

    unsafe_tlds = ['.xyz', '.buzz', '.top', '.gq', '.tk', '.ml']

    payload = {
        "client": {"clientId": "your-app", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    response = requests.post(SAFE_BROWSING_URL + f"?key={SAFE_BROWSING_API}", json=payload)

    if (
        bool(response.json())
        or any(re.search(pattern, domain) for pattern in suspicious_patterns)
        or any(domain.endswith(tld) for tld in unsafe_tlds)
        or len(domain.split('.')) < 2
    ):
        return {"safe": False, "status": "Risk Detected"}

    return {"safe": True, "status": "Safe"}

@app.route('/check-url', methods=['POST'])
def check_url():
    url = request.form.get('url')
    if not url.startswith('http://') and not url.startswith('https://'):
        url = "http://" + url  

    result = check_phishing(url)
    return jsonify(result)

# --------------------------------------
# TERMS & CONDITIONS ANALYZER
# --------------------------------------
def analyze_terms(url):
    try:
        page = requests.get(url.strip(), timeout=5)
        if page.status_code != 200:
            return {"status": f"Failed to retrieve page: {page.status_code}"}

        soup = BeautifulSoup(page.text, 'html.parser')
        text = soup.get_text()

        risky_keywords = ["data sharing", "third-party", "privacy risk", "tracking", "liability waiver"]
        safe_keywords = ["encryption", "data protection", "secure payment", "GDPR compliant", "opt-out option"]

        risks = [kw for kw in risky_keywords if kw in text.lower()]
        safe_practices = [kw for kw in safe_keywords if kw in text.lower()]

        return {
            "status": "Risk Detected" if risks else "Safe",
            "risks": risks,
            "safe_practices": safe_practices
        }
    except requests.exceptions.RequestException as e:
        return {"status": f"Error connecting to site: {str(e)}"}

@app.route('/analyze-tos', methods=['POST'])
def analyze_tos():
    url = request.form.get('tos_url')
    if not url:
        return jsonify({"error": "No TOS URL provided."}), 400
    result = analyze_terms(url)
    return jsonify(result)

# --------------------------------------
# ANONYMOUS CRIME REPORTING
# --------------------------------------
@app.route('/report-crime', methods=['POST'])
def report_crime():
    data = request.json
    if not data or "description" not in data or "location" not in data:
        return jsonify({"error": "Invalid data format. Please provide 'description', 'location', and optionally 'name'."}), 400

    report = {
        "name": data.get("name", "Anonymous"),  
        "description": data["description"],
        "location": data["location"],
        "timestamp": datetime.now().isoformat(),
    }
    collection.insert_one(report)
    return jsonify({"message": "Report submitted successfully."})

# --------------------------------------
# HTML HOME ROUTE
# --------------------------------------
@app.route('/')
def home():
    return render_template('index.html')

# --------------------------------------
# SERVER START
# --------------------------------------
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
