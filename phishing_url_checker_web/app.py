from flask import Flask, render_template, request
import re
import requests
import validators

app = Flask(__name__)

def check_url(url):
    result = {
        "valid": False,
        "reachable": False,
        "risk_score": 0,
        "issues": []
    }

    # 1️⃣ Validate URL format
    if not validators.url(url):
        result["issues"].append("Invalid URL format")
        return result

    result["valid"] = True
    risk = 0
    issues = []

    # 2️⃣ Pattern checks
    if re.search(r'\d+\.\d+\.\d+\.\d+', url):
        issues.append("Contains IP address (suspicious)")
        risk += 25

    if '@' in url:
        issues.append("Contains '@' symbol (used to hide true domain)")
        risk += 20

    if url.count('-') > 3:
        issues.append("Too many '-' in domain (phishing indicator)")
        risk += 15

    if len(url) > 75:
        issues.append("Unusually long URL")
        risk += 10

    if not url.startswith("https"):
        issues.append("Does not use HTTPS (insecure)")
        risk += 10

    # Suspicious keywords
    suspicious_words = ["verify", "login", "update", "secure", "bank", "account", "signin", "confirm"]
    if any(word in url.lower() for word in suspicious_words):
        issues.append("Contains suspicious keywords")
        risk += 20

    # 3️⃣ Try reaching the URL
    try:
        response = requests.get(url, timeout=4)
        if response.status_code == 200:
            result["reachable"] = True
        else:
            issues.append(f"Site returned status code {response.status_code}")
            risk += 10
    except requests.exceptions.RequestException:
        issues.append("Site not reachable")
        risk += 15

    # Final risk calculation
    risk = min(100, risk)
    result["risk_score"] = risk
    result["issues"] = issues
    return result


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    if request.method == "POST":
        url = request.form.get("url").strip()
        if url:
            result = check_url(url)
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)