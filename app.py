import re
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS 

app = Flask(__name__)
CORS(app) 


def analyze_scam_message(text):
    text_lower = text.lower()
    score = 0
    reasons = []

    # 1. High Risk Fraud & Urgent Keywords
    urgent_keywords = [
        "kyc",
        "account suspended",
        "blocked",
        "lottery",
        "congratulations",
        "winner",
        "urgent",
        "click here",
        "earn daily",
        "part time job",
        "free gift",
        "claim now",
        "otp",
        "bank update",
        "reward",
    ]

    found_words = [word for word in urgent_keywords if word in text_lower]
    if found_words:
        score += len(found_words) * 15
        reasons.append(
            f"Suspicious/Urgent keywords found: {', '.join(found_words)}"
        )

    # 2. URL and Link Inspection
    urls = re.findall(r"https?://[^\s]+", text)
    if urls:
        score += 20
        reasons.append(f"Message contains links ({len(urls)} link/s)")
        for url in urls:
            if (
                "bit.ly" in url
                or "tinyurl" in url
                or "goo.gl" in url
                or "t.co" in url
            ):
                score += 25
                reasons.append(f"Shortener/Unsafe link detected: {url}")
            elif not url.startswith("https://"):
                score += 20
                reasons.append(f"Insecure HTTP link detected: {url}")

    # 3. Phone Number & Payment Pattern Check
    phone_numbers = re.findall(r"\b\d{10}\b", text)
    if phone_numbers and ("pay" in text_lower or "send" in text_lower):
        score += 20
        reasons.append("Unauthorized payment or contact number referenced")

    # Cap final risk score at 100%
    final_score = min(score, 100)

    # Classification Label & Color Theme
    if final_score >= 60:
        status = "HIGH RISK SCAM 🚨"
        color = "danger"
    elif final_score >= 30:
        status = "SUSPICIOUS MESSAGE ⚠️"
        color = "warning"
    else:
        status = "SAFE MESSAGE ✅"
        color = "success"

    return {
        "score": final_score,
        "status": status,
        "color": color,
        "reasons": (
            reasons
            if reasons
            else ["No suspicious patterns or unsafe links detected."]
        ),
    }


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    message = data.get("message", "")
    if not message.strip():
        return jsonify({"error": "Please enter a message!"}), 400

    result = analyze_scam_message(message)
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
