from flask import Flask, render_template, request

app = Flask(__name__)


# ---------- EMAIL ANALYZER ----------
def analyze_email(text: str):
    text_lower = text.lower()
    reasons = []
    risk = 0

    if not text.strip():
        return None

    if "verify your account" in text_lower or "confirm your password" in text_lower \
       or "update your account" in text_lower:
        reasons.append("Asks to verify or confirm your account/password.")
        risk += 40

    if "urgent" in text_lower or "immediately" in text_lower or "within 24 hours" in text_lower \
       or "your account will be closed" in text_lower:
        reasons.append("Uses urgent or threatening language.")
        risk += 20

    for word in ["password", "otp", "cvv", "pin"]:
        if word in text_lower:
            reasons.append("Asks for sensitive information (password/OTP/CVV/PIN).")
            risk += 30
            break

    # basic link detection
    import re
    urls = re.findall(r"https?://[^\s]+", text)
    if urls:
        reasons.append(f"Contains external links: {', '.join(urls[:3])}")
        risk += 10

    # Adjust label thresholds if needed (email-specific)
    if risk >= 60:
        label = "Scam / Phishing"
    elif risk >= 30:
        label = "Suspicious"
    else:
        label = "Likely Safe"

    if not reasons:
        reasons.append("No strong phishing signs found, but always be cautious.")

    return {
        "label": label,
        "risk": min(risk, 100),
        "reasons": reasons
    }


# ---------- SOCIAL MEDIA / CHAT ANALYZER ----------
def analyze_social(text: str):
    text_lower = text.lower()
    reasons = []
    risk = 0

    if not text.strip():
        return None

    # Romance / emotional manipulation (high risk)
    if any(p in text_lower for p in [
        "i am a soldier", "i'm a soldier", "stationed overseas", "overseas", "cannot access my bank",
        "send me money", "send money", "i love you", "need money", "help me", "urgent help", "trust you",
        "can't access my bank", "please send", "please help me"
    ]):
        reasons.append("Contains emotional manipulation and direct money requests — strong romance scam indicator.")
        risk += 50

    # Lottery / prize scams
    if any(p in text_lower for p in ["you have won", "congratulations", "lucky winner", "lottery", "claim your prize"]):
        reasons.append("Looks like a lottery / prize scam.")
        risk += 35

    # Investment / crypto scams
    if any(p in text_lower for p in ["double your money", "guaranteed returns", "investment plan", "crypto", "get rich"]):
        reasons.append("Promises guaranteed or very high investment returns.")
        risk += 30

    # Fee / advance payment scams
    if any(p in text_lower for p in ["processing fee", "transfer fee", "pay the fee", "registration fee", "pay rs", "pay in advance"]):
        reasons.append("Asks you to pay a fee, which is common in scams.")
        risk += 25

    # Secrecy / isolation tactic
    if any(p in text_lower for p in ["don't tell anyone", "do not tell anyone", "keep this secret", "private deal"]):
        reasons.append("Asks you to keep it secret, which is a common red flag.")
        risk += 15

    # If the message mentions direct requests for OTP/password/credentials
    for word in ["password", "otp", "cvv", "pin"]:
        if word in text_lower:
            reasons.append("Requests sensitive credentials or OTPs — never share them.")
            risk += 40
            break

    # Basic link detection for social messages
    import re
    urls = re.findall(r"https?://[^\s]+", text)
    if urls:
        reasons.append(f"Contains external links: {', '.join(urls[:3])}")
        risk += 10

    # Revised thresholds for labeling social messages
    if risk >= 50:
        label = "Scam / High Risk"
    elif risk >= 20:
        label = "Suspicious"
    else:
        label = "Likely Safe"

    if not reasons:
        reasons.append("No strong scam indicators found, but stay cautious when chatting online.")

    return {
        "label": label,
        "risk": min(risk, 100),
        "reasons": reasons
    }


# ---------- JOB OFFER / RECRUITMENT SCAM ANALYZER ----------
def analyze_job(text: str):
    text_lower = text.lower()
    reasons = []
    risk = 0

    if not text.strip():
        return None

    # Pay-to-apply / registration fee
    if any(p in text_lower for p in ["registration fee", "pay the fee", "processing fee", "security deposit",
                                     "pay the amount", "pay rs", "pay in advance"]):
        reasons.append("Asks for money or fees for job application — major red flag.")
        risk += 40

    # No interview / guaranteed placement
    if any(p in text_lower for p in ["no interview", "guaranteed job", "100% placement", "immediate joining", "instant job"]):
        reasons.append("Claims guaranteed job or no-interview hiring — suspicious.")
        risk += 30

    # Requests for sensitive docs upfront
    if any(p in text_lower for p in ["share your aadhaar", "pan card", "bank statement", "send otp", "send password",
                                     "passport copy", "share documents"]):
        reasons.append("Asks for sensitive personal documents or OTPs — never share these.")
        risk += 35

    # Unrealistic salary promises (look for numbers near payment words)
    if any(p in text_lower for p in ["earn up to", "per month", "per day", "per week", "work from home"]) and any(ch.isdigit() for ch in text_lower):
        reasons.append("Displays unrealistic salary/payment claims; verify via official company page.")
        risk += 15

    # Generic/poor contact info
    if any(p in text_lower for p in ["contact whatsapp", "contact telegram", "contact number only", "no official domain", "gmail.com", "yahoo.com"]):
        reasons.append("Uses informal contact channels or personal email addresses instead of official company domain.")
        risk += 10

    if risk >= 70:
        label = "Scam / High Risk"
    elif risk >= 35:
        label = "Suspicious"
    else:
        label = "Likely Safe"

    if not reasons:
        reasons.append("No clear scam signals detected; still verify the offer on official company channels.")

    return {
        "label": label,
        "risk": min(risk, 100),
        "reasons": reasons
    }


# ---------- ROUTES ----------

@app.route("/")
def home_page():
    return render_template("home.html")

@app.route("/email", methods=["GET", "POST"])
def email_page():
    result = None
    email_text = ""

    if request.method == "POST":
        email_text = request.form.get("email_text", "")
        result = analyze_email(email_text)

    return render_template("email.html", result=result, email_text=email_text)


@app.route("/social", methods=["GET", "POST"])
def social_page():
    result = None
    message_text = ""

    if request.method == "POST":
        message_text = request.form.get("message_text", "")
        result = analyze_social(message_text)

    return render_template("social.html", result=result, message_text=message_text)


@app.route("/job", methods=["GET", "POST"])
def job_page():
    result = None
    job_text = ""

    if request.method == "POST":
        job_text = request.form.get("job_text", "")
        result = analyze_job(job_text)

    return render_template("job.html", result=result, job_text=job_text)


# ---------- RUN SERVER ----------
if __name__ == "__main__":
    # debug=True restarts automatically on file changes (development only)
    app.run(host="127.0.0.1", port=5000, debug=True)
