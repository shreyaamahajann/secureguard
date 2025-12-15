SecureGuard  
A lightweight cybersecurity toolkit for detecting phishing emails, social media scams, and job fraud.

SecureGuard is a simple Flask-based web application designed to help users identify suspicious messages across **email**, **social media**, and **job offers**.  
It analyzes text, assigns a **risk score**, and explains the **reasons** behind potential scams using rule-based detection logic.

Features

**Phishing Email Detector**
- Detects threatening language  
- Flags requests for passwords, OTP, CVV, and sensitive info  
- Identifies suspicious links  
- Provides a risk label + detailed reasons  

**Social Media Scam Detector**
- Catches lottery scams  
- Investment/Crypto promises  
- Romance scam patterns  
- Fee/advance payment traps  
- Secrecy-based manipulation  

### ✔ **Job Fraud Detector**
- Flags jobs asking for money  
- Unrealistic salary claims  
- No-interview guaranteed placement scams  
- Requests for Aadhaar, PAN, bank details  
- Suspicious contact emails (gmail/yahoo domains)


How It Works

SecureGuard uses **text-analysis heuristics** to detect scam patterns.  
Each analyzer returns:
- **Label** → Likely Safe / Suspicious / High Risk  
- **Risk score** (0–100)  
- **List of reasons**

No machine learning needed — fast, transparent, explainable.


Tech Stack

| Technology | Purpose |
|-----------|---------|
| **Python** | Core logic |
| **Flask** | Web framework |
| **Jinja2** | HTML templating |
| **HTML/CSS** | Frontend pages |


## 📂 Project Structure

