import requests
from flask import Flask, render_template, request
import time

app = Flask(__name__)

# DDoS Test Function (as previously defined)
def test_ddos_vulnerability(url, num_requests=100):
    failed_requests = 0
    start_time = time.time()

    for i in range(num_requests):
        try:
            response = requests.get(url)
            if response.status_code != 200:
                failed_requests += 1
        except requests.RequestException:
            failed_requests += 1
    
    elapsed_time = time.time() - start_time
    if failed_requests > 0:
        return f"Potential vulnerability to DDoS detected (failed {failed_requests} requests)."
    return "No DDoS vulnerability detected."

# Doxxing Check (using Have I Been Pwned API)
def check_email_breach(email):
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {"User-Agent": "Python Script"}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            breached_data = response.json()
            return f"Found breaches: {[entry['Title'] for entry in breached_data]}"
        elif response.status_code == 404:
            return "No breaches found for this email."
        else:
            return "Error occurred while checking the email."
    except Exception as e:
        return f"Error: {e}"

@app.route("/", methods=["GET", "POST"])
def index():
    ddos_result = ""
    doxxing_result = ""
    if request.method == "POST":
        # Getting URL for DDoS Test
        url = request.form.get("url")
        ddos_result = test_ddos_vulnerability(url)

        # Getting email for Doxxing Check
        email = request.form.get("email")
        if email:
            doxxing_result = check_email_breach(email)
        
    return render_template("index.html", ddos_result=ddos_result, doxxing_result=doxxing_result)

if __name__ == "__main__":
    app.run(debug=True)
