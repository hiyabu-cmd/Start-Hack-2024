import requests
import ssl
import socket
from flask import Flask, render_template, request

app = Flask(__name__)

# Function to check if the website uses HTTPS
def check_https(url):
    if url.startswith("https://"):
        return "HTTPS is enabled"
    else:
        return "HTTPS is not enabled. The website may be vulnerable to man-in-the-middle attacks."

# Function to check SSL Certificate validity
def check_ssl_cert(url):
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=url) as s:
            s.connect((url, 443))
            cert = s.getpeercert()
            return "SSL Certificate is valid"
    except ssl.SSLError:
        return "SSL Certificate is not valid"
    except Exception as e:
        return f"Error: {str(e)}"

# Function to check HTTP Security Headers
def check_http_headers(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        if 'Strict-Transport-Security' in headers:
            return "HSTS (HTTP Strict Transport Security) header is present"
        else:
            return "HSTS header is missing. This can leave the site vulnerable to downgrade attacks."
    except Exception as e:
        return f"Error: {str(e)}"

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"]
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url  # Default to http if no protocol is provided
        
        https_result = check_https(url)
        ssl_result = check_ssl_cert(url)
        headers_result = check_http_headers(url)

        return render_template("index.html", 
                               url=url, 
                               https_result=https_result, 
                               ssl_result=ssl_result, 
                               headers_result=headers_result)
    
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
