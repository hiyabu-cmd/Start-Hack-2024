import requests

def check_http_https(url):
    
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url  # Assuming http as default if no protocol is specified
    
    try:
        response = requests.get(url, timeout=5)
        
        if response.url.startswith("https://"):
            print(f"{url} is using HTTPS: Secure connection.")
        else:
            print(f"{url} is using HTTP: Not a secure connection.")
            print("\nPotential Vulnerabilities of HTTP:\n")
            print("1. Data is transmitted in plain text, which makes it easy for attackers to intercept sensitive information.")
            print("2. It is susceptible to Man-in-the-Middle (MITM) attacks where attackers can alter or inject malicious content.")
            print("3. Browsers will show warnings about insecure connections, leading to a loss of user trust.")
            print("4. It's easier for attackers to steal login credentials or credit card information when HTTP is used instead of HTTPS.")
            print("\nRecommendations: Upgrade to HTTPS by renewing your SSL/TLS certificate to protect your users' data.")
    
    except requests.exceptions.RequestException as e:
        print(f"Error accessing the site: {e}")

# Example Usage:
#url = "http://http.badssl.com/"  #example of a site using HTTP

url = "http://www.thelegacy.de/" # example for vuneralable site
url = "http://www.cisco.com" # example for secure site
#url = "https://adorable-vivacious-lark-0w53nf.teleporthq.app/"
check_http_https(url)




#############Open port scanner##############
import socket

def check_open_ports(host, ports=[22, 80, 443, 3389]):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Set a timeout for connection
        result = sock.connect_ex((host, port))
        if result == 0:  # 0 means the port is open
            open_ports.append(port)
        sock.close()
    return open_ports

# Example Usage:
host = input("Enter IP or domain to scan for open ports: ")
open_ports = check_open_ports(host)
if open_ports:
    print(f"Open Ports: {open_ports}")
else:
    print("No open ports detected.")





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
