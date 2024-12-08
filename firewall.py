import requests
import socket
import time
from tabulate import tabulate

# Function to check open ports (for DDoS vulnerability)
def check_ports(host, ports):
    print(f"\nChecking ports for {host}...\n")
    open_ports = []
    test_result = "Pass"
    
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Timeout for 1 second to check if port is open
        result = sock.connect_ex((host, port))  # Try to connect to the port
        if result == 0:
            open_ports.append(port)
        sock.close()
    
    if open_ports:
        print(f"Open ports: {open_ports}")
    else:
        test_result = "Fail"
        print("No open ports found or all ports are blocked by a firewall.")
    
    return test_result

# Function to check allowed HTTP methods
def test_http_methods(url):
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
    allowed_methods = []
    test_result = "Pass"

    print(f"\nTesting HTTP methods for {url}...\n")
    
    for method in methods:
        try:
            response = requests.request(method, url)
            if response.status_code != 405:  # 405 means Method Not Allowed
                allowed_methods.append(method)
            print(f"Method {method} is allowed (Status: {response.status_code})")
        except requests.exceptions.RequestException as e:
            test_result = "Fail"
            print(f"Method {method} request failed: {e}")
    
    if allowed_methods:
        print(f"\nAllowed HTTP methods: {allowed_methods}")
    else:
        test_result = "Fail"
        print("\nAll HTTP methods are blocked by the firewall.")
    
    return test_result

# Function to simulate malicious traffic (custom headers)
def test_malicious_headers(url):
    headers = {
        "User-Agent": "Malicious Bot",
        "X-Forwarded-For": "123.456.789.0",  # Spoofing the IP
        "Content-Type": "application/x-www-form-urlencoded",
        "Payload": "<script>alert('XSS')</script>"  # Malicious payload
    }
    test_result = "Pass"

    print(f"\nTesting malicious headers for {url}...\n")

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            print(f"Request with malicious headers passed (Status: {response.status_code})")
        else:
            test_result = "Fail"
            print(f"Request with malicious headers blocked (Status: {response.status_code})")
    except requests.exceptions.RequestException as e:
        test_result = "Fail"
        print(f"Request failed: {e}")
    
    return test_result

# Main function that runs all tests
def run_tests():

 
 

    target_host = "www.thelegacy.de"
    target_url_http = "http://www.thelegacy.de/"
    target_url_https = "https://www.thelegacy.de/"
    ports_to_check = [80, 443, 8080, 21]  # HTTP, HTTPS, FTP ports

    test_results = []

    print("Starting Firewall Tests...\n")

    # Run Port Test (DDoS check)
    port_result = check_ports(target_host, ports_to_check)
    test_results.append(["Port Test (DDoS)", port_result])
    time.sleep(2)  # Short delay before next test

    # Run HTTP Methods Test for HTTP
    http_methods_result = test_http_methods(target_url_http)
    test_results.append(["HTTP Methods Test (HTTP)", http_methods_result])
    time.sleep(2)  # Short delay before next test

    # Run HTTP Methods Test for HTTPS
    https_methods_result = test_http_methods(target_url_https)
    test_results.append(["HTTP Methods Test (HTTPS)", https_methods_result])
    time.sleep(2)  # Short delay before next test

    # Run Malicious Headers Test for HTTP
    malicious_headers_http_result = test_malicious_headers(target_url_http)
    test_results.append(["Malicious Headers Test (HTTP)", malicious_headers_http_result])
    time.sleep(2)  # Short delay before next test

    # Run Malicious Headers Test for HTTPS
    malicious_headers_https_result = test_malicious_headers(target_url_https)
    test_results.append(["Malicious Headers Test (HTTPS)", malicious_headers_https_result])

    print("\nAll tests completed.\n")
    
    # Print summary table
    print(tabulate(test_results, headers=["Test", "Result"], tablefmt="grid"))

# Run all tests
if __name__ == "__main__":
    run_tests()
