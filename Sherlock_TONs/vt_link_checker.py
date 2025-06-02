import requests
import time
import os
from dotenv import load_dotenv
from urllib.parse import urlparse
from requests.exceptions import MissingSchema, InvalidURL


# Load API key
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
assert VT_API_KEY, "VT_API_KEY not found in .env"

HEADERS = {
    "x-apikey": VT_API_KEY
}



def check_url_virustotal(url) -> str:
    if url == "UNRESOLVED_DOMAIN":
        return "unresolved"
    elif url == "INVALID_URL":
         return "invalid"   

    
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path

    try:
        print(f"🔎 Checking URL: {url}")

        # 1. Submit URL for scanning
        scan_response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=HEADERS,
            data={"url": url},
            timeout=10
        )
        scan_response.raise_for_status()
        url_id = scan_response.json()["data"]["id"]
        
        # 2. Wait for scan to complete
        time.sleep(10)

        # 3. Retrieve the analysis report
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
        analysis_response = requests.get(analysis_url, headers=HEADERS, timeout=10)
        analysis_response.raise_for_status()
        analysis = analysis_response.json()

        stats = analysis["data"]["attributes"]["stats"]
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless", 0)

        print(f"🧾 Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {harmless}")

        if malicious > 0 or suspicious > 0 :
            return "dangerous"
        elif  url == "UNRESOLVED_DOMAIN":
           return "unresolved"   
        elif url == "INVALID_URL":
         return "invalid"   
        else:
            return "safe"
        
    except requests.exceptions.ConnectionError as e:
        print(f"❌ Unable to connect to {domain}: {e}")
        return "unknown"

def resolve_url(url):
    """
    Follow redirects to get the final URL (works for short links, etc.).
    """
    try:
        response = requests.get(url, allow_redirects=True, timeout=10)
        final = response.url
        print(f"🔗 Resolved URL: {final}")
        return final
    except (MissingSchema, InvalidURL) as e:
        print(f"❌ Invalid URL format: {e}")
        return "INVALID_URL"
    except Exception as e:
        print(f"❌ Failed to resolve URL: {e}")
        return "UNRESOLVED_DOMAIN"


def convert_onion_to_gateway(url):
    """
    If it's a .onion link, route through a Tor2Web gateway.
    """
    # Ensure scheme
    if ".onion" in url and not url.startswith(("http://", "https://")):
        url = "http://" + url
    if ".onion" in url:
        return url.replace(".onion", ".onion.to")
    return url

def prepare_url_for_checking(url):
    """
    Normalize .onion links and resolve short URLs before checking.
    """
    url = convert_onion_to_gateway(url)
    url = resolve_url(url)
    return url

# Note: no `if __name__ == "__main__"` block, 
# the bot will call prepare_url_for_checking() and check_url_virustotal().
