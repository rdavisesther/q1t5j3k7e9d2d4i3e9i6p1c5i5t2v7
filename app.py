import requests
import time
import dns.resolver
import concurrent.futures
from flask import Flask, render_template, request

# API configuration for VirusTotal
API_KEY = "338dc6f217e8a283b2854c17d7d7a626ad92398985ad876faf568d540fcc82b7"

# Initialize Flask app
app = Flask(__name__)

# Function to fetch subdomains using the VirusTotal API
def fetch_subdomains(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {"x-apikey": API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return [item["id"] for item in data.get("data", [])]
        else:
            return f"Error for domain {domain}: {response.status_code}"
    except Exception as e:
        return f"Connection error for domain {domain}: {e}"

# Function to get SPF record for a subdomain
def get_spf_record(subdomain):
    try:
        answers = dns.resolver.resolve(subdomain, 'TXT')
        for rdata in answers:
            txt_string = rdata.strings[0].decode('utf-8')
            if txt_string.startswith('v=spf'):
                return subdomain
        return None
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return None
    except Exception as e:
        return None

# Function to fetch SPF records for a list of subdomains
def check_spf_for_subdomains(subdomains):
    spf_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_subdomain = {executor.submit(get_spf_record, subdomain): subdomain for subdomain in subdomains}
        for future in concurrent.futures.as_completed(future_to_subdomain):
            result = future.result()
            if result:
                spf_results.append(result)
    return spf_results

# Web route for the main page
@app.route('/', methods=['GET', 'POST'])
def home():
    spf_results = []
    if request.method == 'POST':
        domain = request.form.get('domain')
        subdomains = fetch_subdomains(domain)
        if isinstance(subdomains, list) and subdomains:
            spf_results = check_spf_for_subdomains(subdomains)
        return render_template('index.html', domain=domain, spf_results=spf_results)
    return render_template('index.html', domain=None, spf_results=None)

# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True)
