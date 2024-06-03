import sys
import requests
import csv
import json
import time
import os
from datetime import datetime
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

print(f"Python version: {sys.version}")

# Function to load configuration from a JSON file
def load_config(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

# Load configuration for base URLs
config = load_config('config.json')
BASE_URLS = config['base_urls']

# Read API keys from environment variables
API_KEYS = {
    'virustotal': os.getenv('VIRUSTOTAL_API_KEY'),
    'ipvoid': os.getenv('IPVOID_API_KEY'),
    'whoisjson': os.getenv('WHOISJSON_API_KEY')
}

# Function to read domains from a file
def read_domains(file_path):
    with open(file_path, 'r') as file:
        domains = [line.strip() for line in file]
    print(f"Read {len(domains)} domains from {file_path}")
    return domains

# Function to query VirusTotal
def query_virustotal(domain):
    headers = {'x-apikey': API_KEYS['virustotal']}
    response = requests.get(BASE_URLS['virustotal'] + domain, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return {'error': 'Not found'}

# Function to query IPVoid
def query_ipvoid(domain):
    params = {'key': API_KEYS['ipvoid'], 'host': domain}
    response = requests.get(BASE_URLS['ipvoid'], params=params)
    if response.status_code == 200:
        return response.json()
    else:
        return {'error': 'Not found'}

# Function to query WhoisJSON with retry logic
def query_whois(domain):
    url = f"{BASE_URLS['whoisjson']}?domain={domain}&format=json"
    headers = {
        'accept': 'application/json',
        'Authorization': f'TOKEN={API_KEYS["whoisjson"]}'
    }
    session = requests.Session()
    retries = Retry(total=5, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount('https://', HTTPAdapter(max_retries=retries))

    try:
        response = session.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            return {'error': 'Not found'}
    except requests.exceptions.RequestException as e:
        print(f"WHOIS Request Exception: {e}")
        return {'error': 'Not found'}

# Function to extract necessary fields from VirusTotal response
def extract_virustotal_data(data):
    if 'error' in data:
        return {
            'vt_creation_date': 'Not found',
            'vt_certificate_not_before': 'Not found',
            'vt_certificate_not_after': 'Not found',
            'vt_dns_records': 'Not found',
            'vt_reputation': 'Not found',
            'vt_last_analysis_stats': 'Not found'
        }

    attributes = data.get('data', {}).get('attributes', {})
    last_https_certificate = attributes.get('last_https_certificate', {})
    validity = last_https_certificate.get('validity', {})
    last_dns_records = attributes.get('last_dns_records', [])
    dns_records = {record['type']: record['value'] for record in last_dns_records}

    return {
        'vt_creation_date': attributes.get('creation_date', 'Not found'),
        'vt_certificate_not_before': validity.get('not_before', 'Not found'),
        'vt_certificate_not_after': validity.get('not_after', 'Not found'),
        'vt_dns_records': dns_records if dns_records else 'Not found',
        'vt_reputation': attributes.get('reputation', 'Not found'),
        'vt_last_analysis_stats': attributes.get('last_analysis_stats', 'Not found')
    }

# Function to extract necessary fields from IPVoid response
def extract_ipvoid_data(data):
    if 'error' in data:
        return {
            'ipvoid_blacklist_status': 'Not found',
            'ipvoid_ip': 'Not found',
            'ipvoid_country': 'Not found',
            'ipvoid_isp': 'Not found'
        }

    report = data.get('data', {}).get('report', {})
    server = report.get('server', {})

    return {
        'ipvoid_blacklist_status': report.get('blacklists', {}).get('detections', 'Not found'),
        'ipvoid_ip': server.get('ip', 'Not found'),
        'ipvoid_country': server.get('country_name', 'Not found'),
        'ipvoid_isp': server.get('isp', 'Not found')
    }

# Function to extract necessary fields from WhoisJSON response
def extract_whois_data(data):
    if 'error' in data:
        return {
            'whois_server': 'Not found',
            'whois_name': 'Not found',
            'whois_idnName': 'Not found',
            'whois_status': 'Not found',
            'whois_nameserver': 'Not found',
            'whois_ips': 'Not found',
            'whois_created': 'Not found',
            'whois_changed': 'Not found',
            'whois_expires': 'Not found',
            'whois_registered': 'Not found',
            'whois_dnssec': 'Not found',
            'whois_owner_handle': 'Not found',
            'whois_owner_type': 'Not found',
            'whois_owner_name': 'Not found',
            'whois_owner_organization': 'Not found',
            'whois_owner_email': 'Not found',
            'whois_owner_address': 'Not found',
            'whois_owner_zipcode': 'Not found',
            'whois_owner_city': 'Not found',
            'whois_owner_state': 'Not found',
            'whois_owner_country': 'Not found',
            'whois_owner_phone': 'Not found',
            'whois_owner_fax': 'Not found',
            'whois_owner_created': 'Not found',
            'whois_owner_changed': 'Not found'
        }

    owner = data.get('contacts', {}).get('owner', [{}])[0]
    return {
        'whois_server': data.get('server', 'Not found'),
        'whois_name': data.get('name', 'Not found'),
        'whois_idnName': data.get('idnName', 'Not found'),
        'whois_status': ', '.join(data.get('status', ['Not found'])),
        'whois_nameserver': ', '.join(data.get('nameserver', ['Not found'])),
        'whois_ips': data.get('ips', 'Not found'),
        'whois_created': data.get('created', 'Not found'),
        'whois_changed': data.get('changed', 'Not found'),
        'whois_expires': data.get('expires', 'Not found'),
        'whois_registered': data.get('registered', 'Not found'),
        'whois_dnssec': data.get('dnssec', 'Not found'),
        'whois_owner_handle': owner.get('handle', 'Not found'),
        'whois_owner_type': owner.get('type', 'Not found'),
        'whois_owner_name': owner.get('name', 'Not found'),
        'whois_owner_organization': owner.get('organization', 'Not found'),
        'whois_owner_email': owner.get('email', 'Not found'),
        'whois_owner_address': ', '.join(owner.get('address', ['Not found'])),
        'whois_owner_zipcode': owner.get('zipcode', 'Not found'),
        'whois_owner_city': owner.get('city', 'Not found'),
        'whois_owner_state': owner.get('state', 'Not found'),
        'whois_owner_country': owner.get('country', 'Not found'),
        'whois_owner_phone': owner.get('phone', 'Not found'),
        'whois_owner_fax': owner.get('fax', 'Not found'),
        'whois_owner_created': owner.get('created', 'Not found'),
        'whois_owner_changed': owner.get('changed', 'Not found')
    }

# Function to generate a unique filename
def generate_unique_filename(base_name, extension):
    counter = 1
    filename = f"{base_name}{counter:03d}.{extension}"
    while os.path.exists(filename):
        counter += 1
        filename = f"{base_name}{counter:03d}.{extension}"
    return filename

# Function to save results to a CSV file
def save_results_to_csv(results, base_filename):
    if not results:
        print("No results to save.")
        return

    fieldnames = [
        'domain', 'vt_creation_date', 'vt_certificate_not_before', 'vt_certificate_not_after', 'vt_dns_records',
        'vt_reputation', 'vt_last_analysis_stats', 'ipvoid_blacklist_status', 'ipvoid_ip', 'ipvoid_country',
        'ipvoid_isp', 'whois_server', 'whois_name', 'whois_idnName', 'whois_status', 'whois_nameserver',
        'whois_ips', 'whois_created', 'whois_changed', 'whois_expires', 'whois_registered', 'whois_dnssec',
        'whois_owner_handle', 'whois_owner_type', 'whois_owner_name', 'whois_owner_organization',
        'whois_owner_email', 'whois_owner_address', 'whois_owner_zipcode', 'whois_owner_city',
        'whois_owner_state', 'whois_owner_country', 'whois_owner_phone', 'whois_owner_fax',
        'whois_owner_created', 'whois_owner_changed'
    ]

    filename = generate_unique_filename(base_filename, "csv")

    with open(filename, 'w', newline='') as file:
        dict_writer = csv.DictWriter(file, fieldnames=fieldnames)
        dict_writer.writeheader()
        dict_writer.writerows(results)
    print(f"Results saved to {filename}")

def main(input_path, output_path):
    domains = read_domains(input_path)
    if not domains:
        print("No domains found in the input file.")
        return

    results = []

    for domain in domains:
        print(f"Processing domain: {domain}")
        result = {'domain': domain}

        # Query VirusTotal
        try:
            vt_result = query_virustotal(domain)
            vt_data = extract_virustotal_data(vt_result)
            result.update(vt_data)
        except Exception as e:
            result['virustotal'] = f"Error: {e}"
            print(f"Error querying VirusTotal for {domain}: {e}")

        # Query IPVoid
        try:
            ipvoid_result = query_ipvoid(domain)
            ipvoid_data = extract_ipvoid_data(ipvoid_result)
            result.update(ipvoid_data)
        except Exception as e:
            result['ipvoid'] = f"Error: {e}"
            print(f"Error querying IPVoid for {domain}: {e}")

        # Query WhoisJSON
        try:
            whois_result = query_whois(domain)
            whois_data = extract_whois_data(whois_result)
            result.update(whois_data)
        except Exception as e:
            result['whois'] = f"Error: {e}"
            print(f"Error querying WhoisJSON for {domain}: {e}")

        results.append(result)

        # Sleep to avoid rate limits
        time.sleep(1)

    # Generate the base filename with the current date
    base_filename = os.path.join(output_path, f"domains_result_{datetime.now().strftime('%Y%m%d')}_")
    print(f"Saving results to {base_filename}")
    save_results_to_csv(results, base_filename)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python your_script.py <input_path> <output_path>")
        sys.exit(1)
    input_path = sys.argv[1]
    output_path = sys.argv[2]
    print(f"Running script with input_path: {input_path} and output_path: {output_path}")
    main(input_path, output_path)
