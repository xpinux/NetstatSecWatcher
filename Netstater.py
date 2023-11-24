import subprocess
import requests
import re
from ipaddress import ip_address
from requests.exceptions import RequestException
import logging

def get_netstat_output():
    try:
        # Run netstat command and capture output
        netstat_process = subprocess.Popen(['netstat', '-ano', '-b'], stdout=subprocess.PIPE, text=True, shell=True)
        netstat_output, _ = netstat_process.communicate()
        return netstat_output
    except subprocess.CalledProcessError as e:
        logging.error(f'Error running netstat command: {e}')
        return None

def is_private_ip(ip):
    try:
        # Check if the IP is private
        return ip_address(ip).is_private
    except ValueError:
        # Handle invalid IP addresses
        return False

def get_ip_reputation(api_key, ip_address):
    # Check the IP address against VirusTotal API
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    headers = {'x-apikey': api_key}
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise an error for bad responses (e.g., 404)
        result = response.json()

        if 'data' in result:
            data = result['data']
            if 'attributes' in data and 'last_analysis_stats' in data['attributes']:
                stats = data['attributes']['last_analysis_stats']
                total_scans = stats["harmless"] + stats["malicious"]

                if total_scans > 0 and (stats['malicious'] / total_scans) > 0.1:  # Check if malicious score is above 10%
                    return f'Malicious connection detected: {ip_address} - {stats["malicious"]}/{total_scans} positive scans'
                else:
                    return f'Safe connection detected: {ip_address} - {stats["malicious"]}/{total_scans} positive scans'
            else:
                return f'No reputation data for {ip_address}'
        else:
            return f'Error retrieving reputation for {ip_address} - Response: {response.content}'

    except RequestException as e:
        logging.error(f'Error accessing VirusTotal API: {e}')
        return f'Error accessing VirusTotal API for {ip_address}'

def get_netstat_info_for_ip(ip):
    # Run netstat command to get information about the connections associated with the IP
    netstat_output = get_netstat_output()
    if netstat_output:
        # Split netstat output by lines
        lines = netstat_output.splitlines()
        # Search for lines containing the IP address
        ip_info = [line for line in lines if ip in line]
        return ip_info
    else:
        return []

def main(api_key):
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    # Extract IP addresses from netstat output (modify regex as needed)
    netstat_output = get_netstat_output()
    ip_addresses = set(ip for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', netstat_output) if not is_private_ip(ip))

    if not ip_addresses:
        logging.warning("No public IP addresses found.")
        return

    for ip in ip_addresses:
        logging.info(f'Checking IP: {ip}')
        reputation_info = get_ip_reputation(api_key, ip)
        netstat_info = get_netstat_info_for_ip(ip)

        logging.info(reputation_info)
        logging.info(f'Netstat information for {ip}:')
        for info in netstat_info:
            logging.info(info)

if __name__ == "__main__":
    # Replace 'your_api_key' with your actual VirusTotal API key
    api_key = 'your_api_key '
    main(api_key)
