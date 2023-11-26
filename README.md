# NetstatSecWatcher

NetstatSecWatcher is a Python script that monitors the netstat output, checks the reputation of public IP addresses using the VirusTotal API, and provides essential information about network connections.

## Features
![368179460_319636021009474_1427213308682831194_n](https://github.com/xpinux/NetstatSecWatcher/assets/33750676/edfa622b-4a25-4781-8f7b-6248e46552a8)
- **IP Reputation Check:** Utilizes the VirusTotal API to assess the reputation of public IP addresses.
- **Netstat Information:** Displays netstat information for each public IP address, including protocol, PID, process, etc.
- **Malicious Detection:** Identifies malicious connections based on a configurable threshold. If the malicious score is above 10% of the total scans, it is marked as CRITICAL.
- **Suspicious Connections:** If an IP has no reputation or a low reputation, it is marked as SUSPICIOUS.
- **Safe Connections:** If an IP has a clean reputation (0 out of total detections), it is marked as INFO.

## Prerequisites

- Python 3
- Requests library (`pip install requests`)

## Usage

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/netstatsecwatcher.git](https://github.com/xpinux/NetstatSecWatcher.git```
  2. Navigate to the project folder
  3. Replace 'your_api_key' with your actual VirusTotal API key in NetstatSecWatcher.py.
  4. run the script `python NetstatSecWatcher.py`

# Configuration
Modify the regex pattern in the script to extract IP addresses from netstat output as needed.
Adjust the malicious threshold as required.

# Output Legend
- CRITICAL: Indicates a malicious connection (malicious score above 10%).
- SUSPICIOUS: Indicates a connection with no reputation or low reputation.
- INFO: Indicates a safe connection.

# License
This project is licensed under the MIT License.

# Contribution
Feel free to contribute by opening issues or submitting pull requests.

Enjoy monitoring your computers with NetstatSecWatcher!
