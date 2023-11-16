import requests

# Insert your VirusTotal API key here
API_KEY = 'YOUR_VIRUSTOTAL_API_KEY'

# Function to query the VirusTotal API for IP reputation
def check_ip_reputation(ip_address):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    headers = {
        'x-apikey': API_KEY
    }
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        if 'data' in data:
            attributes = data['data']['attributes']
            print(f"IP Address: {ip_address}")
            print(f"Reputation: {attributes.get('reputation')}")
            print(f"Detected URLs: {attributes.get('last_analysis_stats', {}).get('malicious')}")
        else:
            print("No information available for this IP.")
    else:
        print("Error fetching information from VirusTotal API.")

# Example IP address to check (replace this with the IP you want to check)
ip_to_check = '8.8.8.8'

# Check the reputation of the specified IP
check_ip_reputation(ip_to_check)
