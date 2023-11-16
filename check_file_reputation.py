import requests

# Insert your VirusTotal API key here
API_KEY = 'YOUR_VIRUSTOTAL_API_KEY'

# Function to check file hash against VirusTotal API
def check_file_hash(file_hash):
    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    headers = {
        'x-apikey': API_KEY
    }
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        if 'data' in data:
            attributes = data['data']['attributes']
            print(f"File Hash: {file_hash}")
            print(f"Last Analysis Stats: {attributes.get('last_analysis_stats')}")
        else:
            print("No information available for this file hash.")
    else:
        print("Error fetching information from VirusTotal API.")

# Example file hash to check (replace this with the hash of the file you want to check)
file_hash_to_check = 'INSERT_FILE_HASH_HERE'

# Check the file hash against VirusTotal's database
check_file_hash(file_hash_to_check)
