import requests
import os

# This URL points to list of malicious IPs
FEED_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
SAVE_PATH = os.path.join("data", "firehol_level1.netset")

def download_feed():
    """
    Downloads the FireHOL level 1 IP blocklist and saves it to the data folder.
    """
    print(f"Downloading threat feed from: {FEED_URL}")
    
    # Set to be polite
    HEADERS = {
        'User-Agent': 'AIThreatCorrelator (GitHub project)'
    }
    
    try:
        response = requests.get(FEED_URL, headers=HEADERS, timeout=10)
        response.raise_for_status()  # Raise error for bad responses
        
        # Ensure the data directory exists
        os.makedirs(os.path.dirname(SAVE_PATH), exist_ok=True)
        
        with open(SAVE_PATH, 'w') as f:
            f.write(response.text)
            
        print(f"Successfully downloaded and saved feed to: {SAVE_PATH}")
        return True
        
    except requests.exceptions.RequestException as e:
        print(f"Error: Could not download threat feed. {e}")
        return False

if __name__ == "__main__":
    download_feed()