import requests

API_KEY = "ac9a15afc6dcd0785391ea29f56977516f24ecf0661c6bf5127de9371965da31"

# -------- IP Check --------
def check_ip_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    
    headers = {
        "x-apikey": API_KEY
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            malicious = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
            
            if malicious > 0:
                return True, malicious
            else:
                return False, malicious
        else:
            print(f"⚠️ VT API Error (IP): Status Code {response.status_code}")
            return None, None

    except requests.exceptions.RequestException as e:
        print(f"❌ Connection Error (IP): {e}")
        return None, None


# -------- File Hash Check (MD5) --------
def check_hash_virustotal(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    
    headers = {
        "x-apikey": API_KEY
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            malicious = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
            
            if malicious > 0:
                return True, malicious
            else:
                return False, malicious
        else:
            print(f"⚠️ VT API Error (HASH): Status Code {response.status_code}")
            return None, None

    except requests.exceptions.RequestException as e:
        print(f"❌ Connection Error (HASH): {e}")
        return None, None
    