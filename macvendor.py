import requests

def mac_vendor_lookup(mac_address):
    url = f"https://api.macvendors.com/{mac_address}"
    try:
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            return response.text.strip()
        else:
            return "Unavailable"
    except Exception as e:
        return f"Error: {e}"

# Example usage:
mac_address = "a0:36:bc:32:72:bc"
vendor = mac_vendor_lookup(mac_address)
print("Vendor:", vendor)