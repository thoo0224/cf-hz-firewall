import requests
import schedule
import time
import json
import os

HETZNER_API_TOKEN = os.getenv("HETZNER_API_TOKEN")
HETZNER_FIREWALL_ID = os.getenv("HETZNER_FIREWALL_ID")

if HETZNER_API_TOKEN is None or HETZNER_FIREWALL_ID is None:
    raise ValueError("Please set environment variables for HETZNER_API_TOKEN and HETZNER_FIREWALL_ID")

def get_cloudflare_ips():
    response = requests.get('https://www.cloudflare.com/ips-v4')
    if response.status_code == 200:
        return response.text.strip().split('\n')
    else:
        print("Failed to retrieve Cloudflare IP ranges")
        return []

def whitelist_ips_in_hetzner(ip_ranges):
    headers = {
        'Authorization': f'Bearer {HETZNER_API_TOKEN}',
        'Content-Type': 'application/json',
    }
    payload = {
        "rules": [
            {
                "direction": "in",
                "source_ips": ip_ranges,
                "port": "443",
                "protocol": "tcp",
                "description": "Accept port 443"
            },
                        {
                "direction": "in",
                "source_ips": ip_ranges,
                "port": "80",
                "protocol": "tcp",
                "description": "Accept port 80"
            },
        ]
    }

    response = requests.post(f'https://api.hetzner.cloud/v1/firewalls/{HETZNER_FIREWALL_ID}/actions/set_rules', headers=headers, data=json.dumps(payload))
    if 200 <= response.status_code < 203:
        print("IPs whitelisted successfully in Hetzner Firewall")
    else:
        print("Failed to whitelist IPs in Hetzner Firewall", response.json())

def update():
    cloudflare_ips = get_cloudflare_ips()
    whitelist_ips_in_hetzner(cloudflare_ips)

if __name__ == "__main__":
    update()

    schedule.every().day.at("00:00").do(update)

    while True:
        schedule.run_pending()
        time.sleep(1)