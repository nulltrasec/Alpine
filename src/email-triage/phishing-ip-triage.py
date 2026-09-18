import imaplib
import email
import os
import re
import sys

import requests

# --- Configuration ---
# Credentials come from the environment -- never hardcode an app password or
# API key in a script that's going to sit in a public repo.
IMAP_SERVER = 'imap.gmail.com'
EMAIL_USER = os.getenv('ALPINE_TRIAGE_EMAIL_USER')
EMAIL_APP_PASSWORD = os.getenv('ALPINE_TRIAGE_EMAIL_APP_PASSWORD')  # Gmail App Password, not your account password
ABUSEIPDB_API_KEY = os.getenv('ALPINE_ABUSEIPDB_API_KEY')
ABUSEIPDB_URL = 'https://api.abuseipdb.com/api/v2/check'

if not EMAIL_USER or not EMAIL_APP_PASSWORD or not ABUSEIPDB_API_KEY:
    sys.exit(
        "Set ALPINE_TRIAGE_EMAIL_USER, ALPINE_TRIAGE_EMAIL_APP_PASSWORD and "
        "ALPINE_ABUSEIPDB_API_KEY before running this script."
    )


def get_abuseipdb_score(ip_address):
    """Query the AbuseIPDB API for the threat score of a given IP."""
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    # maxAgeInDays=90 checks the last 3 months of threat intelligence
    params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
    try:
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()['data']
            confidence_score = data['abuseConfidenceScore']
            isp = data['isp']
            print(f"[+] IP: {ip_address} | Threat Score: {confidence_score}% | ISP: {isp}")
            if confidence_score > 50:
                print("    [!] HIGH RISK IP DETECTED!")
        else:
            print(f"[-] API Error for {ip_address}: {response.status_code}")
    except Exception as e:
        print(f"[-] Request failed: {e}")


def check_email_threats():
    """Connect to IMAP, fetch unseen emails, extract routing IPs, and check them."""
    try:
        # 1. Connect and Authenticate
        print("[*] Connecting to IMAP server...")
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(EMAIL_USER, EMAIL_APP_PASSWORD)

        # 2. Select the inbox
        mail.select('inbox')

        # 3. Search for UNSEEN (New/Unread) emails only
        status, messages = mail.search(None, 'UNSEEN')
        email_ids = messages[0].split()

        if not email_ids:
            print("[*] No new emails found.")
            return

        print(f"[*] Found {len(email_ids)} new email(s). Processing...")

        # 4. Process each unread email
        for e_id in email_ids:
            # Fetch the raw email (this marks it as 'Read' on the server)
            status, msg_data = mail.fetch(e_id, '(RFC822)')
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    # Parse the raw MIME data
                    raw_email = response_part[1]
                    msg = email.message_from_bytes(raw_email)
                    print(f"\n--- Checking Email: {msg.get('Subject')} ---")

                    # 5. Extract IPs from 'Received' headers
                    received_headers = msg.get_all('Received')
                    if received_headers:
                        for header in received_headers:
                            # Regex to extract standard IPv4 addresses
                            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', str(header))
                            for ip in ips:
                                # Ignore local/internal network routing IPs
                                if not ip.startswith(('10.', '192.168.', '172.', '127.')):
                                    get_abuseipdb_score(ip)

        # Logout cleanly
        mail.logout()
        print("\n[*] Email triage complete.")

    except Exception as e:
        print(f"[-] An error occurred: {e}")


if __name__ == '__main__':
    check_email_threats()
