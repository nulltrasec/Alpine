from flask import Flask, request, jsonify
import winrm
import os
import hmac

app = Flask(__name__)

# WinRM password and the webhook shared secret come from the environment --
# never hardcoded. The listener refuses to start if either is missing.
WINRM_PASSWORD = os.getenv('ALPINE_WINRM_PASS')
WEBHOOK_TOKEN = os.getenv('ALPINE_WEBHOOK_TOKEN')

if not WINRM_PASSWORD or not WEBHOOK_TOKEN:
    raise SystemExit(
        "Set ALPINE_WINRM_PASS and ALPINE_WEBHOOK_TOKEN before starting the listener."
    )

# This route listens for Splunk's HTTP POST request
@app.route('/isolate', methods=['POST'])
def isolate_host():
    # Splunk's webhook action appends this as a query-string param (see
    # src/splunk/savedsearches.conf) -- without this check, anyone who can
    # reach V.S 2 could POST here and quarantine an arbitrary host.
    if not hmac.compare_digest(request.args.get('token', ''), WEBHOOK_TOKEN):
        return jsonify({"status": "error", "message": "invalid or missing token"}), 401

    # 1. Parse the JSON payload from Splunk
    alert_data = request.json
    victim_ip = alert_data.get('victim_ip') # Splunk sends the infected IP here

    # 2. The PowerShell Firewall Script
    ps_script = """
    # 1. Block all inbound and outbound traffic
    New-NetFirewallRule -DisplayName "QUARANTINE-BLOCK-IN" -Direction Inbound -Action Block -Profile Any
    New-NetFirewallRule -DisplayName "QUARANTINE-BLOCK-OUT" -Direction Outbound -Action Block -Profile Any

    # 2. Punch a hole for the SOC's WinRM traffic (TCP 5985). The allowed source is
    # the gateway VIP (10.254.2.1), not the real SOAR host (10.254.2.100) -- outbound
    # WinRM packets get SNAT'd to the VIP before they ever reach V.S 2, so that's the
    # address the victim's firewall actually needs to allow (see
    # docs/01-architecture/network-plumbing-tc-iptables.md).
    New-NetFirewallRule -DisplayName "QUARANTINE-ALLOW-WINRM-IN" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5985 -RemoteAddress "10.254.2.1" -Profile Any
    New-NetFirewallRule -DisplayName "QUARANTINE-ALLOW-WINRM-OUT" -Direction Outbound -Action Allow -Protocol TCP -RemotePort 5985 -RemoteAddress "10.254.2.1" -Profile Any
    """

    # 3. Authenticate to the victim machine via WinRM and execute the script
    try:
        session = winrm.Session(victim_ip, auth=('Administrator', WINRM_PASSWORD))
        result = session.run_ps(ps_script)

        return jsonify({"status": "success", "message": f"Host {victim_ip} isolated successfully."}), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# Start the server on port 5000
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
