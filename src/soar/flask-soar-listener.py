from flask import Flask, request, jsonify
import winrm

app = Flask(__name__)

# This route listens for Splunk's HTTP POST request
@app.route('/isolate', methods=['POST'])
def isolate_host():
    # 1. Parse the JSON payload from Splunk
    alert_data = request.json
    victim_ip = alert_data.get('victim_ip') # Splunk sends the infected IP here
    
    # 2. The PowerShell Firewall Script
    ps_script = """
    # 1. Block all inbound and outbound traffic
New-NetFirewallRule -DisplayName "QUARANTINE-BLOCK-IN" -Direction Inbound -Action Block -Profile Any
New-NetFirewallRule -DisplayName "QUARANTINE-BLOCK-OUT" -Direction Outbound -Action Block -Profile Any

# 2. Punch a hole specifically for the SOC Machine (e.g., 192.168.1.50) over WinRM (TCP 5985)
New-NetFirewallRule -DisplayName "QUARANTINE-ALLOW-WINRM-IN" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5985 -RemoteAddress "192.168.1.50" -Profile Any
New-NetFirewallRule -DisplayName "QUARANTINE-ALLOW-WINRM-OUT" -Direction Outbound -Action Allow -Protocol TCP -RemotePort 5985 -RemoteAddress "192.168.1.50" -Profile Any
    """
    
    # 3. Authenticate to the victim machine via WinRM and execute the script
    try:
        session = winrm.Session(victim_ip, auth=('Administrator', 'YourLabPassword'))
        result = session.run_ps(ps_script)
        
        return jsonify({"status": "success", "message": f"Host {victim_ip} isolated successfully."}), 200
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# Start the server on port 5000
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
