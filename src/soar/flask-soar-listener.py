#!/usr/bin/env python3
"""
Alpine Lab - Python Micro-SOAR Webhook Listener
================================================================================
Role: Ingests real-time Splunk alert webhooks, extracts compromised host telemetry,
      authenticates to the target endpoint via WinRM, and executes draconian
      containment rules to neutralize active C2 beaconing.
================================================================================
"""

import os
import sys
import hmac
import logging
from flask import Flask, request, jsonify
import winrm

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [Alpine-SOAR] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# --- Environment & Configuration ---
# No hardcoded credential fallbacks: a default password here would end up
# committed to source control the moment this file is pushed. Both of these
# must be set in the environment, or the service refuses to start.
WINRM_USER = os.getenv('ALPINE_WINRM_USER', 'Administrator')
WINRM_PASSWORD = os.getenv('ALPINE_WINRM_PASS')
SOC_GATEWAY_IP = os.getenv('ALPINE_SOC_GATEWAY', '10.254.2.1')
PORT = int(os.getenv('ALPINE_SOAR_PORT', 5000))

# Shared secret Splunk must present as ?token=... on the webhook URL (see
# src/splunk/savedsearches.conf) so /isolate can't be triggered by anything
# that can merely reach this port.
WEBHOOK_TOKEN = os.getenv('ALPINE_WEBHOOK_TOKEN')

# WinRM transport is lab-scoped: the victim VMs use self-signed certs, so
# cert validation is off by default here. Outside this lab, set
# ALPINE_WINRM_TRANSPORT=ssl, ALPINE_WINRM_PORT=5986 and
# ALPINE_WINRM_CERT_VALIDATION=validate with a real certificate deployed.
WINRM_TRANSPORT = os.getenv('ALPINE_WINRM_TRANSPORT', 'ntlm')
WINRM_CERT_VALIDATION = os.getenv('ALPINE_WINRM_CERT_VALIDATION', 'ignore')

if not WINRM_PASSWORD or not WEBHOOK_TOKEN:
    logging.getLogger(__name__).error(
        "ALPINE_WINRM_PASS and ALPINE_WEBHOOK_TOKEN must both be set in the "
        "environment. Refusing to start with a missing credential or an "
        "unauthenticated containment endpoint."
    )
    sys.exit(1)

# Path to containment script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONTAINMENT_SCRIPT_PATH = os.path.join(SCRIPT_DIR, "isolate_host.ps1")

def load_containment_script(soc_ip: str) -> str:
    """Reads the PowerShell containment playbook and injects the SOC gateway address."""
    if os.path.exists(CONTAINMENT_SCRIPT_PATH):
        with open(CONTAINMENT_SCRIPT_PATH, "r", encoding="utf-8") as f:
            script_content = f.read()
        return f"$SocAddress = '{soc_ip}';\n" + script_content
    else:
        # Fallback inline containment script
        return f"""
        New-NetFirewallRule -DisplayName "ALPINE-BLOCK-IN" -Direction Inbound -Action Block -Profile Any
        New-NetFirewallRule -DisplayName "ALPINE-BLOCK-OUT" -Direction Outbound -Action Block -Profile Any
        New-NetFirewallRule -DisplayName "ALPINE-ALLOW-WINRM-IN" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5985 -RemoteAddress "{soc_ip}" -Profile Any
        New-NetFirewallRule -DisplayName "ALPINE-ALLOW-WINRM-OUT" -Direction Outbound -Action Allow -Protocol TCP -RemotePort 5985 -RemoteAddress "{soc_ip}" -Profile Any
        """

@app.route('/isolate', methods=['POST'])
def handle_isolation_alert():
    """
    Ingests JSON alert payload from Splunk Webhook Alert Action.
    Expected JSON keys: 'risk_object' or 'victim_ip'
    """
    supplied_token = request.args.get('token', '')
    if not hmac.compare_digest(supplied_token, WEBHOOK_TOKEN):
        logger.warning("Rejected /isolate request: missing or invalid webhook token.")
        return jsonify({"status": "error", "message": "unauthorized"}), 401

    try:
        payload = request.get_json(force=True, silent=True)
        if not payload:
            logger.error("Received request with missing or unparseable JSON payload.")
            return jsonify({"status": "error", "message": "Empty or invalid JSON payload"}), 400

        logger.info(f"Received Splunk Webhook Alert: {payload}")

        # Extract victim host identity from Splunk fields
        victim_ip = (
            payload.get("risk_object") or
            payload.get("victim_ip") or
            payload.get("result", {}).get("risk_object") or
            payload.get("result", {}).get("ClientAddress")
        )

        if not victim_ip:
            logger.warning("Could not resolve target IP/Hostname from Splunk payload.")
            return jsonify({"status": "error", "message": "Target risk_object not identified in payload"}), 422

        logger.info(f"Targeting host for automated containment: {victim_ip}")

        # Prepare containment PowerShell execution
        ps_script = load_containment_script(SOC_GATEWAY_IP)

        # Establish WinRM session to victim endpoint over Management Plane (V.S 2)
        session = winrm.Session(
            target=victim_ip,
            auth=(WINRM_USER, WINRM_PASSWORD),
            transport=WINRM_TRANSPORT,
            server_cert_validation=WINRM_CERT_VALIDATION
        )

        logger.info(f"Executing containment playbook on {victim_ip} via WinRM...")
        result = session.run_ps(ps_script)

        if result.status_code == 0:
            logger.info(f"Successfully isolated host {victim_ip}. Standard output: {result.std_out.decode('utf-8').strip()}")
            return jsonify({
                "status": "success",
                "victim_ip": victim_ip,
                "message": f"Host {victim_ip} successfully isolated from network.",
                "output": result.std_out.decode('utf-8').strip()
            }), 200
        else:
            err_msg = result.std_err.decode('utf-8').strip()
            logger.error(f"WinRM execution failed on {victim_ip} with status code {result.status_code}: {err_msg}")
            return jsonify({
                "status": "error",
                "victim_ip": victim_ip,
                "message": "PowerShell containment failed",
                "error": err_msg
            }), 500

    except Exception as ex:
        logger.exception(f"Unhandled exception during host containment workflow: {str(ex)}")
        return jsonify({"status": "error", "message": str(ex)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for SOC service monitoring."""
    return jsonify({"status": "healthy", "service": "Alpine-Micro-SOAR-Listener"}), 200

if __name__ == '__main__':
    logger.info(f"Starting Alpine Micro-SOAR Webhook Server on 0.0.0.0:{PORT}...")
    logger.info(f"SOC Gateway configured as: {SOC_GATEWAY_IP}")
    app.run(host='0.0.0.0', port=PORT)
