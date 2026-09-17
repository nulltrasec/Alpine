# Formal Incident Response Report

**Incident Reference**: `IR-2026-0917-ALPINE`  
**Classification**: **CRITICAL (Severity 1)**  
**Target Asset**: Workstation `HR-01` (`10.0.0.15`)  
**Domain**: `ALPINE.INTERNAL`  
**Lead Investigator**: SOC Detection & Response Team  
**Status**: **RESOLVED / CONTAINED**

---

**A note on methodology**: this report documents a self-run exercise in the Alpine lab (see [network-topology.md](../01-architecture/network-topology.md)). The timeline below shows the causal detection chain; actual wall-clock latency between steps is bounded by the cron intervals of the underlying Splunk saved searches (1-5 minutes -- see [detection-engineering-rba.md](detection-engineering-rba.md)), not by continuous real-time polling.

---

## 1. Executive Summary

On September 17, 2026, the Alpine Security Operations Center (SOC) detected an active intrusion campaign targeting the internal enterprise environment. An adversary successfully achieved code execution on endpoint `HR-01` via a spearphishing attachment (`invoice.docm`), injected a fileless Meterpreter command-and-control (C2) stager into `explorer.exe`, and executed Active Directory reconnaissance using SharpHound.

The adversary subsequently targeted a high-privilege service account (`svc_sql_prod_migration`) to execute an **AS-REP Roasting attack**. 

Because this service account was a pre-configured **Active Directory Honeytoken**, the request instantly generated a maximum-severity alert in Splunk. The automated **Micro-SOAR** containment engine responded within minutes of the risk score crossing threshold, deploying host isolation rules via WinRM that completely severed the adversary's C2 connection while maintaining SOC forensic access.

No domain compromise, privilege escalation, or unauthorized data exfiltration occurred.

---

## 2. Key Metrics & Incident Timeline

| Metric | Measured Value | Benchmark / SLA Target |
|---|---|---|
| **Mean Time to Detect (MTTD)** | **< 2 minutes** (bounded by the 1-minute honeytoken-detection and master-correlation search intervals) | < 15 minutes |
| **Mean Time to Contain (MTTC)** | **< 3 minutes end-to-end** (detection interval + SOAR webhook + WinRM firewall injection, the last step itself completing in seconds) | < 30 minutes |
| **Data Loss Impact** | **0 bytes** (Containment enforced prior to credential harvesting) | 0 bytes |

### Chronological Event Timeline

| Timestamp (UTC) | Source / Component | Event Description | Forensic Indicator |
|---|---|---|---|
| `14:18:02` | `HR-01` (Sysmon EID 11) | User downloads `invoice.docm` via Google Chrome | File creation in `\Downloads\` |
| `14:18:03` | `HR-01` (Sysmon EID 15) | Windows Mark of the Web attached to document | `Zone.Identifier` (`ZoneId=3`) |
| `14:19:15` | `HR-01` (Sysmon EID 1) | Macro executes; spawns child `powershell.exe` | Parent: `winword.exe` |
| `14:19:40` | `HR-01` (Sysmon EID 8) | Remote thread injected into native system process | Target: `explorer.exe` |
| `14:20:00` | Zeek (`conn.log`) | High-frequency C2 beaconing initiated (Port 443) | Strict 2.0-second delta |
| `14:20:02` | Suricata (`eve.json`) | Meterpreter TLS Client Hello JA4 fingerprint match | `t13d1516h2_8daaf...` |
| `14:21:30` | SilkETW | SharpHound in-flight LDAP enumeration queries | YARA rule: `ASREPRoastScan` |
| `14:22:10` | AD DC (WinEvent 4768) | Honeytoken AS-REP ticket requested (`PreAuthType: 0`) | Target: `svc_sql_prod_migration` |
| `14:22:11` | Splunk SIEM | Master RBA correlation engine declares threshold breach | Risk Score: 100 |
| `14:22:12` | Micro-SOAR | Flask webhook dispatches `isolate_host.ps1` via WinRM | Management Plane (V.S 2) |
| `14:22:13` | `HR-01` (Firewall) | Draconian firewall block rules enforced | Inbound/Outbound severed |

---

## 3. Scope of Impact & Compromise Assessment

* **Affected Endpoints**: Workstation `HR-01` (`10.0.0.15`).
* **Compromised Accounts**: None. The targeted account `svc_sql_prod_migration` was protected by a random 64-character uncrackable password.
* **C2 Persistence**: Fully severed. The injected thread in `explorer.exe` was neutralized via network isolation and subsequent process termination.
* **Domain Integrity**: 100% intact. Active Directory schemas, GPOs, and Kerberos keys remained uncompromised.

---

## 4. Root Cause Analysis (RCA)

1. **Initial Access**: Execution of weaponized VBA macro inside an email attachment delivered via cleartext web download.
2. **Defensive Gaps Identified**:
   * Endpoint was not enforcing Microsoft Office attack surface reduction (ASR) rules preventing Office applications from spawning child processes.
   * Legacy RC4 encryption (`0x17`) was permitted domain-wide, allowing adversaries to request downgrade tickets during Kerberos requests.

---

## 5. Strategic Hardening Recommendations

### Immediate Actions Completed
* Endpoint `HR-01` re-imaged and restored from known-good baseline.
* Domain Controller Kerberos logs audited for any additional `PreAuthType: 0` anomalies.

### Long-Term Architectural Remediations
1. **Enforce Attack Surface Reduction (ASR) via Group Policy**:
   * Block WinWord from creating child processes (`D4F940AB-401B-4EFC-AADC-AD5F3C50688A`).
   * Block Office applications from injecting code into other processes (`75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84`).
2. **Deprecate Kerberos RC4 Encryption**:
   * Configure Active Directory Group Policy: *Network security: Configure encryption types allowed for Kerberos* to strictly permit `AES128_HMAC_SHA1` and `AES256_HMAC_SHA1`.
3. **Domain-Wide PowerShell Script Block Logging**:
   * Enable Windows Event ID 4104 via GPO across all domain workstations to eliminate memory blindspots caused by unmanaged PowerShell wrappers.
