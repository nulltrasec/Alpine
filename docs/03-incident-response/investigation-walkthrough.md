# Incident Response: Step-by-Step Forensic Investigation Walkthrough

## 1. Investigation Initialization & Trigger Verification

The investigation initiates following an automated containment alert dispatched by the Alpine Micro-SOAR engine (`10.254.2.100`), which successfully quarantined endpoint `HR-01` (`10.0.0.15`).

### Step 1: Validating the Honeytoken Alert (Event ID 4768)
The initial pivot begins inside the SIEM by examining the alert payload from the Domain Controller (`10.0.0.10`):

```splunk
index=endpoint_data EventCode=4768 TargetUserName="svc_sql_prod_migration"
```

* **Observation**: Windows Security Event ID 4768 confirms a Ticket-Granting Ticket (TGT) request.
* **Forensic Indicators**:
  * `PreAuthType: 0`: Confirms that Kerberos Pre-Authentication was not performed, validating that an attacker leveraged the `DONT_REQ_PREAUTH` configuration for AS-REP roasting.
  * `TicketEncryptionType: 0x17`: Verifies that the client requested legacy RC4-HMAC encryption.
  * `ClientAddress`: `10.0.0.15`, matching the isolated workstation `HR-01`.

---

## 2. Endpoint Process & Network Telemetry Correlation

### Step 2: Scoping Sysmon Network Telemetry (Event ID 3)
Because Sysmon Event ID 3 (Network Connections) generates massive data volumes, searching an arbitrary 30-minute window creates excessive noise. The hunt is narrowly scoped to a **10 to 60-second window** preceding the Kerberos alert timestamp.

```splunk
index=endpoint_data EventCode=3 Computer="HR-01" DestinationPort=88
```

* **Observation**: Sysmon logs outbound traffic to port 88 on `10.0.0.10`.
* **Anomaly**: The initiating binary is `C:\Windows\explorer.exe`.
* **Deduction**: Under standard Windows baseline operations, `explorer.exe` never initiates outbound Kerberos authentication traffic over port 88. This anomalous origin strongly indicates process injection.

---

## 3. Process GUID Pivoting & Injection Analysis

### Step 3: Extracting the Unique Process GUID
Operating systems dynamically recycle Process IDs (PIDs). A PID observed at 14:21 may belong to an entirely different executable minutes later. Sysmon solves this via the `ProcessGuid`, an immutable, globally unique identifier generated per process execution.

* **Extracted Value**: `TargetProcessGuid = {D6E87A12-2210-66E8-0000-00103A820100}` (`explorer.exe`)

### Step 4: Tracking Process Injection (Sysmon Event ID 8 & Event ID 10)
Using the extracted GUID as `TargetProcessGuid`, the analyst queries cross-process injection telemetry:

```splunk
index=endpoint_data EventCode IN (8, 10) TargetProcessGuid="{D6E87A12-2210-66E8-0000-00103A820100}"
```

* **Event ID 8 (CreateRemoteThread)**:
  * `SourceProcessGuid`: `{D6E87A12-2150-66E8-0000-00109F710100}`
  * `SourceImage`: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
  * `StartFunction`: `0x00007FFD3A201000` (Unbacked memory region)
* **Deduction**: A rogue thread was injected directly into `explorer.exe` originating from `powershell.exe`.

---

## 4. Root Cause Ancestry & Fileless Memory Extraction

### Step 5: Tracing Process Lineage (Sysmon Event ID 1)
Querying Sysmon Event ID 1 with the `SourceProcessGuid` reveals the parent process tree of the PowerShell engine:

```splunk
index=endpoint_data EventCode=1 ProcessGuid="{D6E87A12-2150-66E8-0000-00109F710100}"
```

* **Observation**:
  * `ParentImage`: `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`
  * `CommandLine`: `powershell.exe -nop -w hidden -e JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgA...`
* **Deduction**: Microsoft Word executed a macro that spawned PowerShell, passing the entire payload via an encoded command-line string. **No `.ps1` file was written to disk.**

### Step 6: Extracting the In-Memory Stager (Event ID 4104)
To recover the actual Meterpreter shellcode for reverse engineering without a dropped file, the analyst leverages **Script Block Logging**:

```splunk
index=endpoint_data EventCode=4104 Computer="HR-01"
```

* **Observation**: Splunk displays the completely de-obfuscated script block captured in memory just before execution. Inside the log, the analyst finds the raw byte array of the injected shellcode:
  `[Byte[]]$buf = 0xfc,0x48,0x83,0xe4,0xf0,0xe8...`
* **Forensic Action**: The analyst copies this byte array, converts it to a raw `.bin` file, and loads it into Ghidra and BlobRunner for deep technical analysis.

---

## 5. Ingress Attribution: Mark of the Web Verification

### Step 7: Identifying the Initial Phishing Vector
Since `WINWORD.EXE` was the parent process, the analyst investigates how the malicious document reached the system.

```splunk
index=endpoint_data EventCode=11 TargetFilename="*\\Downloads\\*.docm"
```

* **Observation**: `chrome.exe` created `C:\Users\victim\Downloads\invoice.docm`.

### Step 8: Proving Internet Origin (Sysmon Event ID 15)
To definitively confirm whether `invoice.docm` originated from an external threat actor rather than a local USB or internal file share:

```splunk
index=endpoint_data EventCode=15 TargetFilename="*invoice.docm:Zone.Identifier*"
```

* **Observation**: Sysmon Event ID 15 logs the creation of the NTFS Alternate Data Stream (ADS) `invoice.docm:Zone.Identifier`.
* **Contents**: `ZoneId=3` (Windows Mark of the Web - Internet Zone).
* **Conclusion**: The malicious document was downloaded directly from an untrusted internet source via Google Chrome, establishing complete forensic causality from the initial phishing ingress to the fileless memory injection and Active Directory exploitation.
