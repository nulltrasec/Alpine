# Detection Engineering: Splunk Risk-Based Alerting (RBA) Framework

## 1. Traditional Alerting vs. Risk-Based Alerting (RBA)

Traditional Security Information and Event Management (SIEM) architectures rely on atomic, threshold-based rules. If an individual rule fires (e.g., an unusual network connection or an LDAP query), an alert is generated. In modern enterprise environments, this creates severe **alert fatigue**, leading analysts to ignore subtle or noisy detections.

**Splunk Risk-Based Alerting (RBA)** fundamentally transforms this approach:
1. Individual detection rules do **not** wake up analysts or generate urgent tickets.
2. Instead, rules write a standardized risk attribution event into Splunk's dedicated `risk` index, attributing a defined numerical **Risk Score** to a specific entity (`risk_object`, e.g., a workstation IP or username).
3. A centralized **Risk Incident Rule** aggregates cumulative risk over a moving time window (e.g., 10 minutes).
4. Only when an asset's cumulative risk score crosses the threshold of **100 points** does the system declare an active security incident and dispatch automated SOAR playbooks.

---

## 2. The Alpine Risk Matrix & Detection Rules

| Detection Logic | Source Telemetry | Target MITRE Technique | Risk Score | Rationale |
|---|---|---|:---:|---|
| **Honeytoken AS-REP Roasting** | Windows EID 4768 | T1558.004 | **100** | Zero false-positive canary; justifies immediate containment. |
| **SharpHound LDAP Enumeration** | SilkETW JSON | T1069.002 | **80** | High-fidelity YARA match on in-flight LDAP query structure. |
| **Injected Explorer Kerberos** | Sysmon EID 3 | T1055 / T1558 | **40** | Anomalous parent process initiating port 88 authentication. |
| **Meterpreter C2 Beaconing** | Zeek `conn.log` | T1071.001 | **40** | Rigid 2.0-second delta with uniform payload byte sizes. |
| **JA4 TLS Fingerprint Match** | Suricata `eve.json` | T1071.001 | **40** | Exact Client Hello cipher/extension fingerprint match. |

---

## 3. Deep Dive: Key Detection SPL Implementations

### A. Zeek C2 Beaconing Analytics via `streamstats`
Detecting automated C2 communication over encrypted TLS cannot rely on packet payload inspection. Instead, Alpine evaluates **behavioral rhythm** using the `streamstats` non-transformative command:

```splunk
index="network_data" source="*conn.log" sourcetype="_json"
| sort _time
| streamstats current=f window=1 last(_time) as prev_time by id.orig_h, id.resp_h, orig_bytes
| eval time_delta = round(_time - prev_time, 0)
| stats count by id.orig_h, id.resp_h, orig_bytes, time_delta
| where count >= 50 and time_delta == 2
```

* **`current=f window=1`**: Looks strictly one step backward to compute the exact timestamp delta between consecutive connections.
* **`by id.orig_h, id.resp_h, orig_bytes`**: Groups calculations by unique host pairs and payload size. Normal web browsing has random intervals and fluctuating sizes. An automated Meterpreter beacon transmits identical byte sizes at mathematically precise intervals (2 seconds).
* **`where count >= 50 and time_delta == 2`**: Eliminates transient network bursts, firing only after sustained, automated beaconing is proven.

### B. Suricata JA4 Cryptographic Fingerprinting
While TLS 1.3 payloads are encrypted, the initial **Client Hello** packet is transmitted in cleartext. JA4 extracts:
1. Transport protocol and TLS version.
2. Number of ciphers and extensions.
3. First and last cipher suites.
4. Truncated SHA-256 hash of sorted extensions and elliptic curve algorithms.

```splunk
index=network_data sourcetype=suricata_json event_type=tls
| search tls.ja4="t13d1516h2_8daaf6152771_a00000000000"
| stats count by src_ip, dest_ip, dest_port, tls.ja4, tls.sni
| where count > 0
```
This fingerprint remains identical regardless of destination IP or domain name changes, defeating adversary proxy infrastructure.

---

## 4. Master Risk Correlation & SOAR Webhook Execution

The master correlation search continuously evaluates the `risk` index:

```splunk
index=risk earliest=-10m
| stats sum(risk_score) as total_risk, values(threat_technique) as techniques by risk_object
| where total_risk >= 100
```

When `HR-01` accumulates risk points crossing the 100-point ceiling, Splunk triggers an automated HTTP POST webhook to `http://10.254.2.100:5000/isolate`. The Flask Micro-SOAR listener authenticates via WinRM on V.S 2 and enforces immediate network quarantine.
