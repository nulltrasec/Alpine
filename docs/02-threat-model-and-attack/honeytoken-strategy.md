# Deception Engineering: Active Directory Honeytoken Strategy

## 1. The Strategic Concept: Active Directory Honeytokens

In modern SOC operations, behavioral detection and anomaly baselining often suffer from noise and false positives. Deception Engineering solves this problem by planting canary assets that legitimate users and systems have zero operational reason to touch. 

When an adversary conducts internal Active Directory reconnaissance using tools like **BloodHound**, **SharpHound**, or **Rubeus**, they query the Domain Controller via LDAP to identify low-hanging fruit. One of the most desirable targets is accounts vulnerable to **AS-REP Roasting** (MITRE ATT&CK T1558.004).

---

## 2. Technical Vulnerability Mechanics: AS-REP Roasting

Standard Kerberos authentication requires the client to encrypt a timestamp using a key derived from the user's password before the Domain Controller issues a Ticket-Granting Ticket (TGT). This process is known as **Kerberos Pre-Authentication**.

If the Active Directory attribute `DONT_REQ_PREAUTH` (bitmask `4194304` or `0x400000` in `userAccountControl`) is enabled:
1. Anyone on the network can send an `AS-REQ` packet to the KDC (port 88) for that username.
2. The KDC immediately replies with an `AS-REP` packet containing an encrypted session key and TGT encrypted with the target account's password hash.
3. The attacker extracts the ciphertext (`$krb5asrep$23$...`) and attempts offline password cracking using Hashcat or John the Ripper without generating failed logon events on the Domain Controller.

---

## 3. Engineering the Alpine Deception Trap

To make the honeytoken irresistible to an attacker while preventing it from becoming an actual liability, Alpine incorporates three critical design principles:

### A. The Bait (High Value & Realistic Naming)
* **Account Name**: `svc_sql_prod_migration`
* **Description**: `"Service Account for Legacy SQL Cluster Migration and ETL Pipeline"`
* **Privileged Groups**: `Server Operators`, `Backup Operators`
* **Realism Rationale**: Attackers specifically hunt for service accounts because they frequently retain legacy settings and excessive privileges. Naming it something obvious (like `honey_test` or `admin_trap`) alerts sophisticated actors immediately.

### B. The Deception Paradox (Active History vs. Uncrackable Password)
* **The Problem**: Attackers inspect `pwdLastSet` and `lastLogonTimestamp`. If a privileged account was created recently and has a NULL `lastLogonTimestamp`, it is flagged as a honeypot.
* **The Automation**: The companion script `simulate-dummy-logon.ps1` runs periodically on the Domain Controller to update the account's directory timestamps, maintaining the illusion of an active production service.
* **The Defense**: The account is assigned a cryptographically random **64-character password**. Even though the attacker successfully captures the AS-REP ticket, offline cracking will never succeed within the lifetime of the universe.

### C. The 0% False-Positive Detection Trigger
Because this account performs no human operational duties, any interaction with it is by definition malicious. In Splunk, the detection rule is lightweight and immediate:

```splunk
index=endpoint_data EventCode=4768 TargetUserName="svc_sql_prod_migration" PreAuthType=0 TicketEncryptionType=0x17
```

* **EventCode 4768**: A Kerberos authentication ticket (TGT) was requested.
* **PreAuthType 0**: Pre-authentication was explicitly bypassed (`DONT_REQ_PREAUTH`).
* **TicketEncryptionType 0x17**: Specifies RC4-HMAC encryption, confirming that the attacker requested legacy cipher suites to expedite offline cracking.

When this event fires, the SOC has 100% confidence of an active adversary in the environment, justifying instantaneous automated host isolation.
