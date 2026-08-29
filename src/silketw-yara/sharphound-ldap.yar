/*
  Alpine Project - SharpHound & Active Directory Reconnaissance YARA Signatures
  Purpose: Detects SharpHound, BloodHound, and Kerberos enumeration queries
           within ETW Microsoft-Windows-LDAP-Client telemetry via SilkETW.
*/

rule AdminScanning
{
    meta:
        description = "Detects LDAP search queries enumerating high-privilege administrative groups"
        author = "Alpine Detection Engineering Team"
        reference = "MITRE ATT&CK T1069.002 - Permission Groups Discovery"
        threat_score = "80"
    strings:
        $s1 = "Domain Admins" ascii wide nocase
        $s2 = "Enterprise Admins" ascii wide nocase
        $s3 = "Schema Admins" ascii wide nocase
        $s4 = "Administrators" ascii wide nocase
    condition:
        any of ($s*)
}

rule SPNScanning
{
    meta:
        description = "Detects LDAP filter queries searching for Service Principal Names (Kerberoasting Recon)"
        author = "Alpine Detection Engineering Team"
        reference = "MITRE ATT&CK T1558.003 - Kerberoasting"
        threat_score = "80"
    strings:
        $s1 = /serviceprincipalname=\*/ ascii wide nocase
        $s2 = /serviceprincipalname=\*\/\*/ ascii wide nocase
    condition:
        any of ($s*)
}

rule ASREPRoastScan
{
    meta:
        description = "Detects LDAP filter targeting DONT_REQ_PREAUTH bit (4194304) for AS-REP Roasting discovery"
        author = "Alpine Detection Engineering Team"
        reference = "MITRE ATT&CK T1558.004 - AS-REP Roasting"
        threat_score = "90"
    strings:
        // Bitmask 4194304 corresponds to ADS_UF_DONT_REQUIRE_PREAUTH (0x400000)
        $s1 = /userAccountControl:1\.2\.840\.113556\.1\.4\.803:=4194304/ ascii wide nocase
        $s2 = /userAccountControl:.*=4194304/ ascii wide nocase
    condition:
        any of ($s*)
}
