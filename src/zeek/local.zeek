# ==============================================================================
# Alpine Lab Zeek Network Security Monitoring Site Policy
# ==============================================================================

# Force Zeek to write logs in JSON format for automated Splunk ingestion
@load policy/tuning/json-logs.zeek

# Enable Community ID calculation across all connection logs
# Matches Suricata community_id flow hashing for unified SIEM pivots.
# Zeek 4.0+ ships this as a built-in policy script; if you're on an older
# Zeek that still needs the external package, swap this back to
# `@load packages/zeek-community-id`.
@load policy/protocols/conn/community-id-logging

# Load standard protocol analyzers
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/ssl
@load protocols/http
@load protocols/dns

redef LogAscii::use_json = T;
redef Log::default_rotation_interval = 1 hrs;

# Custom tuning: Ensure all network flow fields are serialized cleanly
event zeek_init()
    {
    print "[+] Alpine Lab Zeek Engine Initialized: JSON Logging & Community ID Active";
    }
