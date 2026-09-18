# Post-Incident Detection: Email-Based Phishing Triage

## 1. Why This Exists

The incident documented in [incident-response-report.md](incident-response-report.md) started with a spearphishing attachment (`invoice.docm`) reaching `HR-01` -- see [attack-chain.md](../02-threat-model-and-attack/attack-chain.md), Step 1. Every other detection mechanism in this lab (Zeek, Suricata, Sysmon, SilkETW) picks the intrusion up *after* that document is opened. This script targets the step before that: triaging inbound mail before a user ever clicks anything.

It was added after the incident, as a detective control informed by the RCA, not as part of the original simulated attack chain.

## 2. How It Works

`src/email-triage/phishing-ip-triage.py` polls a mailbox over IMAP and scores the IPs in each message's delivery path against threat intelligence:

1. Connects to `imap.gmail.com` and logs in with a Gmail **App Password** (not the account password).
2. Searches for `UNSEEN` messages in the inbox.
3. For each one, parses the raw MIME message and pulls every `Received` header -- the hop-by-hop chain of mail servers the message passed through.
4. Extracts IPv4 addresses from those headers with a regex and skips ones in private/internal ranges (`10.`, `192.168.`, `172.`, `127.`) -- those are hops inside Gmail's own infrastructure, not the sender's origin.
5. Queries the remaining IPs against [AbuseIPDB](https://www.abuseipdb.com/)'s `/check` endpoint (90-day lookback) and flags anything with an abuse confidence score above 50% as high risk.

## 3. Setup

```bash
pip install -r src/email-triage/requirements.txt
```

The script refuses to run unless all three of these are set in the environment:

| Variable | What it is |
|---|---|
| `ALPINE_TRIAGE_EMAIL_USER` | The mailbox address to poll |
| `ALPINE_TRIAGE_EMAIL_APP_PASSWORD` | A Gmail **App Password** generated for that account -- not the real account password |
| `ALPINE_ABUSEIPDB_API_KEY` | An AbuseIPDB API key (free tier is sufficient) |

## 4. Design Notes & Limitations

Kept honest rather than overstated, in line with the rest of this repo:

* **Fetching marks mail as read.** `mail.fetch(e_id, '(RFC822)')` pulls the full message and, as a side effect of IMAP, flips it from `UNSEEN` to `Seen` on the server. Re-running the script won't re-check the same message.
* **One-shot, not a service.** This is a script you run, not a daemon -- there's no built-in scheduling. Continuous coverage would mean wrapping it in a cron job (or Task Scheduler) rather than anything implemented here.
* **Console output only.** Results print to stdout; they aren't (yet) written anywhere Splunk could ingest them. Extending `inputs.conf` with a monitor stanza over a JSON-lines output file would be the natural next step, but that's not built.
* **The private-range filter is a coarse heuristic.** `ip.startswith('172.')` excludes all of `172.0.0.0/8`, not just the true private slice (`172.16.0.0/12`) -- fine for this lab, where no internal address outside `172.16.0.0/12` would ever appear, but worth knowing if reused elsewhere.
* **This is the one component in the repo that talks to the real internet.** Everything else here (Zeek, Suricata, Sysmon, the SOAR listener) operates on simulated traffic inside the isolated lab network. This script deliberately polls a real Gmail inbox and calls a real threat-intel API, because phishing triage only means something against real-world sending infrastructure.
