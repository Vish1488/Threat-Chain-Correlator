# ThreatChain Correlator

> Detects multi-stage AWS attack sequences using temporal correlation across CloudTrail logs — not just individual suspicious events.

---

## The Problem With Single-Event Detection

An IAM `ListUsers` call alone is noise — could be a developer exploring the console.
An `AssumeRole` call alone is noise — happens constantly in any AWS account.
An S3 `GetObject` alone is noise — completely normal behaviour.

**All three from the same identity, in sequence, within 15 minutes?**
That is a credential theft → privilege escalation → data exfiltration chain.
That is an incident.

This is the difference between **alert generation** and **detection engineering**.

---

## Attack Chain Detected

### Chain 1 — IAM Recon → Privilege Escalation → S3 Exfiltration

| Stage | Actor | API Calls | MITRE TTP |
|-------|-------|-----------|-----------|
| 1 — Recon | compromised-dev-user | ListUsers, ListRoles, ListPolicies, ListGroups, GetAccountAuthorizationDetails | T1580 |
| 2 — Privilege Escalation | compromised-dev-user | AssumeRole → priv-data-role | T1548 |
| 3 — Exfiltration | assumed-role/priv-data-role | ListObjects, GetObject on sensitive S3 bucket | T1530 |

**Correlation window: 15 minutes · Same actor · Temporally ordered**

The key insight: after `AssumeRole`, the actor identity changes from `compromised-dev-user` to `assumed-role/priv-data-role`. The engine dynamically resolves this identity transition and correlates across both identities — something single-event detection cannot do.

---

## Sample Alert Output

```
=================================================================
  CRITICAL ALERT — ATTACK CHAIN DETECTED
=================================================================
  Chain:     IAM_RECON_PRIVESC_S3_EXFIL
  Actor:     compromised-dev-user
  Source IP: 49.43.24.78
  MITRE:     T1580 · T1548 · T1530

  Timeline:
    Recon started:   2026-03-22T15:17:08+00:00
    Priv esc at:     2026-03-22T15:17:49+00:00
    Exfil at:        2026-03-22T15:17:49+00:00

  Evidence:
    Recon calls:     ['ListUsers', 'ListRoles', 'ListPolicies', 'ListGroups', 'GetAccountAuthorizationDetails']
    Roles assumed:   ['priv-data-role']
    Buckets hit:     ['sensitive-data-threat-detection']
=================================================================
  Alert saved to output/alerts.json
```

---

## Architecture

```
AWS CloudTrail
      ↓
CloudWatch Logs
      ↓
ingestor.py        — fetches events via boto3, handles pagination + batching
      ↓
normalizer.py      — extracts actor, API call, timestamp, IP from raw CloudTrail JSON
      ↓
SQLite (events.db) — stores normalized events for temporal correlation
      ↓
engine.py          — correlation logic: checks all 3 attack stages per actor within time window
      ↓
alerter.py         — formats terminal output + saves to alerts.json
```

**No SIEM required.** Runs entirely on Python + boto3 + SQLite.
The same detection logic is expressed as a portable Sigma rule in `rules/` — convertible to Splunk SPL, Chronicle YARA-L, or Microsoft Sentinel KQL using sigma-cli.

---

## How The Correlation Engine Works

For each run, the engine:

1. Queries SQLite for all unique actors active in the last 15 minutes
2. For each actor, checks whether Stage 1 (3+ IAM recon calls), Stage 2 (AssumeRole), and Stage 3 (S3 GetObject) all occurred
3. Dynamically resolves the assumed role identity for Stage 3 correlation
4. Verifies temporal ordering — recon must precede privilege escalation, which must precede exfiltration
5. Fires a CRITICAL alert if all conditions are met
6. Marks events as processed to prevent duplicate alerts on subsequent runs

The temporal ordering check is what separates high-fidelity detections from false positives. An attacker who happened to access S3 at 9am and ran IAM enumeration at 11am does not trigger this rule.

---

## Tech Stack

- **Python 3.10+** with boto3
- **AWS CloudTrail** — management + S3 data events (free tier)
- **AWS CloudWatch Logs** — log delivery and querying
- **SQLite** — event state storage for temporal correlation (no external DB required)
- **Sigma rule** — portable detection logic in `rules/chain_iam_recon_exfil.yml`
- **colorama** — terminal alert formatting

---

## Project Structure

```
threat-chain-correlator/
├── main.py                          # Orchestrator — runs the full pipeline
├── config.example.py                # Config template — copy to config.py
├── requirements.txt
├── correlation/
│   ├── ingestor.py                  # CloudTrail event ingestion via boto3
│   ├── normalizer.py                # Raw CloudTrail JSON normalization
│   ├── engine.py                    # Temporal correlation engine (core logic)
│   └── alerter.py                   # Alert formatting and output
├── rules/
│   └── chain_iam_recon_exfil.yml    # Sigma rule — MITRE ATT&CK mapped
├── tests/
│   └── test_engine.py               # Unit tests for correlation logic
└── output/
    └── alerts.json                  # Auto-generated alert output
```

---

## Setup & Run

### Prerequisites
- Python 3.10+
- AWS account with CloudTrail + CloudWatch Logs enabled
- IAM user with CloudWatch Logs read access

### Install

```bash
git clone https://github.com/Vish1488/threat-chain-correlator
cd threat-chain-correlator
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Configure

```bash
cp config.example.py config.py
# Edit config.py with your AWS account details
```

### Run

```bash
# Simulate the attack chain against your own AWS account
python simulate_attack.py

# Wait 3-5 minutes for CloudTrail log delivery, then:
python main.py
```

---

## Sigma Rule

The detection logic is expressed as a Sigma rule for SIEM portability:

```bash
# Convert to Splunk SPL
sigma convert -t splunk rules/chain_iam_recon_exfil.yml

# Convert to Chronicle YARA-L
sigma convert -t chronicle rules/chain_iam_recon_exfil.yml

# Convert to Microsoft Sentinel KQL
sigma convert -t sentinel rules/chain_iam_recon_exfil.yml
```

---

## MITRE ATT&CK Coverage

| Tactic | Technique | ID | Detected Via |
|--------|-----------|-----|--------------|
| Discovery | Cloud Infrastructure Discovery | T1580 | 3+ IAM list API calls within correlation window |
| Privilege Escalation | Abuse Elevation Control Mechanism | T1548 | AssumeRole to privileged role following recon |
| Exfiltration | Data from Cloud Storage | T1530 | GetObject/ListObjects under assumed role identity |

---

## False Positive Considerations

- IAM administrators performing routine access reviews → allowlist known admin principals in `config.py`
- Automated compliance tools with broad IAM read permissions → add service account principals to exclusion list
- CI/CD pipelines with cross-account role assumptions → scope `PRIVESC_API_CALLS` to exclude known automation roles

---

## Security Notes

- All credentials loaded from environment variables — never hardcoded
- Lab work performed using scoped IAM user, not root account credentials
- For production deployments, CloudTrail logs should be encrypted with a Customer Managed KMS key
- `config.py` and `attack.py` are gitignored — see `config.example.py` for setup

---
