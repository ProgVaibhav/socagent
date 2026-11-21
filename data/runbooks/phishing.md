# Phishing response runbook

## Scope
Applies to emails reported by employees through the Report Phishing button or forwarded to the phishing mailbox.

## Triage
Check SPF, DKIM and DMARC results. Check sender domain age and reputation. Check every URL domain and attachment hash.
A newly registered domain (under 30 days) that imitates a company domain is a strong credential phishing signal.

## Credential phishing containment
If a user clicked a credential phishing link or entered a password: revoke all sessions for the user, force a password reset, and review sign-in logs for the last 24 hours.
Block the phishing domain on the proxy and mail gateway. Search the mail system for other recipients and purge the message.

## Malware attachment containment
If an attachment hash is known malicious and the user opened it: isolate the host via EDR, then collect triage artefacts.
Block the hash in EDR.

## Benign and marketing email
Legitimate marketing or internal mail: close as benign, thank the reporter, and tune the report if the same sender is reported repeatedly.
