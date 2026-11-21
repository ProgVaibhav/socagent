# Identity threats runbook

## MFA fatigue
Many MFA push prompts in a short window (five or more in ten minutes) followed by an approval indicates MFA fatigue (ATT&CK T1621).
Revoke sessions, reset the password, and contact the user out of band. Move the user to number matching or phishing-resistant MFA.

## Impossible travel
Sign-ins from locations that are physically impossible to travel between. First check whether either IP belongs to the corporate VPN or a cloud provider.
If not explained, treat as account compromise: revoke sessions and reset credentials.
