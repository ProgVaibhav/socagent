# Endpoint threats runbook

## Office spawning scripting engines
Word, Excel or Outlook launching PowerShell, mshta, wscript or rundll32 is a classic malicious-document pattern.
Isolate the host if the command line downloads or decodes content. Collect the document and the process tree.

## Encoded PowerShell
PowerShell with -EncodedCommand or FromBase64String from a user context is high risk. Decode the command in a sandbox before deciding.
