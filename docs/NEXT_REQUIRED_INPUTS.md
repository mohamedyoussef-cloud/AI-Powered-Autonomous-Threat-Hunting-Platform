# Next Required Inputs — v0.4.0

ATT&CK, Sigma, EVTX-ATTACK-SAMPLES, and the BOTS v3 source archive have been received.

## Required to continue BOTS event export and canonical normalization

Provide the execution environment:

- Operating system and version
- Python version
- RAM and CPU
- GPU and VRAM, if any
- Free storage
- Docker allowed: Yes / No
- Splunk Enterprise installed: Yes / No
- Splunk Enterprise version, if installed
- Preferred deployment: local / VM / Docker / remote
- Target backends: Splunk / Elastic / Microsoft Sentinel

Do not send credentials, passwords, or tokens in chat.

The next technical stage is to load BOTS v3 into Splunk, validate the `2,030,269` active event count, run field profiling for all 107 sourcetypes, and export bounded event batches for canonical telemetry normalization.
