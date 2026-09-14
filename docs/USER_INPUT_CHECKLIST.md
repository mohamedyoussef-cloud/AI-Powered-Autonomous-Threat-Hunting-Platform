# Information and files required from the project team

## Required now

1. **Actual dataset locations**
   - MITRE ATT&CK Enterprise STIX 2.1 bundle used by the team.
   - Local clone or archive of the Sigma repository.
   - BOTS v3 files or the accessible Splunk instance containing the indexed dataset.
   - Local clone/archive of EVTX-ATTACK-SAMPLES.

2. **Execution environment**
   - Operating system used for development.
   - Python version.
   - Whether Docker is allowed.
   - Available RAM, CPU, GPU, and storage.

3. **Splunk details**
   - Splunk Enterprise or another edition/version.
   - Local installation, VM, container, or remote instance.
   - Read-only test credentials or confirmation that credentials will remain in a local `.env` file.
   - Existing indexes and sourcetypes for BOTS v3.

4. **Approved platform scope**
   - Confirm whether the complete implementation must support Splunk, Elastic, and Sentinel simultaneously.
   - Confirm whether Windows, Linux, network, identity, AWS, Azure AD, and Office 365 are all required in the first full release.

5. **Ground-truth ownership**
   - Who will approve malicious/benign/requires-review labels?
   - Is a cybersecurity analyst available to review ambiguous findings?

## Required before ML dataset construction

- Asset criticality scale and sample asset inventory.
- Business-hours definition and timezone.
- User privilege/role information or a synthetic equivalent.
- Allowlist policy for administrative tools and service accounts.
- Labeling guidelines and reviewer identities/roles.

## Required before LLM fine-tuning

- Exact Mistral model/version and runtime.
- Hardware constraints.
- Allowed training framework.
- Approval of the instruction/output schema.
- Rules for handling Sigma licenses, attribution, and redistribution.

## Security rule

Do not send production passwords, private keys, tokens, or unrestricted SIEM credentials. Store secrets locally in `.env`; provide only non-secret configuration values and sanitized samples in shared artifacts.
