# Security and privacy

## Repository boundary

Never commit `.env`, private API tokens, authentication databases, credentials, raw telemetry with personal information, model training sources containing identifiers, internal GPU hostnames, or workstation paths. Public `.env.example` values must be non-sensitive placeholders.

## Application hardening requirements

The integrated auth code includes local **demonstration accounts and default credentials**. Treat these as **development-only**, not a production authentication system. Before exposing any endpoint outside a trusted local environment: disable/remove demo accounts and passwords; implement secure admin provisioning; supply a unique strong `THREATHUNT_AUTH_SECRET`; require HTTPS, authentication/authorization review, security logging and proper database access restrictions.

Security classification of a finding remains analyst-assisted; ML scores must not automatically close cases or suppress potential incidents. Validate SIEM connector permissions and audit operations separately from model evaluation.

## Reproducibility and private metadata

Preserve original frozen artifacts outside Git where they contain confidential paths, credentials or restricted data. Sanitized derivative manifests must be clearly labeled as derivatives and must not overwrite canonical evaluation evidence. Recheck all staged files before publication.
