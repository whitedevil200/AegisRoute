# Security policy

## Supported version

Security fixes are made against the latest 3.x release.

## Reporting a vulnerability

Do not open a public issue for a suspected security vulnerability. Contact the repository owner privately with a concise reproduction, affected version, impact, and any suggested mitigation. Please allow reasonable time for triage before public disclosure.

## Operational guidance

Run AegisRoute only against destinations you are authorized to measure. Treat JSON/HTML reports as potentially sensitive operational data: they can include public route addresses, reverse-DNS names, and optional location or routing context. The remote agent is intentionally read-only; keep it on loopback or behind authenticated TLS.
