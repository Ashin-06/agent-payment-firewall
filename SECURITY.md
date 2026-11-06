# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately, through GitHub's private vulnerability
reporting on this repository (Security → Report a vulnerability) or by contacting the
maintainer, [@Ashin-06](https://github.com/Ashin-06), directly. Do not open a public issue.

Include what you found, how to reproduce it and what an attacker could do with it. You should
get an acknowledgement within 5 working days. Please give us 90 days to fix an issue before
disclosing it, and don't test against anyone else's deployment.

## Supported versions

| Version | Supported |
|---|---|
| 1.5.x | yes |
| 1.1.x to 1.4.x | no: see the changelog for what they let through |
| 1.0.x | no: see the changelog for what it let through |
| < 1.0 | no (prototype releases) |

## Scope

In scope: the gateway (policy engine, mandate parser, provenance tracking, injection scanner), the approval
queue, the audit chain, the console API and page, the assistant loop, the container image and
the CI configuration in this repository. A tool call that moves money the customer didn't ask for
without their confirmation is the most serious class of finding. A sentence the mandate parser
reads as a request when it isn't one counts.

Out of scope: the demo bank (`agentfw/bank.py`, an in-memory stand-in), the model provider,
your reverse proxy or TLS setup, and findings that need an already-compromised host or a leaked
API key with the matching role.

This project has **not** had an independent security review or penetration test.
