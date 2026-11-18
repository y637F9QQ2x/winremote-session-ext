# Security policy

## Reporting a vulnerability

Please report a vulnerability in this extension through GitHub private
vulnerability reporting on this repository (Security tab, "Report a
vulnerability"). Do not open a public issue for it.

A problem in winremote-mcp itself belongs to the upstream project:
https://github.com/dddabtc/winremote-mcp/security/policy

## Supported versions

There are no tagged releases yet. Fixes go to the main branch only.

## What this extension does and does not protect

README.md, section "Security and trust model", states the trust model: who
the API key holder is, which transports are acceptable, and which risks stay
with the operator. In short: anyone with the API key controls every enabled
tool as the server's Windows account, which with the default tool tiers
includes running commands, and a local administrator of the machine can read
that key.
