# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities **privately** via GitHub's private
vulnerability reporting: open the repository's **Security** tab and click
**Report a vulnerability** (Security → Advisories → Report a vulnerability).

This routes the report to the maintainers without public disclosure. Do not
open a public issue or pull request for a suspected vulnerability. We aim to
acknowledge reports within a few days and will coordinate a fix and disclosure
timeline with you.

## Supported versions

This project is pre-1.0 (0.x). Security fixes are applied to the latest
released `0.x` line only; please upgrade to the most recent release before
reporting.

| Version | Supported |
| ------- | --------- |
| 0.2.x   | Yes       |
| < 0.2   | No        |

## Transport security note

The Vanderbilt SPC EDP v2 transport carried by this SDK is **either plaintext
or AES-128-ECB**, and in **neither mode does it provide a message
authentication code (MAC)**. Consequences:

- Plaintext frames offer no confidentiality and no integrity protection.
- AES-128-ECB frames are confidential only at the block level (identical
  plaintext blocks produce identical ciphertext) and, lacking a MAC, are not
  protected against tampering or replay.

This is a property of the EDP protocol itself, not of this implementation, and
cannot be fixed in the SDK. Run the EDP receiver on a **trusted, isolated
network segment**, or tunnel the connection over a transport that provides
confidentiality and integrity (for example a VPN or an SSH/TLS tunnel) when it
must traverse an untrusted network.
