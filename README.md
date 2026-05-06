# Loc'd Protocol Specification

**Version:** 0.1.1  
**Status:** Draft  
**Date:** February 17, 2026  
**License:** CC BY 4.0  

---

## What is Loc'd?

Loc'd is an open protocol for **hardware-bound, user-sovereign digital identity and encrypted connectivity**.

It enables you to:
- Prove your identity using keys stored in device hardware (TPM/Secure Enclave)
- Publish your public identity to DNS (no blockchain required)
- Establish encrypted peer-to-peer connections without open ports
- Delegate scoped, time-limited authority to devices and agents

**No shared secrets. No third-party identity providers. No central infrastructure.**

---

## Quick Links

- **[Full Specification](locd-protocol-spec-v0.1.md)** — Complete protocol definition
- **[License](LICENSE)** — Creative Commons Attribution 4.0 International

---

## Why Another Protocol?

Current authentication models have three fundamental problems:

1. **Borrowed identity** — Providers can revoke your access unilaterally
2. **Discovery-based connectivity** — Exposing endpoints creates attack surface
3. **Static, unscoped trust** — Credentials grant binary access with no constraints

Loc'd inverts the trust model. You hold the root of trust. Services verify against your published identity. Delegation tokens grant precise, revocable authority.

---

## Key Features

| Feature | Loc'd |
|---------|-------|
| User owns identity | ✅ Yes |
| Hardware-bound keys | ✅ Required |
| No shared secrets | ✅ Yes |
| Scoped delegation | ✅ Yes |
| Time-limited auth | ✅ Yes (24h default) |
| User-controlled revocation | ✅ Instant |
| No vendor dependency | ✅ Yes |
| Works without server | ✅ Yes |

---

## Repository Structure

spec/
├── LICENSE # CC BY 4.0
└── locd-protocol-spec-v0.1.md # Full specification (v0.1.1)

text

---

## Contributing

This specification is open for review and feedback. Issues and pull requests welcome.

Maintainer: Lane (12wqa)

---

## Implementations

| Project | Description | Status |
|---------|-------------|--------|
| *Coming soon* | Reference implementation | Planned |

---

## License

This specification is licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.

You are free to share and adapt this work for any purpose, including commercially, as long as you provide appropriate credit.

---

**Built with conviction in Melbourne, Australia.**
