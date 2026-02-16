# Loc'd Protocol Specification

**Version:** 0.1.0 (Draft)  
**Status:** Draft for Review  
**Date:** February 15, 2026  
**License:** CC BY 4.0  
**Authors:** Lane  
**Repository:** https://github.com/locd-protocol/spec

---

## Abstract

Loc'd is an open protocol for hardware-bound, user-sovereign digital identity and encrypted connectivity. It enables users to prove their identity cryptographically using keys stored in device hardware (TPM/Secure Enclave), publish their public identity to DNS, establish encrypted peer-to-peer connections without open ports, and delegate scoped authority to devices and agents — all without shared secrets, third-party identity providers, or centralised infrastructure.

This document specifies the protocol's data formats, cryptographic operations, verification procedures, and interaction flows in sufficient detail for independent implementation.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [Design Principles](#3-design-principles)
4. [Key Hierarchy](#4-key-hierarchy)
5. [Identity Layer](#5-identity-layer)
6. [Delegation Layer](#6-delegation-layer)
7. [Verification Layer](#7-verification-layer)
8. [Revocation Layer](#8-revocation-layer)
9. [Mesh Connectivity Layer](#9-mesh-connectivity-layer)
10. [Legacy Bridge Layer](#10-legacy-bridge-layer)
11. [Recovery](#11-recovery)
12. [DNS Record Formats](#12-dns-record-formats)
13. [Wire Formats](#13-wire-formats)
14. [Security Considerations](#14-security-considerations)
15. [IANA Considerations](#15-iana-considerations)
16. [References](#16-references)
17. [Appendix A: Example Flows](#appendix-a-example-flows)
18. [Appendix B: Comparison with Existing Standards](#appendix-b-comparison-with-existing-standards)

---

## 1. Introduction

### 1.1 Problem Statement

The internet's prevailing authentication model relies on shared secrets (passwords, API keys, OAuth tokens) mediated by third-party identity providers. This creates three fundamental vulnerabilities:

1. **Borrowed identity.** Users do not control their own identity. An identity provider can revoke access unilaterally, affecting all downstream services.
2. **Discovery-based connectivity.** Services expose public endpoints and filter access after discovery. The existence of the endpoint is itself an attack surface.
3. **Static, unscoped trust.** Credentials grant binary access with no constraints on scope, time, device, or action.

### 1.2 Solution Overview

Loc'd inverts the trust model:

- The **user** holds the root of trust (a hardware-bound master key).
- The **user** publishes their public identity (via DNS).
- **Services** verify against the user's published identity.
- **Connections** are encrypted tunnels established only after mutual cryptographic verification.
- **Delegation** allows devices and agents to act on the user's behalf with scoped, time-limited, revocable authority.

### 1.3 Scope

This specification defines:

- Key generation, storage, and lifecycle requirements
- DNS-based identity publication format
- Delegation token format and signing
- Challenge-response verification protocol
- Revocation mechanisms
- WireGuard-based mesh establishment after identity verification
- Recovery procedures

This specification does NOT define:

- Client user interface or user experience
- Specific hardware requirements beyond minimum capabilities
- Service-side business logic
- Legacy credential storage formats (implementation-specific)

### 1.4 Relationship to Existing Standards

Loc'd builds on and combines existing standards. It does not replace them.

| Standard | Role in Loc'd |
|----------|---------------|
| FIDO2/WebAuthn (W3C) | Cryptographic identity model, hardware key interaction via CTAP2 |
| WireGuard | Encrypted tunnel establishment for mesh connectivity |
| DNSSEC (RFC 4033-4035) | Integrity protection for published identity records |
| DNS-over-HTTPS (RFC 8484) | Privacy protection for identity lookups |
| CBOR (RFC 8949) | Binary encoding for delegation tokens |
| COSE (RFC 9052) | Signing and encryption of delegation tokens |
| Ed25519 (RFC 8032) | Default signature algorithm |
| X25519 (RFC 7748) | Default key agreement for tunnel establishment |

---

## 2. Terminology

| Term | Definition |
|------|-----------|
| **Master Key** | The Tier 1 key pair representing the user's sovereign identity. Generated and stored in a phone's secure enclave. |
| **Device Key** | A Tier 2 key pair generated in a device's TPM or secure enclave, authorised by the Master Key via a delegation token. |
| **Session Key** | A Tier 3 ephemeral key pair used for a single connection. Exists only in memory. |
| **Delegation Token** | A signed data structure granting a Device Key scoped authority to act on behalf of the Master Key. |
| **Identity Record** | A DNS TXT record publishing a user's public Master Key. |
| **Revocation Record** | A DNS TXT record or out-of-band publication listing revoked Device Keys or Delegation Tokens. |
| **Verifier** | Any service that checks a Loc'd identity and delegation before granting access. |
| **Claimant** | Any device presenting a Loc'd identity and delegation to a Verifier. |
| **Mesh** | A set of devices connected via WireGuard tunnels, authenticated by Loc'd identities. |
| **Legacy Bridge** | A client component that manages credentials for services that do not support Loc'd natively. |
| **Cooperative Namespace** | A shared DNS zone (e.g., `id.locd.net`) providing subdomains for users without their own domain. |

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## 3. Design Principles

1. **User sovereignty.** The user is the root of trust. No third party can revoke, modify, or intercept the user's identity without physical access to their hardware.

2. **Hardware-bound keys.** Private keys MUST be generated in and MUST NOT be extractable from hardware security modules (TPM 2.0, Secure Enclave, or equivalent).

3. **No shared secrets.** The protocol MUST NOT rely on passwords, pre-shared keys, API keys, or any credential that exists in more than one location simultaneously.

4. **Invisible security.** The protocol MUST be implementable such that routine authentication requires no user interaction after initial setup.

5. **Independent layers.** Each protocol layer (Identity, Mesh, Bridge) MUST be usable independently. A service MAY implement only the Identity layer without requiring Mesh connectivity.

6. **Graceful degradation.** If a Verifier cannot reach DNS, or a delegation is near expiry, the protocol MUST define fallback behaviour rather than failing silently.

7. **No vendor dependency.** The protocol MUST NOT require any specific vendor's infrastructure for core functionality. Coordination services, if used, MUST be self-hostable.

---

## 4. Key Hierarchy

### 4.1 Tier 1: Master Key

- **Algorithm:** Ed25519 (RFC 8032)
- **Generation:** MUST be generated within a hardware secure enclave (iOS Secure Enclave, Android StrongBox / TEE, or equivalent).
- **Storage:** Private key MUST NOT leave the secure enclave. All signing operations are performed within the enclave.
- **Access control:** Signing operations MUST require biometric authentication (fingerprint, face recognition) or device PIN.
- **Purpose:** Signs Delegation Tokens, Revocation statements, and Recovery operations. MUST NOT be used for routine authentication or session establishment.
- **Cardinality:** One Master Key per Loc'd identity.

### 4.2 Tier 2: Device Key

- **Algorithm:** Ed25519 (RFC 8032)
- **Generation:** MUST be generated within the device's TPM 2.0 or secure enclave.
- **Storage:** Private key MUST NOT leave the TPM/secure enclave.
- **Purpose:** Routine authentication, tunnel establishment, service connections.
- **Authorisation:** Each Device Key MUST have a valid Delegation Token signed by the Master Key.
- **Cardinality:** One Device Key per device. A single identity may have multiple authorised devices.

### 4.3 Tier 3: Session Key

- **Algorithm:** X25519 key agreement (RFC 7748), producing a shared secret for symmetric encryption (ChaCha20-Poly1305).
- **Generation:** Generated in memory for each connection.
- **Storage:** MUST NOT be written to persistent storage. MUST be destroyed when the session ends.
- **Purpose:** Encrypts a single session between Claimant and Verifier.
- **Lifetime:** Duration of one session. Maximum lifetime of 24 hours, after which re-establishment is REQUIRED.

### 4.4 Key Lifecycle

```
┌─────────────────────────────────────────────────────┐
│                    MASTER KEY                         │
│              (Phone Secure Enclave)                   │
│                                                       │
│  Signs:  Delegation Tokens                           │
│          Revocation Statements                        │
│          Recovery Operations                          │
│          Device Key Authorisations                    │
│                                                       │
│  Backed up to: USB Recovery Key (encrypted)          │
└──────────────────┬──────────────────────┬────────────┘
                   │ signs delegation     │ signs delegation
                   ▼                      ▼
        ┌──────────────────┐   ┌──────────────────┐
        │   DEVICE KEY A    │   │   DEVICE KEY B    │
        │   (Laptop TPM)    │   │   (Server TPM)    │
        │                   │   │                   │
        │  Scope: all       │   │  Scope: service X │
        │  Expiry: 30 days  │   │  Expiry: 24 hours │
        └────────┬──────────┘   └────────┬──────────┘
                 │ per-connection          │ per-connection
                 ▼                         ▼
        ┌──────────────────┐   ┌──────────────────┐
        │  SESSION KEY      │   │  SESSION KEY      │
        │  (Memory only)    │   │  (Memory only)    │
        │  Lifetime: 1 sess │   │  Lifetime: 1 sess │
        └──────────────────┘   └──────────────────┘
```

---

## 5. Identity Layer

### 5.1 Identity Creation

1. User installs a Loc'd-compatible client on their primary device (typically a smartphone with secure enclave).
2. The client generates an Ed25519 key pair within the secure enclave.
3. The public key becomes the user's **Loc'd Identity**.
4. The identity is represented as: `base64url(public_key)` (32 bytes → 43 characters).

### 5.2 Identity Publication

The user's public key is published as a DNS TXT record under their domain (or a cooperative namespace subdomain).

**Record location:**
```
_locd.<domain>         # For domain owners
<username>._locd.id.locd.net   # For cooperative namespace users
```

**Record format:**
```
v=locd1; k=ed25519; p=<base64url-encoded-public-key>; t=<unix-timestamp>; exp=<unix-timestamp>; rev=<revocation-endpoint>
```

**Fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `v` | REQUIRED | Protocol version. MUST be `locd1` for this specification. |
| `k` | REQUIRED | Key algorithm. MUST be `ed25519` for this specification. Future versions MAY add algorithms. |
| `p` | REQUIRED | Base64url-encoded public key (no padding). |
| `t` | REQUIRED | Unix timestamp of key publication. |
| `exp` | OPTIONAL | Unix timestamp of key expiry. If absent, key does not expire (revocation still applies). |
| `rev` | OPTIONAL | URL of supplementary revocation list. If absent, revocation is DNS-only. |

**Example:**
```
_locd.example.com. 300 IN TXT "v=locd1; k=ed25519; p=O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik; t=1739577600; rev=https://example.com/.well-known/locd/revocations"
```

### 5.3 DNSSEC Requirement

Identity records MUST be signed with DNSSEC. A Verifier MUST reject identity lookups that fail DNSSEC validation. This prevents DNS spoofing attacks where an attacker publishes a fraudulent public key.

### 5.4 DNS-over-HTTPS (DoH)

Clients SHOULD perform identity lookups via DNS-over-HTTPS (RFC 8484) to prevent network observers from determining which identities a user is verifying.

### 5.5 TTL Recommendations

| Context | Recommended TTL |
|---------|----------------|
| Active identity record | 300 seconds (5 minutes) |
| Cooperative namespace record | 300 seconds (5 minutes) |
| Revoked/expired identity | 60 seconds (1 minute) |

Short TTLs enable faster propagation of key rotation and revocation at the cost of increased DNS query volume.

### 5.6 Multiple Identities

A user MAY maintain multiple Loc'd identities (e.g., personal and professional). Each identity is an independent Master Key with its own DNS record, delegation tokens, and revocation scope. Identities are not linked unless the user explicitly publishes a cross-reference.

### 5.7 Cooperative Namespace

For users without their own domain, the Loc'd project operates a cooperative namespace at `id.locd.net`. Users register a subdomain (e.g., `lane.id.locd.net`) and publish their identity record there.

The cooperative namespace:
- MUST be operated as a non-profit service.
- MUST allow users to migrate to their own domain at any time by updating their identity record location.
- MUST NOT impose vendor lock-in through proprietary extensions.
- SHOULD be operatable by multiple independent organisations (federated model).

---

## 6. Delegation Layer

### 6.1 Purpose

Delegation allows the holder of a Master Key to authorise other keys (Device Keys, agent keys) to act on their behalf with specific constraints. This enables automated, unattended operations without exposing the Master Key.

### 6.2 Delegation Token Format

Delegation Tokens are CBOR-encoded (RFC 8949) and signed using COSE Sign1 (RFC 9052).

**Token structure (CBOR map):**

```
{
  1: "locd-delegation-v1",     ; type identifier
  2: bytes,                     ; delegator public key (Master Key)
  3: bytes,                     ; delegate public key (Device Key)
  4: uint,                      ; issued-at (Unix timestamp)
  5: uint,                      ; expires-at (Unix timestamp)
  6: text,                      ; delegation ID (UUID v4)
  7: [text],                    ; permitted services (list of domain patterns)
  8: [text],                    ; permitted actions (protocol-defined action strings)
  9: uint,                      ; max uses (0 = unlimited)
  10: text,                     ; device attestation (optional, TPM quote)
  11: bool                      ; can-sub-delegate (default: false)
}
```

**Field details:**

| Key | Name | Required | Description |
|-----|------|----------|-------------|
| 1 | type | REQUIRED | MUST be `"locd-delegation-v1"` |
| 2 | delegator | REQUIRED | 32-byte Ed25519 public key of the Master Key signing this delegation |
| 3 | delegate | REQUIRED | 32-byte Ed25519 public key of the Device Key being authorised |
| 4 | issued_at | REQUIRED | Unix timestamp. Verifiers MUST reject tokens with issued_at in the future (with 60-second clock skew tolerance). |
| 5 | expires_at | REQUIRED | Unix timestamp. MUST be ≤ 30 days from issued_at. RECOMMENDED default: 24 hours. |
| 6 | delegation_id | REQUIRED | UUID v4 string. Used for revocation. |
| 7 | services | OPTIONAL | Array of domain patterns (e.g., `["*.example.com", "api.service.net"]`). Empty array or absent = all services. |
| 8 | actions | OPTIONAL | Array of action strings (e.g., `["read", "write", "admin"]`). Action vocabulary is service-defined. Empty or absent = all actions. |
| 9 | max_uses | OPTIONAL | Maximum number of times this delegation can be used. 0 or absent = unlimited. |
| 10 | attestation | OPTIONAL | TPM 2.0 attestation quote proving the delegate key is hardware-bound. |
| 11 | can_sub_delegate | OPTIONAL | Whether the delegate can create further delegations. Default: false. |

### 6.3 Signing

The Delegation Token is wrapped in a COSE Sign1 structure:

```
COSE_Sign1 = [
  protected:   { 1: -8 },          ; alg: EdDSA
  unprotected: {},
  payload:     CBOR-encoded token,
  signature:   Ed25519 signature by Master Key
]
```

### 6.4 Constraints

- `expires_at` MUST NOT exceed 30 days from `issued_at`. Implementations SHOULD default to 24 hours.
- Auto-renewal: Clients SHOULD automatically request renewed delegation tokens before expiry when the Master Key device is reachable.
- If the Master Key device is unreachable at renewal time, the delegation expires and the device cannot authenticate until the Master Key device is available.

### 6.5 Sub-Delegation

If `can_sub_delegate` is true, the delegate MAY issue further delegation tokens. Sub-delegated tokens:
- MUST include a chain: the original delegation token plus the sub-delegation token.
- MUST NOT expand scope beyond the parent delegation.
- MUST NOT exceed the parent delegation's `expires_at`.
- Chain depth MUST NOT exceed 3 (Master → Device → Sub-delegate → Sub-sub-delegate).

---

## 7. Verification Layer

### 7.1 Challenge-Response Protocol

When a Claimant connects to a Verifier, the following exchange occurs:

```
Claimant                                    Verifier
   │                                           │
   │──── 1. HELLO (identity domain) ──────────▶│
   │                                           │
   │                          2. DNS lookup: _locd.<domain>
   │                             Verify DNSSEC chain
   │                             Extract public key
   │                                           │
   │◀─── 3. CHALLENGE (nonce, timestamp) ──────│
   │                                           │
   │     4. Sign challenge with Device Key     │
   │        Attach Delegation Token            │
   │                                           │
   │──── 5. RESPONSE (signature, delegation) ─▶│
   │                                           │
   │                          6. Verify delegation:
   │                             - Signed by published Master Key?
   │                             - Delegation not expired?
   │                             - Delegation not revoked?
   │                             - Service within scope?
   │                             - Action within scope?
   │                          7. Verify response signature:
   │                             - Signed by delegated Device Key?
   │                             - Nonce matches?
   │                             - Timestamp within tolerance?
   │                                           │
   │◀─── 8. VERIFIED / REJECTED ──────────────│
   │                                           │
   │──── 9. (If verified) Establish tunnel ───▶│
   │                                           │
```

### 7.2 Message Formats

All protocol messages are CBOR-encoded.

**HELLO:**
```cbor
{
  1: "locd-hello-v1",
  2: "example.com",            ; identity domain
  3: bytes                     ; Claimant's Device Key public key
}
```

**CHALLENGE:**
```cbor
{
  1: "locd-challenge-v1",
  2: bytes,                    ; 32-byte random nonce
  3: uint,                     ; Unix timestamp
  4: text                      ; Verifier's identity domain (for mutual auth)
}
```

**RESPONSE:**
```cbor
{
  1: "locd-response-v1",
  2: bytes,                    ; Ed25519 signature over (nonce || timestamp || verifier_domain)
  3: bytes,                    ; COSE Sign1 Delegation Token
  4: [bytes]                   ; Sub-delegation chain (if any), ordered root-first
}
```

**RESULT:**
```cbor
{
  1: "locd-result-v1",
  2: bool,                     ; verified (true/false)
  3: text,                     ; reason code (see §7.4)
  4: bytes                     ; (If verified) Verifier's WireGuard public key for tunnel
}
```

### 7.3 Mutual Authentication

Loc'd supports mutual authentication. After the Claimant is verified, the Verifier MAY prove its identity using the same protocol in reverse. This is RECOMMENDED for Mesh connections and OPTIONAL for service connections.

For mutual authentication, the HELLO message includes a flag requesting mutual verification, and the RESULT message includes a counter-challenge for the Verifier.

### 7.4 Reason Codes

| Code | Meaning |
|------|---------|
| `ok` | Verification succeeded. |
| `dns_lookup_failed` | Could not resolve identity record. |
| `dnssec_invalid` | DNSSEC validation failed. |
| `identity_not_found` | No Loc'd identity record at the specified domain. |
| `identity_expired` | Identity record has passed its `exp` timestamp. |
| `delegation_invalid` | Delegation token signature does not match published Master Key. |
| `delegation_expired` | Delegation token has passed its `expires_at` timestamp. |
| `delegation_revoked` | Delegation ID appears on the revocation list. |
| `scope_violation` | Requested service or action not permitted by delegation. |
| `nonce_mismatch` | Response signature does not match the issued challenge. |
| `timestamp_skew` | Timestamps outside acceptable tolerance (60 seconds). |
| `chain_too_deep` | Sub-delegation chain exceeds maximum depth. |
| `attestation_failed` | TPM attestation did not validate. |

### 7.5 Caching

Verifiers MAY cache a Claimant's public key for the duration of the DNS TTL. Verifiers MUST re-query DNS when the cached TTL expires. Verifiers MUST NOT cache past a Delegation Token's `expires_at`.

---

## 8. Revocation Layer

Revocation is the most time-critical operation in the protocol. If a device is lost or compromised, the user must be able to invalidate its authority as quickly as possible.

### 8.1 Revocation Mechanisms

Loc'd uses a layered revocation strategy:

**Layer 1: Short-Lived Delegations (Primary)**
- Delegation tokens SHOULD have a default expiry of 24 hours.
- Even without active revocation, a compromised device loses authority within 24 hours.
- This is the primary defence: limit the blast radius by limiting the lifetime.

**Layer 2: DNS Revocation Record (Authoritative)**
- A DNS TXT record at `_locd-revoke.<domain>` lists revoked delegation IDs.
- Format: `v=locd-revoke1; ids=<comma-separated-delegation-UUIDs>; t=<timestamp>`
- Verifiers MUST check the revocation record as part of the verification flow (§7.1 step 6).
- Propagation time: depends on TTL (recommended 60 seconds for revocation records).

**Layer 3: Supplementary Revocation List (Fast)**
- Published at the URL specified in the `rev` field of the identity record.
- A signed JSON document listing revoked delegation IDs with timestamps.
- Verifiers SHOULD check this endpoint if available, as it propagates faster than DNS.
- The list is signed by the Master Key. Verifiers MUST reject unsigned or incorrectly signed lists.

```json
{
  "v": "locd-revoke-list-v1",
  "identity": "example.com",
  "revocations": [
    {
      "delegation_id": "550e8400-e29b-41d4-a716-446655440000",
      "revoked_at": 1739577600,
      "reason": "device_lost"
    }
  ],
  "published_at": 1739577660,
  "signature": "<base64url-encoded-Ed25519-signature>"
}
```

### 8.2 Revocation Reasons

| Reason | Description |
|--------|-------------|
| `device_lost` | Physical device lost or stolen. |
| `device_compromised` | Device suspected or confirmed compromised. |
| `key_rotation` | Routine key rotation. Previous delegation superseded. |
| `scope_change` | Delegation scope reduced. New delegation issued with narrower scope. |
| `user_initiated` | User explicitly revoked for any other reason. |

### 8.3 Master Key Rotation

If the Master Key itself is compromised (e.g., phone lost without remote wipe):

1. User recovers identity via USB Recovery Key (see §11).
2. A new Master Key is generated in the new device's secure enclave.
3. A **key rotation record** is published to DNS, signed by the old Master Key (via the USB recovery key):

```
_locd-rotate.<domain> TXT "v=locd-rotate1; old=<old-pubkey>; new=<new-pubkey>; t=<timestamp>; sig=<signature-by-old-key>"
```

4. All existing Delegation Tokens become invalid (they reference the old Master Key).
5. Devices must re-pair with the new Master Key.
6. After a transition period (recommended: 7 days), the old key rotation record can be removed.

---

## 9. Mesh Connectivity Layer

### 9.1 Overview

The Mesh layer provides encrypted, peer-to-peer connectivity between devices authenticated by the Identity and Delegation layers. It uses WireGuard as the tunnel protocol.

### 9.2 Tunnel Establishment

After successful identity verification (§7.1), the Verifier and Claimant exchange WireGuard public keys and establish a tunnel:

1. Verification completes. Both parties have confirmed each other's identity.
2. The RESULT message (§7.2) includes the Verifier's WireGuard public key.
3. The Claimant responds with its WireGuard public key.
4. Both parties configure a WireGuard peer entry with the exchanged keys.
5. The WireGuard tunnel is established over the existing network connection.

### 9.3 Coordination

Devices need to discover each other's current network address to establish tunnels. Loc'd supports two coordination models:

**Self-Hosted Coordination (RECOMMENDED):**
- A lightweight coordination service (compatible with Headscale API) runs on a user's device or server.
- Stores current IP addresses and port mappings for mesh members.
- Authenticated via Loc'd identity (the coordinator is a Verifier).
- No traffic passes through the coordinator — it only facilitates connection setup.

**Peer-to-Peer Discovery (OPTIONAL):**
- Devices exchange address information directly via the WireGuard mesh itself.
- Requires at least one initial connection to bootstrap.
- Suitable for small meshes (2–5 devices).

### 9.4 No Open Ports

Mesh devices MUST NOT listen on publicly accessible ports. Connections are established via:
- WireGuard's UDP hole-punching (works behind most NATs).
- STUN/TURN relay as a fallback (the relay sees only encrypted WireGuard traffic).
- The coordination service facilitating initial rendezvous.

### 9.5 Device-to-Device Sync

Devices within a mesh synchronise:
- The current delegation token set (so devices know which peers are authorised).
- Revocation lists (so compromised devices are blocked immediately within the mesh).
- Legacy bridge credentials (encrypted to each device's TPM key — see §10).

Sync is performed over the WireGuard mesh. No data passes through any external service.

---

## 10. Legacy Bridge Layer

### 10.1 Purpose

The Legacy Bridge provides value to users before services adopt Loc'd natively. It manages credentials (passwords, API keys, OAuth tokens) for non-Loc'd services, encrypted to the device's hardware.

### 10.2 Credential Storage

- Credentials are encrypted using a key derived from the device's TPM-bound Device Key.
- Encryption algorithm: XChaCha20-Poly1305 with a key derived via HKDF-SHA256 from the Device Key.
- Encrypted credentials are stored on the device's local filesystem.
- Credentials are NEVER stored in plaintext, NEVER transmitted to a server, and NEVER decryptable without the device's TPM.

### 10.3 Credential Injection

When connecting to a legacy service:
1. The client decrypts the relevant credential within the TPM trust boundary.
2. The credential is injected into the connection (HTTP header, form field, API call) at the moment of use.
3. The plaintext credential exists in memory only for the duration of the injection.
4. From the service's perspective, it receives a normal authenticated request.

### 10.4 Cross-Device Credential Sync

Credentials can be synced between devices in the mesh:
1. Source device encrypts the credential set using a shared secret derived from a Diffie-Hellman exchange between the two devices' Device Keys.
2. Encrypted payload is transmitted over the WireGuard mesh.
3. Receiving device re-encrypts each credential to its own TPM-bound key.
4. The shared secret is discarded after sync.

### 10.5 Dashboard Indicators

Clients SHOULD display service connections with visual indicators:
- **Green:** Service supports native Loc'd authentication. No shared secrets involved.
- **Yellow:** Service accessed via Legacy Bridge. Credentials managed locally.
- **Red:** Service has a known security issue or credential configuration problem.

---

## 11. Recovery

### 11.1 USB Recovery Key

The primary recovery mechanism is a physical USB security key (e.g., YubiKey 5 series) holding an encrypted backup of the Master Key.

**Backup creation:**
1. The Master Key private key is exported from the secure enclave in an encrypted form.
2. The key is encrypted to a user-chosen passphrase using Argon2id key derivation (minimum parameters: 64MB memory, 3 iterations, 4 parallelism) and XChaCha20-Poly1305.
3. The encrypted key material is written to the USB security key's FIDO2 resident credential storage.
4. The USB key's secure element holds the encrypted material. Decryption requires the passphrase AND physical presence (button press on the USB key).

**Recovery process:**
1. User installs a Loc'd client on a new device.
2. User inserts the USB recovery key.
3. User enters the passphrase.
4. The USB key's secure element decrypts the Master Key internally.
5. The decrypted Master Key is transferred directly to the new device's secure enclave via a secure channel (CTAP2 protocol).
6. The Master Key is now resident in the new device's secure enclave. The USB key can be removed.
7. User re-pairs devices or verifies existing delegations.

### 11.2 Multiple Recovery Keys

Users SHOULD create multiple USB recovery keys and store them in different physical locations (e.g., home, office, safety deposit box, trusted person). Each recovery key holds an independently encrypted copy of the same Master Key material.

### 11.3 Shamir's Secret Sharing (Optional)

As an alternative or supplement to USB recovery keys, users MAY use Shamir's Secret Sharing to distribute recovery capability across trusted parties.

**Setup:**
1. The Master Key backup is split into N shares using Shamir's scheme (recommended: 5 shares, threshold of 3).
2. Each share is distributed to a trusted party (friend, family member, lawyer, safety deposit box).
3. Shares are individually encrypted to each recipient.

**Recovery:**
1. User collects the threshold number of shares (e.g., 3 of 5).
2. Shares are combined to reconstruct the Master Key backup.
3. Backup is decrypted and transferred to the new device's secure enclave.

### 11.4 Recovery Without Backup

If a user loses their Master Key device AND all recovery keys/shares:
- The identity is irrecoverable. This is by design.
- Services accessed via Legacy Bridge can be recovered through each service's individual recovery process (email-based password reset, etc.).
- The user creates a new Loc'd identity and re-registers with services.
- This is the trade-off of self-sovereignty: no "forgot password" backdoor.

---

## 12. DNS Record Formats

### 12.1 Summary of DNS Records

| Record | Location | Purpose |
|--------|----------|---------|
| Identity | `_locd.<domain>` | Publishes user's public Master Key |
| Revocation | `_locd-revoke.<domain>` | Lists revoked Delegation IDs |
| Key Rotation | `_locd-rotate.<domain>` | Announces Master Key rotation |
| Service Endpoint | `_locd-svc.<service-domain>` | (Optional) Announces Loc'd-native service capability |

### 12.2 Service Discovery Record

Services that support Loc'd authentication MAY publish a discovery record:

```
_locd-svc.api.example.com TXT "v=locd-svc1; port=<coordination-port>; actions=read,write,admin; min-delegation-ttl=3600"
```

This allows clients to discover Loc'd support without attempting a connection first.

---

## 13. Wire Formats

### 13.1 Transport

The Loc'd verification protocol (§7) is transport-agnostic. Implementations MAY use:
- Raw TCP connection (default port: TBD, to be registered with IANA)
- WebSocket (for browser-based clients)
- HTTP/2 or HTTP/3 (for integration with web services)

The CBOR-encoded messages are transmitted as length-prefixed frames:

```
┌────────────────┬──────────────────────┐
│ Length (4 bytes)│ CBOR payload         │
│ big-endian u32 │ (variable length)    │
└────────────────┴──────────────────────┘
```

### 13.2 Protocol Negotiation

The HELLO message includes the protocol version. If the Verifier does not support the requested version, it responds with a RESULT containing `version_unsupported` and a list of supported versions.

---

## 14. Security Considerations

### 14.1 Threat Model Summary

| Threat | Mitigation |
|--------|-----------|
| DNS spoofing | DNSSEC required for identity records. Verifiers MUST reject records that fail DNSSEC validation. |
| Network eavesdropping | All identity lookups SHOULD use DoH. All data transport uses WireGuard (ChaCha20-Poly1305). |
| Stolen device | Short-lived delegations (24hr default). Instant revocation via DNS + supplementary list. Biometric gating on Master Key operations. |
| Compromised TPM | Single device compromise does not compromise the Master Key (which is on a separate device). Revoke the compromised device. |
| Rogue coordination server | Coordinator only sees encrypted WireGuard traffic. Cannot decrypt, modify, or inject. Self-hostable. |
| Replay attack | Challenge includes timestamp and random nonce. Verifiers MUST reject replayed nonces within a time window. |
| Master Key compromise | USB recovery key enables key rotation. Old delegations automatically invalidated. |
| Denial of service on DNS | Verifiers MAY cache identity records for the TTL period. Fallback: accept cached identity if DNS is unreachable, but flag as degraded verification. |

### 14.2 What Loc'd Does NOT Defend Against

- **Nation-state adversary with physical access to the user's device and coercive capability.** No protocol can defend against this.
- **Compromise of the secure enclave hardware itself** (e.g., side-channel attacks on a specific TPM model). Loc'd limits blast radius but cannot prevent hardware-level compromise.
- **User social engineering.** If a user is tricked into signing a malicious delegation, the protocol has functioned correctly — the user made a bad decision. Education and clear UX mitigate this.
- **Availability.** Loc'd does not guarantee that services will be reachable, only that connections are authenticated and encrypted when they are.

### 14.3 Cryptographic Agility

The protocol version field (`v=locd1`) enables future versions to adopt new algorithms if Ed25519 or X25519 are weakened. Migration path: publish new identity record with new version and algorithm, maintain old record during transition period, remove old record after all Verifiers have updated.

---

## 15. IANA Considerations

A future version of this specification will request:
- Registration of a TCP/UDP port for the Loc'd verification protocol.
- Registration of `_locd`, `_locd-revoke`, `_locd-rotate`, and `_locd-svc` as underscore-prefixed DNS labels (per RFC 8552).
- Registration of the `locd-delegation-v1` CBOR tag (if applicable).

---

## 16. References

### Normative References

- [RFC 2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", RFC 2119, March 1997.
- [RFC 4033] Arends, R., et al., "DNS Security Introduction and Requirements", RFC 4033, March 2005.
- [RFC 7748] Langley, A., et al., "Elliptic Curves for Security", RFC 7748, January 2016.
- [RFC 8032] Josefsson, S. and I. Liber, "Edwards-Curve Digital Signature Algorithm (EdDSA)", RFC 8032, January 2017.
- [RFC 8484] Hoffman, P. and P. McManus, "DNS Queries over HTTPS (DoH)", RFC 8484, October 2018.
- [RFC 8949] Bormann, C. and P. Hoffman, "Concise Binary Object Representation (CBOR)", RFC 8949, December 2020.
- [RFC 9052] Schaad, J., "CBOR Object Signing and Encryption (COSE)", RFC 9052, August 2022.

### Informative References

- [FIDO2] FIDO Alliance, "Client to Authenticator Protocol (CTAP)", v2.1, June 2021.
- [WebAuthn] W3C, "Web Authentication: An API for accessing Public Key Credentials", Level 2, April 2021.
- [WireGuard] Donenfeld, J.A., "WireGuard: Next Generation Kernel Network Tunnel", NDSS 2017.
- [Argon2] Biryukov, A., Dinu, D., and D. Khovratovich, "Argon2: the memory-hard function for password hashing and other applications", 2015.
- [TPM 2.0] Trusted Computing Group, "TPM Library Specification, Family 2.0", 2019.

---

## Appendix A: Example Flows

### A.1 Complete Authentication Flow

```
1. User "lane" has Master Key published at:
   _locd.lane.id.locd.net TXT "v=locd1; k=ed25519; p=O2onvM62pC1io6jQ...; t=1739577600"

2. Lane's laptop has Device Key DK-laptop, with delegation token:
   {
     delegator: <Master Key pubkey>,
     delegate: <DK-laptop pubkey>,
     expires_at: 1739664000,        // 24 hours from issuance
     services: ["api.example.com"],
     actions: ["read", "write"]
   }
   Signed by Master Key.

3. Laptop connects to api.example.com:

   Laptop → Service:  HELLO { domain: "lane.id.locd.net", device_key: <DK-laptop> }
   
   Service: DNS lookup _locd.lane.id.locd.net → gets Master Key pubkey
            Verifies DNSSEC chain ✓
   
   Service → Laptop:  CHALLENGE { nonce: <random>, timestamp: <now>, verifier: "api.example.com" }
   
   Laptop: Signs (nonce || timestamp || "api.example.com") with DK-laptop private key (in TPM)
   
   Laptop → Service:  RESPONSE { signature: <sig>, delegation: <COSE Sign1 token> }
   
   Service: Verifies delegation:
            - Delegation signed by Master Key from DNS? ✓
            - Delegation not expired? ✓ (24hr window)
            - Delegation not revoked? ✓ (checked DNS + rev endpoint)
            - "api.example.com" in permitted services? ✓
            - Actions within scope? ✓
            Verifies response:
            - Signature matches challenge nonce? ✓
            - Signed by the delegated Device Key? ✓
   
   Service → Laptop:  RESULT { verified: true, wireguard_key: <service WG pubkey> }
   
   WireGuard tunnel established.
```

### A.2 Revocation Flow

```
1. Lane loses his laptop.

2. Lane opens Loc'd app on phone.
   App shows: "DK-laptop — authorized 2026-02-14, expires 2026-02-15"
   Lane swipes to revoke.

3. Phone (Master Key) signs a revocation statement for DK-laptop's delegation ID.

4. Revocation is published:
   a. DNS: _locd-revoke.lane.id.locd.net updated with delegation ID
   b. HTTPS: https://lane.id.locd.net/.well-known/locd/revocations updated

5. Next time anyone tries to verify DK-laptop's delegation:
   - DNS revocation check finds the delegation ID → REJECTED
   - Even if DNS hasn't propagated, HTTPS revocation list check finds it → REJECTED

6. DK-laptop's delegation also expires naturally within 24 hours regardless.
```

---

## Appendix B: Comparison with Existing Standards

| Feature | Loc'd | Passkeys (as shipped) | OAuth 2.0 | mTLS | Tailscale |
|---------|-------|----------------------|-----------|------|-----------|
| User owns identity | ✓ | ✗ (vendor-synced) | ✗ (provider-owned) | Partial (CA-dependent) | ✗ (coordination server) |
| Hardware-bound keys | ✓ (required) | Optional | ✗ | Optional | ✗ |
| No shared secrets | ✓ | ✓ | ✗ (tokens) | ✓ | ✓ |
| Scoped delegation | ✓ | ✗ | Partial (scopes) | ✗ | ✗ |
| Time-limited auth | ✓ (24hr default) | ✗ | ✓ (token expiry) | ✓ (cert expiry) | ✗ |
| User-controlled revocation | ✓ (instant) | ✗ (vendor-dependent) | ✗ (provider-dependent) | Partial (CRL/OCSP) | ✗ |
| No vendor dependency | ✓ | ✗ | ✗ | ✓ | ✗ |
| Encrypted connectivity | ✓ (WireGuard) | ✗ (auth only) | ✗ (auth only) | ✓ | ✓ (WireGuard) |
| Works without server | ✓ | ✗ | ✗ | ✗ | ✗ |
| Legacy service support | ✓ (bridge) | ✗ | N/A | ✗ | ✗ |

---

## Changelog

### v0.1.1 (2026-02-15)
- Initial draft specification.

---

“This specification is published so that others may implement and maintain it.
The original author does not intend to act as long-term maintainer.”


*This specification is licensed under Creative Commons Attribution 4.0 International (CC BY 4.0). You are free to share and adapt this material for any purpose, provided appropriate credit is given.*
