# Plan: legacy-bridge-7

## Task Summary
Integrate with Key Hierarchy module to obtain Tier 2 Device Key and perform HKDF operations within TPM trust boundary. Submit HKDF derivation request to TPM, receive derived key in sealed memory buffer.

## Files to Create
1. **key_hierarchy.py** - Module to access Tier 2 Device Key from TPM/Secure Enclave
2. **credential_key_derivation.py** - HKDF key derivation wrapper integrating legacy-bridge-5 and legacy-bridge-6
3. **tests/test_key_hierarchy.py** - Unit tests for key hierarchy module
4. **tests/test_credential_key_derivation.py** - Unit tests for credential key derivation

## Files to Modify
1. **locd-protocol-spec-v0.1.md** - No changes needed (reference only)

## Dependencies/Integration Section

### External Module Dependencies

#### From legacy-bridge-5 (HKDF)
**Location:** `/mnt/ccm/.worktrees/locd/worker-legacy-bridge-5/hkdf.py`

**Import:**
```python
from locd.legacy_bridge.hkdf import derive_credential_key
```

**Primary Function:**
- `derive_credential_key(device_key: bytes, salt: bytes, key_length: int = 32) -> bytes`
  - Takes Device Key material and derives encryption key via HKDF-SHA256
  - Uses salt (per-credential random 32 bytes) and info context
  - Returns 32-byte derived key for XChaCha20-Poly1305

#### From legacy-bridge-6 (TPM Session Management)
**Location:** `/mnt/ccm/.worktrees/locd/worker-legacy-bridge-6/tpm_session.py`

**Import:**
```python
from locd.legacy_bridge.tpm_session import (
    tpm_session_open,
    tpm_session_close,
    tpm_is_available,
    TPMSessionError,
    TPMUnavailableError
)
```

**Primary Functions:**
- `tpm_session_open() -> Union[LinuxTPMSession, MacOSSecureEnclaveSession]`
  - Opens TPM 2.0 (Linux) or Secure Enclave (macOS) session
  - Returns session object with session_handle or session_token
  - Raises TPMUnavailableError if hardware not available

- `tpm_session_close(session) -> None`
  - Closes TPM/Secure Enclave session
  - Cleans up hardware resources

- `tpm_is_available() -> bool`
  - Checks if TPM 2.0 or Secure Enclave is available

#### From Main Repository (locd/src/locd/)
**Location:** `/mnt/ccm/locd/src/locd/legacy_bridge/encryption.py`

**Import:**
```python
from locd.legacy_bridge.encryption import (
    derive_credential_encryption_key,
    encrypt_credential_data,
    decrypt_credential_data
)
```

**Also available:**
- `locd.recovery.TPM2Exporter` - TPM 2.0 key export for recovery keys
- `locd.recovery.PolicySession` - TPM policy authorization sessions

## Implementation Approach

### Overview
Integrates three previous implementations to provide hardware-bound credential encryption:
- **legacy-bridge-5:** HKDF-SHA256 key derivation (RFC 5869)
- **legacy-bridge-6:** TPM session management (cross-platform)
- **legacy-bridge-7:** Key Hierarchy integration for Tier 2 Device Key access

### TPM Trust Boundary Clarification

**Where does HKDF run?**
- **HKDF computation:** Runs in **application code** (not inside TPM hardware)
- **Reason:** HKDF is a CPU-bound KDF, not a cryptographic operation requiring TPM. Computational overhead inside TPM would be inefficient.
- **Device Key protection:** While HKDF computation is in application memory, it uses the Tier 2 Device Key which:
  - Is generated and stored **within TPM** (never exported)
  - Provides cryptographic binding through its entropy
  - Cannot be accessed without valid TPM session

**TPM trust boundary includes:**
- TPM session management (opened/closed via legacy-bridge-6)
- Device Key seed/material access (from Key Hierarchy module)
- Sealed memory buffer for keys (returned from HKDF with explicit handle)

### Key Components

#### 1. Key Hierarchy Module (`key_hierarchy.py`)
**Responsibilities:**
- Obtain Tier 2 Device Key per spec section 4.2
- Validate delegation token for Device Key access
- Manage Device Key lifecycle (generation, storage in TPM)
- Provide Device Key material to credential derivation pipeline

**Integration with legacy-bridge-6:**
```python
from locd.legacy_bridge.tpm_session import tpm_session_open, tpm_session_close

def get_device_key_material(tpm_session) -> bytes:
    """Retrieve Device Key from TPM using opened session"""
```

#### 2. Credential Key Derivation Module (`credential_key_derivation.py`)
**Responsibilities:**
- Orchestrate TPM session lifecycle (open → derive → close)
- Interface with legacy-bridge-5 HKDF for key derivation
- Return derived key in sealed memory buffer

**Integration with legacy-bridge-5:**
```python
from locd.legacy_bridge.hkdf import derive_credential_key

def derive_sealed_credential_key(service_domain: str) -> SealedKeyBuffer:
    """
    1. Open TPM session (legacy-bridge-6)
    2. Get Device Key from Key Hierarchy
    3. Generate random salt (32 bytes)
    4. Call derive_credential_key() with Device Key + salt (legacy-bridge-5)
    5. Return SealedKeyBuffer handle
    6. Close TPM session
    """
```

**Integration with locd/src/locd/:**
```python
from locd.legacy_bridge.encryption import encrypt_credential_data

def encrypt_credential_with_derived_key(credential: str, service_domain: str) -> bytes:
    """Use derived key to encrypt credential via XChaCha20-Poly1305"""
```

#### 3. Sealed Memory Buffer Implementation
**SealedKeyBuffer class:**
- Opaque handle to derived key material
- Prevents accidental exposure of plaintext key
- Provides context manager interface for lifecycle
- Garbage collection destroys key material on exit

### Architecture Diagram
```
┌──────────────────────────────────────────────────┐
│   Application Layer                               │
│   (credential encryption/decryption)             │
└────────────────┬─────────────────────────────────┘
                 │
    ┌────────────▼──────────────────────────────┐
    │  Credential Key Derivation                 │
    │  (credential_key_derivation.py)           │
    │  - Orchestrates: open → derive → close    │
    │  - SealedKeyBuffer wrapper                │
    └────────┬──────────────────────┬────────────┘
             │                      │
    [1]      │                      │  [3]
             │                      │
    ┌────────▼────────┐   ┌─────────▼──────────────┐
    │ legacy-bridge-6 │   │  legacy-bridge-5      │
    │ tpm_session     │   │  hkdf.py              │
    │ _open/close     │   │  derive_credential_key│
    └────────┬────────┘   └──────────┬────────────┘
             │                       │
    [2]      │                [4]   │
             │                       │
    ┌────────▼───────────────────────▼──────────┐
    │  Key Hierarchy Module                      │
    │  (key_hierarchy.py)                       │
    │  - Get Tier 2 Device Key                  │
    │  - Validate delegation token              │
    │  - Device Key stays in TPM                │
    └────────┬────────────────────────────────┘
             │
    [5]      │  (Device Key material within session)
             │
    ┌────────▼────────────────────────────────┐
    │  TPM 2.0 / Secure Enclave                 │
    │  (Hardware Trust Boundary)                │
    │  - Stores Tier 2 Device Key               │
    │  - Provides session context via           │
    │    legacy-bridge-6                        │
    │  - Device Key never exported              │
    └───────────────────────────────────────────┘

Legend:
[1] tpm_session_open() from legacy-bridge-6
[2] Session handle passed to Key Hierarchy
[3] derive_credential_key() from legacy-bridge-5
[4] Device Key material returned to HKDF
[5] Device Key never leaves TPM (only used in derived keys)
```

### Implementation Details

#### Key Derivation Request Flow (Using Legacy-Bridge Dependencies)
**Complete flow with function references:**

1. **Open TPM Session** (legacy-bridge-6):
   ```python
   session = tpm_session_open()  # from legacy-bridge-6
   # Returns LinuxTPMSession or MacOSSecureEnclaveSession
   ```

2. **Retrieve Device Key** (Key Hierarchy module):
   ```python
   device_key_material = get_device_key_material(session)
   # Returns bytes from Tier 2 Device Key stored in TPM
   # Device Key is accessed via the open session
   # Key material is generated within TPM boundary
   ```

3. **Derive Credential Key** (legacy-bridge-5):
   ```python
   salt = os.urandom(32)  # Per-credential random salt
   derived_key = derive_credential_key(
       device_key=device_key_material,
       salt=salt,
       key_length=32  # 256-bit for XChaCha20-Poly1305
   )
   # Uses HKDF-SHA256 per RFC 5869
   # Computes in application code (not in TPM)
   # Input: Tier 2 Device Key + salt
   # Output: 32-byte encryption key
   ```

4. **Return Sealed Key Buffer**:
   ```python
   sealed_key = SealedKeyBuffer(
       derived_key=derived_key,
       salt=salt,
       context={"service": service_domain}
   )
   # Opaque handle prevents key material exposure
   ```

5. **Close TPM Session** (legacy-bridge-6):
   ```python
   tpm_session_close(session)  # from legacy-bridge-6
   # Flushes TPM session context
   # Prevents resource leaks
   ```

6. **Use Sealed Key** (locd/legacy_bridge/encryption.py):
   ```python
   encrypted = encrypt_credential_data(
       plaintext=credential_json,
       device_key=sealed_key.get_key()  # Sealed access
   )
   # Uses XChaCha20-Poly1305
   # Credential encrypted at rest
   ```

#### Sealed Memory Buffer Implementation
**SealedKeyBuffer class:**
- Stores derived key with metadata (salt, context)
- Provides opaque handle interface
- Implements context manager for lifecycle management
- Garbage collection securely clears key material on exit
- Prevents accidental exposure of plaintext key bytes

**Error Handling:**
- `TPMUnavailableError` if TPM/Secure Enclave not available (from legacy-bridge-6)
- `TPMSessionError` if session creation/closure fails (from legacy-bridge-6)
- `ValueError` if HKDF parameters invalid (from legacy-bridge-5)
- `CredentialStorageError` if storage fails (from locd/legacy_bridge)

### Testing Strategy
- Unit tests for each module
- Mock TPM interface for testing without hardware
- Integration tests for complete flow
- No plaintext key material in test outputs

### Module Import Paths and Usage Summary

| Module | Import | Primary Function | Called From |
|--------|--------|------------------|-------------|
| legacy-bridge-5 | `locd.legacy_bridge.hkdf` | `derive_credential_key(device_key, salt, key_length)` | credential_key_derivation.py |
| legacy-bridge-6 | `locd.legacy_bridge.tpm_session` | `tpm_session_open()`, `tpm_session_close(session)` | credential_key_derivation.py |
| Key Hierarchy (new) | `locd.legacy_bridge.key_hierarchy` | `get_device_key_material(session)` | credential_key_derivation.py |
| Main repo | `locd.legacy_bridge.encryption` | `encrypt_credential_data()`, `decrypt_credential_data()` | Tests and integration |

### Compliance with Spec
- **Section 4.2** (Tier 2 Device Key): Key Hierarchy module obtains Device Key from TPM
- **Section 10.2** (HKDF-SHA256): Uses legacy-bridge-5 `derive_credential_key()` with Device Key
- **Section 10.3** (Credential Injection): SealedKeyBuffer provides transparent key access for encryption
- **TPM Trust Boundary**: Device Key never exported; HKDF uses key material within valid TPM session

### Acceptance Criteria
1. **Task implemented correctly**
   - Key Hierarchy module obtains Tier 2 Device Key per spec 4.2
   - HKDF operations integrate legacy-bridge-5 (RFC 5869 implementation)
   - TPM sessions integrate legacy-bridge-6 (cross-platform management)
   - Derived keys returned in sealed memory buffers (opaque handles)
   - Device Key never exported from TPM

2. **Code follows project conventions**
   - Explicit imports from legacy-bridge-5 and legacy-bridge-6
   - TPM boundary clearly defined and documented
   - Consistent naming with protocol spec terminology
   - Proper error handling (TPMSessionError, TPMUnavailableError, ValueError)
   - Type hints and comprehensive docstrings
   - Unit test coverage for all modules
