# Legacy Bridge 7: Key Hierarchy & HKDF Integration

Implements Tier 2 Device Key management and credential key derivation via HKDF within TPM trust boundary.

Per LOCD spec §4.2 and §10.2.

## Components

### 1. `key_hierarchy.py`
**Tier 2 Device Key Management**

Implements LOCD spec §4.2:
- Device Key generation and storage in TPM/Secure Enclave
- Delegation token validation for key authorization
- Service scope checking per delegation constraints
- Device Key material access within TPM session

**Classes:**
- `DeviceKey` - Represents a Tier 2 key with authorization
- `DelegationToken` - Delegation token per spec §6.2
- `KeyHierarchy` - Main interface for Device Key operations

**Key Methods:**
```python
key_hierarchy = KeyHierarchy()

# Get or create Device Key
device_key = key_hierarchy.get_device_key(
    device_id="laptop-001",
    tpm_session=session,
    delegation_token=token
)

# Check if authorized
if device_key.is_authorized():
    # Get key material for HKDF input
    key_material = key_hierarchy.get_device_key_material(
        device_key, tpm_session
    )
```

### 2. `credential_key_derivation.py`
**HKDF Key Derivation Orchestration**

Integrates legacy-bridge-5 (HKDF) and legacy-bridge-6 (TPM sessions).

Per LOCD spec §10.2: Credentials encrypted using XChaCha20-Poly1305 with keys
derived from Device Key via HKDF-SHA256.

**Key Features:**
- Opens/closes TPM session automatically
- Orchestrates HKDF-SHA256 derivation (RFC 5869)
- Returns sealed key buffer for opaque key handling
- Supports batch derivation for multiple services

**Classes:**
- `SealedKeyBuffer` - Opaque handle to derived key
- `CredentialKeyDeriver` - Orchestrates the derivation pipeline

**Key Methods:**
```python
deriver = CredentialKeyDeriver()

# Derive single credential key
sealed_key = deriver.derive_sealed_credential_key(
    device_id="laptop-001",
    service_domain="api.example.com"
)

# Use for encryption
from locd.legacy_bridge import encrypt_credential_data
encrypted = encrypt_credential_data(
    plaintext=credential_json,
    device_key=sealed_key.get_key()
)

# Derive multiple keys in single TPM session (more efficient)
sealed_keys = deriver.derive_multiple_credential_keys(
    device_id="laptop-001",
    service_domains=["api.example.com", "oauth.example.com"]
)
```

## Dependencies

### Legacy Bridge Dependencies
- **legacy-bridge-5:** `hkdf.py` - HKDF-SHA256 implementation (RFC 5869)
  - `derive_credential_key(device_key, salt, key_length=32)`

- **legacy-bridge-6:** `tpm_session.py` - TPM/Secure Enclave session management
  - `tpm_session_open()` - Open TPM or Secure Enclave session
  - `tpm_session_close(session)` - Close TPM session
  - `tpm_is_available()` - Check if TPM available

### Main Repository Dependencies
- `locd.legacy_bridge.encryption` - Encryption utilities
  - `encrypt_credential_data(plaintext, device_key)`
  - `decrypt_credential_data(ciphertext_blob, device_key)`

- `locd.recovery.TPM2Exporter` - TPM 2.0 key export
- `locd.recovery.PolicySession` - TPM policy authorization

## TPM Trust Boundary

**Where does HKDF run?**
- **HKDF computation:** Runs in **application code** (not inside TPM)
- **Reason:** HKDF is CPU-bound KDF, not a cryptographic operation requiring TPM

**Device Key Protection:**
- Device Key is generated and stored **within TPM** (never exported)
- Only Device Key material accessed via TPM session
- HKDF uses Device Key material as input
- Derived key never touches TPM hardware (not needed)

**Architecture Flow:**
```
Application Layer
        ↓
TPM Session Open (legacy-bridge-6)
        ↓
Get Device Key Material from TPM
        ↓
HKDF-SHA256 Derivation (legacy-bridge-5) in Application Code
        ↓
Return Sealed Key Buffer (Opaque Handle)
        ↓
TPM Session Close (legacy-bridge-6)
```

## Implementation Details

### Key Derivation Process

1. **Open TPM Session** (legacy-bridge-6)
   ```python
   session = tpm_session_open()
   ```

2. **Get Device Key** (key_hierarchy.py)
   ```python
   device_key = key_hierarchy.get_device_key(device_id, tpm_session)
   ```

3. **Retrieve Key Material** (key_hierarchy.py)
   ```python
   key_material = key_hierarchy.get_device_key_material(device_key, tpm_session)
   ```

4. **Derive via HKDF** (legacy-bridge-5)
   ```python
   salt = os.urandom(32)
   derived_key = derive_credential_key(key_material, salt, key_length=32)
   ```

5. **Seal in Buffer** (credential_key_derivation.py)
   ```python
   sealed = SealedKeyBuffer(derived_key, salt, service_domain)
   ```

6. **Close TPM Session** (legacy-bridge-6)
   ```python
   tpm_session_close(session)
   ```

### Error Handling

- `KeyHierarchyError` - Key hierarchy operation failures
- `DeviceKeyNotFoundError` - Device Key cannot be accessed
- `DelegationTokenInvalidError` - Invalid or expired delegation token
- `TPMSessionUnavailableError` - TPM session open/close fails
- `HKDFDerivationError` - HKDF derivation fails
- `CredentialKeyDerivationError` - General derivation failures

## Testing

### Unit Tests

**test_key_hierarchy.py:**
- Device Key creation and validation
- Delegation token expiry and scope checking
- Service authorization verification
- Device Key material retrieval

**test_credential_key_derivation.py:**
- Sealed key buffer lifecycle
- TPM session management
- HKDF integration with legacy-bridge-5
- Error handling and cleanup
- Batch key derivation

### Running Tests

```bash
pytest test_key_hierarchy.py -v
pytest test_credential_key_derivation.py -v
pytest test_*.py -v  # Run all tests
```

## Integration with Encryption

Once credential key is derived and sealed:

```python
from locd.legacy_bridge import encrypt_credential_data, decrypt_credential_data

# Encrypt credential using derived key
credential_json = json.dumps({"username": "user", "password": "pass"})
encrypted = encrypt_credential_data(
    plaintext=credential_json.encode(),
    device_key=sealed_key.get_key()
)

# Later: decrypt when needed
decrypted = decrypt_credential_data(
    ciphertext_blob=encrypted,
    device_key=sealed_key.get_key()  # Get same key from salt+Device Key
)
```

## Compliance with LOCD Spec

- ✅ §4.2: Tier 2 Device Key management
- ✅ §6.2: Delegation token validation
- ✅ §10.2: HKDF-SHA256 credential key derivation
- ✅ §10.3: Credential encryption/decryption pattern
- ✅ TPM boundary: Device Key never exported

## Future Enhancements

- Cross-device credential sync (spec §10.4)
- Credential expiry and rotation
- Revocation token checking
- Hardware attestation support
- Key rotation policies
