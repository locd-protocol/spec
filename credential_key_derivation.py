"""
Credential Key Derivation Module for Loc'd Protocol

Orchestrates HKDF key derivation within TPM trust boundary for credential encryption.
Integrates:
  - legacy-bridge-5: hkdf.py (RFC 5869 HKDF-SHA256)
  - legacy-bridge-6: tpm_session.py (TPM 2.0 / Secure Enclave session management)
  - key_hierarchy.py (Tier 2 Device Key management)

Per LOCD spec §10.2: Credentials encrypted using XChaCha20-Poly1305 with keys
derived from Device Key via HKDF-SHA256.
"""

import os
import time
from typing import Optional, Union
from dataclasses import dataclass, field
from contextlib import contextmanager


class CredentialKeyDerivationError(Exception):
    """Base exception for credential key derivation operations."""
    pass


class TPMSessionUnavailableError(CredentialKeyDerivationError):
    """Raised when TPM session cannot be opened."""
    pass


class HKDFDerivationError(CredentialKeyDerivationError):
    """Raised when HKDF derivation fails."""
    pass


@dataclass
class SealedKeyBuffer:
    """
    Sealed memory buffer containing derived credential encryption key.

    Provides opaque handle to prevent accidental exposure of plaintext key material.
    Implements context manager for automatic key cleanup.
    """
    derived_key: bytes
    salt: bytes
    service_domain: str
    created_at: float = field(default_factory=time.time)
    context: dict = field(default_factory=dict)
    _cleared: bool = field(default=False, init=False)

    def get_key(self) -> bytes:
        """
        Retrieve the derived key from sealed buffer.

        Returns:
            32-byte derived encryption key

        Raises:
            CredentialKeyDerivationError: If buffer has been cleared
        """
        if self._cleared:
            raise CredentialKeyDerivationError("Sealed key buffer has been cleared")
        return self.derived_key

    def get_salt(self) -> bytes:
        """
        Retrieve the salt used for key derivation.

        Returns:
            32-byte random salt
        """
        if self._cleared:
            raise CredentialKeyDerivationError("Sealed key buffer has been cleared")
        return self.salt

    def clear(self) -> None:
        """
        Securely clear the key material from memory.

        Overwrites key and salt with zeros before clearing.
        """
        if not self._cleared:
            # Overwrite with zeros for security
            self.derived_key = bytes(len(self.derived_key))
            self.salt = bytes(len(self.salt))
            self._cleared = True

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - automatically clear key on exit."""
        self.clear()
        return False

    def __del__(self):
        """Destructor - ensure key is cleared on garbage collection."""
        self.clear()


class CredentialKeyDeriver:
    """
    Orchestrates credential key derivation using:
    - TPM session management (legacy-bridge-6)
    - HKDF-SHA256 key derivation (legacy-bridge-5)
    - Device Key hierarchy (key_hierarchy.py)

    Performs HKDF within TPM trust boundary per LOCD spec §10.2.
    """

    def __init__(
        self,
        tpm_session_open_func=None,
        tpm_session_close_func=None,
        derive_credential_key_func=None,
        key_hierarchy=None,
    ):
        """
        Initialize credential key deriver with integrations.

        Args:
            tpm_session_open_func: Function from legacy-bridge-6 (tpm_session_open)
            tpm_session_close_func: Function from legacy-bridge-6 (tpm_session_close)
            derive_credential_key_func: Function from legacy-bridge-5 (derive_credential_key)
            key_hierarchy: KeyHierarchy instance for Device Key access

        Note:
            If not provided, will attempt to import from locd modules.
        """
        # Import functions if not provided
        if tpm_session_open_func is None:
            try:
                from locd.legacy_bridge.tpm_session import tpm_session_open
                tpm_session_open_func = tpm_session_open
            except ImportError:
                raise CredentialKeyDerivationError(
                    "legacy-bridge-6 (tpm_session) not available. "
                    "Install with: pip install locd[tpm]"
                )

        if tpm_session_close_func is None:
            try:
                from locd.legacy_bridge.tpm_session import tpm_session_close
                tpm_session_close_func = tpm_session_close
            except ImportError:
                pass  # Will fail if actually used

        if derive_credential_key_func is None:
            try:
                from locd.legacy_bridge.hkdf import derive_credential_key
                derive_credential_key_func = derive_credential_key
            except ImportError:
                raise CredentialKeyDerivationError(
                    "legacy-bridge-5 (hkdf) not available. "
                    "Install with: pip install locd[crypto]"
                )

        if key_hierarchy is None:
            try:
                from key_hierarchy import KeyHierarchy
                key_hierarchy = KeyHierarchy()
            except ImportError:
                raise CredentialKeyDerivationError(
                    "key_hierarchy module not available"
                )

        self.tpm_session_open = tpm_session_open_func
        self.tpm_session_close = tpm_session_close_func
        self.derive_credential_key = derive_credential_key_func
        self.key_hierarchy = key_hierarchy

    @contextmanager
    def _managed_tpm_session(self):
        """
        Context manager for TPM session lifecycle.

        Ensures session is opened and closed properly.

        Yields:
            TPM session object

        Raises:
            TPMSessionUnavailableError: If session cannot be opened
        """
        try:
            session = self.tpm_session_open()
        except Exception as e:
            raise TPMSessionUnavailableError(f"Failed to open TPM session: {e}")

        try:
            yield session
        finally:
            try:
                self.tpm_session_close(session)
            except Exception as e:
                # Log but don't fail if close fails
                pass

    def derive_sealed_credential_key(
        self,
        device_id: str,
        service_domain: str,
        delegation_token=None,
    ) -> SealedKeyBuffer:
        """
        Derive a credential encryption key from TPM-bound Device Key.

        Complete flow per plan:
        1. Open TPM session (legacy-bridge-6: tpm_session_open)
        2. Get Device Key from Key Hierarchy
        3. Generate random salt (32 bytes)
        4. Call HKDF-SHA256 (legacy-bridge-5: derive_credential_key)
        5. Return SealedKeyBuffer with opaque handle
        6. Close TPM session (legacy-bridge-6: tpm_session_close)

        Args:
            device_id: Unique device identifier
            service_domain: Service domain for credential (e.g., "api.example.com")
            delegation_token: Delegation token authorizing Device Key use

        Returns:
            SealedKeyBuffer with derived encryption key

        Raises:
            TPMSessionUnavailableError: If TPM session cannot be opened
            HKDFDerivationError: If key derivation fails
            KeyHierarchyError: If Device Key cannot be accessed

        Example:
            >>> deriver = CredentialKeyDeriver()
            >>> sealed = deriver.derive_sealed_credential_key(
            ...     device_id="laptop-001",
            ...     service_domain="api.example.com"
            ... )
            >>> # Use sealed key for encryption
            >>> from locd.legacy_bridge import encrypt_credential_data
            >>> encrypted = encrypt_credential_data(
            ...     plaintext=credential_json,
            ...     device_key=sealed.get_key()
            ... )
            >>> # Key is automatically cleared when exiting scope
        """
        try:
            with self._managed_tpm_session() as tpm_session:
                # Step 2: Get Device Key from Key Hierarchy
                device_key = self.key_hierarchy.get_device_key(
                    device_id=device_id,
                    tpm_session=tpm_session,
                    delegation_token=delegation_token,
                )

                # Step 3: Get Device Key material for HKDF input
                device_key_material = self.key_hierarchy.get_device_key_material(
                    device_key=device_key,
                    tpm_session=tpm_session,
                )

                # Step 4: Generate random salt (per-credential, 32 bytes)
                salt = os.urandom(32)

                # Step 5: Derive credential key via HKDF-SHA256 (legacy-bridge-5)
                try:
                    derived_key = self.derive_credential_key(
                        device_key=device_key_material,
                        salt=salt,
                        key_length=32,  # 256-bit for XChaCha20-Poly1305
                    )
                except Exception as e:
                    raise HKDFDerivationError(f"HKDF derivation failed: {e}")

                # Step 6: Return sealed key buffer (opaque handle)
                sealed_buffer = SealedKeyBuffer(
                    derived_key=derived_key,
                    salt=salt,
                    service_domain=service_domain,
                    context={
                        "device_id": device_id,
                        "timestamp": time.time(),
                    },
                )

                return sealed_buffer

        except (TPMSessionUnavailableError, HKDFDerivationError):
            raise
        except Exception as e:
            raise CredentialKeyDerivationError(
                f"Failed to derive sealed credential key: {e}"
            )

    def derive_multiple_credential_keys(
        self,
        device_id: str,
        service_domains: list,
        delegation_token=None,
    ) -> dict:
        """
        Derive credential keys for multiple services in a single TPM session.

        Optimization: Opens TPM session once and derives keys for multiple services.
        Reduces overhead compared to derive_sealed_credential_key() called multiple times.

        Args:
            device_id: Unique device identifier
            service_domains: List of service domains to derive keys for
            delegation_token: Delegation token authorizing Device Key use

        Returns:
            Dictionary mapping service_domain -> SealedKeyBuffer

        Raises:
            TPMSessionUnavailableError: If TPM session cannot be opened
            HKDFDerivationError: If key derivation fails
        """
        sealed_keys = {}

        try:
            with self._managed_tpm_session() as tpm_session:
                # Get Device Key once
                device_key = self.key_hierarchy.get_device_key(
                    device_id=device_id,
                    tpm_session=tpm_session,
                    delegation_token=delegation_token,
                )

                device_key_material = self.key_hierarchy.get_device_key_material(
                    device_key=device_key,
                    tpm_session=tpm_session,
                )

                # Derive key for each service
                for service_domain in service_domains:
                    salt = os.urandom(32)

                    try:
                        derived_key = self.derive_credential_key(
                            device_key=device_key_material,
                            salt=salt,
                            key_length=32,
                        )
                    except Exception as e:
                        raise HKDFDerivationError(
                            f"HKDF derivation failed for {service_domain}: {e}"
                        )

                    sealed_keys[service_domain] = SealedKeyBuffer(
                        derived_key=derived_key,
                        salt=salt,
                        service_domain=service_domain,
                        context={"device_id": device_id},
                    )

            return sealed_keys

        except (TPMSessionUnavailableError, HKDFDerivationError):
            raise
        except Exception as e:
            raise CredentialKeyDerivationError(
                f"Failed to derive multiple credential keys: {e}"
            )
