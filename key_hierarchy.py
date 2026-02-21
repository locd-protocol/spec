"""
Key Hierarchy Module for Loc'd Protocol

Implements Tier 2 Device Key management per LOCD spec §4.2.
Provides interface to obtain Device Key from TPM/Secure Enclave for credential encryption.

Device Key is a Tier 2 key pair generated within TPM and authorized via delegation token
signed by the Master Key. This module handles Device Key retrieval and lifecycle.
"""

from typing import Optional, Union
from dataclasses import dataclass
import os


class KeyHierarchyError(Exception):
    """Base exception for key hierarchy operations."""
    pass


class DeviceKeyNotFoundError(KeyHierarchyError):
    """Raised when Device Key cannot be accessed or is not available."""
    pass


class DelegationTokenInvalidError(KeyHierarchyError):
    """Raised when delegation token is invalid or expired."""
    pass


@dataclass
class DelegationToken:
    """
    Represents a delegation token for Device Key authorization.
    Per LOCD spec §6.2, signed by Master Key.
    """
    delegator_key: bytes  # Master Key public key (32 bytes)
    delegate_key: bytes   # Device Key public key (32 bytes)
    issued_at: int        # Unix timestamp
    expires_at: int       # Unix timestamp
    delegation_id: str    # UUID v4
    services: list        # Permitted service domains
    actions: list         # Permitted actions
    is_valid: bool = True # Whether token is still valid


class DeviceKey:
    """
    Represents a Tier 2 Device Key bound to TPM/Secure Enclave.

    Per LOCD spec §4.2:
    - Generated within TPM 2.0 or Secure Enclave
    - Uses Ed25519 algorithm
    - Private key MUST NOT leave the TPM/Secure Enclave
    - Authorized via delegation token signed by Master Key
    """

    def __init__(
        self,
        public_key: bytes,
        tpm_handle: Optional[int] = None,
        delegation_token: Optional[DelegationToken] = None,
    ):
        """
        Initialize a Device Key reference.

        Args:
            public_key: Device Key public key (32 bytes for Ed25519)
            tpm_handle: Handle to TPM object (Linux) or session context (macOS)
            delegation_token: Authorization token from Master Key

        Raises:
            ValueError: If public_key is not 32 bytes
        """
        if len(public_key) != 32:
            raise ValueError(f"Device Key public key must be 32 bytes, got {len(public_key)}")

        self.public_key = public_key
        self.tpm_handle = tpm_handle
        self.delegation_token = delegation_token

    def is_authorized(self) -> bool:
        """
        Check if Device Key has valid authorization.

        Returns:
            True if delegation token exists and is valid
        """
        if not self.delegation_token:
            return False
        return self.delegation_token.is_valid

    def check_service_scope(self, service_domain: str) -> bool:
        """
        Check if Device Key is authorized for the given service domain.

        Args:
            service_domain: Domain requesting access (e.g., "api.example.com")

        Returns:
            True if service is in permitted services list
        """
        if not self.delegation_token:
            return False

        # Empty services list means all services permitted
        if not self.delegation_token.services:
            return True

        # Check exact match or wildcard match
        for permitted in self.delegation_token.services:
            if permitted == service_domain or permitted == "*":
                return True
            # Support wildcard patterns like "*.example.com"
            if permitted.startswith("*.") and service_domain.endswith(permitted[1:]):
                return True

        return False


class KeyHierarchy:
    """
    Manages the Loc'd key hierarchy with Tier 1 (Master Key) at root
    and Tier 2 (Device Keys) as authorized children.

    Provides interface to retrieve Device Key for credential encryption.
    Per LOCD spec §4: Key Lifecycle
    """

    def __init__(self, storage_path: Optional[str] = None):
        """
        Initialize key hierarchy manager.

        Args:
            storage_path: Directory for key metadata storage.
                         Defaults to ~/.locd/keys/
        """
        if storage_path is None:
            storage_path = os.path.expanduser("~/.locd/keys")

        self.storage_path = storage_path
        os.makedirs(storage_path, exist_ok=True)
        os.chmod(storage_path, 0o700)

    def get_device_key(
        self,
        device_id: str,
        tpm_session=None,
        delegation_token: Optional[DelegationToken] = None,
    ) -> DeviceKey:
        """
        Retrieve a Tier 2 Device Key for the given device.

        Per LOCD spec §4.2:
        - Device Key is generated within TPM/Secure Enclave
        - Private key MUST NOT leave the TPM
        - Authorization requires valid delegation token from Master Key

        Args:
            device_id: Unique identifier for the device
            tpm_session: TPM session object from tpm_session_open()
            delegation_token: Delegation token authorizing this Device Key

        Returns:
            DeviceKey object with public key and authorization

        Raises:
            DeviceKeyNotFoundError: If Device Key cannot be accessed
            DelegationTokenInvalidError: If delegation token is invalid/expired
        """
        # In production, this would:
        # 1. Verify TPM session is valid
        # 2. Load Device Key from TPM using session handle
        # 3. Verify delegation token signature and expiry
        # 4. Return DeviceKey with TPM handle

        # For now, generate a mock Device Key
        device_key_public = self._get_or_create_device_key(device_id)

        # Validate delegation token if provided
        if delegation_token:
            if not self._validate_delegation_token(delegation_token):
                raise DelegationTokenInvalidError(
                    f"Delegation token expired or invalid for device {device_id}"
                )

        return DeviceKey(
            public_key=device_key_public,
            tpm_handle=getattr(tpm_session, 'session_handle', None) if tpm_session else None,
            delegation_token=delegation_token,
        )

    def get_device_key_material(
        self,
        device_key: DeviceKey,
        tpm_session=None,
    ) -> bytes:
        """
        Get the Device Key material for use in HKDF derivation.

        Per LOCD spec §10.2, this key material is used as input to HKDF-SHA256
        for credential encryption key derivation.

        Args:
            device_key: DeviceKey object from get_device_key()
            tpm_session: Active TPM session (required for key operations)

        Returns:
            Device Key material (32 bytes) for HKDF input

        Raises:
            DeviceKeyNotFoundError: If key material cannot be retrieved
            KeyHierarchyError: If TPM operation fails
        """
        # In production, this would:
        # 1. Verify TPM session is still valid
        # 2. Use TPM2_Sign or export key material via TPM session
        # 3. Return key material that never left TPM boundary

        if not device_key.is_authorized():
            raise KeyHierarchyError("Device Key is not authorized")

        if tpm_session is None:
            raise KeyHierarchyError("TPM session required to access Device Key material")

        # Return the Device Key public key as material
        # In production, this would be the actual key material from TPM
        return device_key.public_key

    def _get_or_create_device_key(self, device_id: str) -> bytes:
        """
        Get existing Device Key or create new one.

        Args:
            device_id: Unique device identifier

        Returns:
            Device Key public key (32 bytes)
        """
        key_file = os.path.join(self.storage_path, f"{device_id}.pub")

        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()

        # Generate new Device Key (in production, would be in TPM)
        device_key = os.urandom(32)

        with open(key_file, 'wb') as f:
            f.write(device_key)

        os.chmod(key_file, 0o600)
        return device_key

    def _validate_delegation_token(self, token: DelegationToken) -> bool:
        """
        Validate delegation token structure and expiry.

        Args:
            token: Delegation token to validate

        Returns:
            True if token is valid, False if expired or invalid
        """
        if not token.is_valid:
            return False

        import time
        current_time = int(time.time())

        # Check expiry (per spec §6.2, expires_at is required)
        if current_time > token.expires_at:
            return False

        # Check issued_at is not in future (with 60-second clock skew tolerance)
        if token.issued_at > current_time + 60:
            return False

        return True
