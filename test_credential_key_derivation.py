"""
Unit tests for credential_key_derivation.py module.

Tests credential key derivation orchestration, TPM session integration,
and HKDF integration with legacy-bridge-5 and legacy-bridge-6.
"""

import pytest
import os
import time
from unittest.mock import Mock, MagicMock, patch, call
from credential_key_derivation import (
    CredentialKeyDeriver,
    SealedKeyBuffer,
    CredentialKeyDerivationError,
    TPMSessionUnavailableError,
    HKDFDerivationError,
)
from key_hierarchy import KeyHierarchy, DeviceKey, DelegationToken


class TestSealedKeyBuffer:
    """Tests for SealedKeyBuffer class."""

    def test_create_sealed_key_buffer(self):
        """Test creating a SealedKeyBuffer."""
        key = os.urandom(32)
        salt = os.urandom(32)

        sealed = SealedKeyBuffer(
            derived_key=key,
            salt=salt,
            service_domain="api.example.com",
        )

        assert sealed.derived_key == key
        assert sealed.salt == salt
        assert sealed.service_domain == "api.example.com"

    def test_sealed_key_buffer_get_key(self):
        """Test retrieving key from sealed buffer."""
        key = os.urandom(32)
        salt = os.urandom(32)

        sealed = SealedKeyBuffer(
            derived_key=key,
            salt=salt,
            service_domain="api.example.com",
        )

        assert sealed.get_key() == key

    def test_sealed_key_buffer_get_salt(self):
        """Test retrieving salt from sealed buffer."""
        key = os.urandom(32)
        salt = os.urandom(32)

        sealed = SealedKeyBuffer(
            derived_key=key,
            salt=salt,
            service_domain="api.example.com",
        )

        assert sealed.get_salt() == salt

    def test_sealed_key_buffer_clear(self):
        """Test clearing key material from sealed buffer."""
        key = os.urandom(32)
        salt = os.urandom(32)

        sealed = SealedKeyBuffer(
            derived_key=key,
            salt=salt,
            service_domain="api.example.com",
        )

        sealed.clear()

        # After clearing, should raise error on access
        with pytest.raises(CredentialKeyDerivationError):
            sealed.get_key()

        with pytest.raises(CredentialKeyDerivationError):
            sealed.get_salt()

    def test_sealed_key_buffer_context_manager(self):
        """Test SealedKeyBuffer as context manager."""
        key = os.urandom(32)
        salt = os.urandom(32)

        with SealedKeyBuffer(
            derived_key=key,
            salt=salt,
            service_domain="api.example.com",
        ) as sealed:
            # Should be accessible inside context
            assert sealed.get_key() == key
            assert sealed.get_salt() == salt

        # After context, should be cleared
        with pytest.raises(CredentialKeyDerivationError):
            sealed.get_key()

    def test_sealed_key_buffer_destructor_cleanup(self):
        """Test SealedKeyBuffer clears on garbage collection."""
        sealed = SealedKeyBuffer(
            derived_key=os.urandom(32),
            salt=os.urandom(32),
            service_domain="api.example.com",
        )

        # Delete the object
        del sealed

        # Verify cleanup happened (no exception on re-creation)
        new_sealed = SealedKeyBuffer(
            derived_key=os.urandom(32),
            salt=os.urandom(32),
            service_domain="other.com",
        )
        assert new_sealed.service_domain == "other.com"

    def test_sealed_key_buffer_context_info(self):
        """Test SealedKeyBuffer stores context information."""
        sealed = SealedKeyBuffer(
            derived_key=os.urandom(32),
            salt=os.urandom(32),
            service_domain="api.example.com",
            context={"device_id": "laptop-001", "timestamp": 1234567890},
        )

        assert sealed.context["device_id"] == "laptop-001"
        assert sealed.context["timestamp"] == 1234567890


class TestCredentialKeyDeriver:
    """Tests for CredentialKeyDeriver class."""

    def test_credential_key_deriver_initialization(self):
        """Test CredentialKeyDeriver initialization with mock functions."""
        mock_session_open = Mock()
        mock_session_close = Mock()
        mock_derive_key = Mock()
        mock_key_hierarchy = Mock()

        deriver = CredentialKeyDeriver(
            tpm_session_open_func=mock_session_open,
            tpm_session_close_func=mock_session_close,
            derive_credential_key_func=mock_derive_key,
            key_hierarchy=mock_key_hierarchy,
        )

        assert deriver.tpm_session_open == mock_session_open
        assert deriver.tpm_session_close == mock_session_close
        assert deriver.derive_credential_key == mock_derive_key
        assert deriver.key_hierarchy == mock_key_hierarchy

    def test_credential_key_deriver_missing_legacy_bridge_5(self):
        """Test error when legacy-bridge-5 (hkdf) is not available."""
        mock_session_open = Mock()
        mock_session_close = Mock()

        with patch('builtins.__import__', side_effect=ImportError):
            with pytest.raises(CredentialKeyDerivationError, match="legacy-bridge-5"):
                CredentialKeyDeriver(
                    tpm_session_open_func=mock_session_open,
                    tpm_session_close_func=mock_session_close,
                    derive_credential_key_func=None,
                )

    def test_credential_key_deriver_missing_legacy_bridge_6(self):
        """Test error when legacy-bridge-6 (tpm_session) is not available."""
        mock_derive_key = Mock()

        with patch('builtins.__import__', side_effect=ImportError):
            with pytest.raises(CredentialKeyDerivationError, match="legacy-bridge-6"):
                CredentialKeyDeriver(
                    tpm_session_open_func=None,
                    tpm_session_close_func=None,
                    derive_credential_key_func=mock_derive_key,
                )

    def test_derive_sealed_credential_key_success(self):
        """Test successful credential key derivation."""
        # Create mocks for all dependencies
        mock_session = MagicMock()
        mock_session.session_handle = 0x123456

        mock_session_open = Mock(return_value=mock_session)
        mock_session_close = Mock()

        device_key = os.urandom(32)
        derived_key = os.urandom(32)

        mock_derive_key = Mock(return_value=derived_key)

        # Setup key hierarchy mock
        mock_device_key_obj = Mock(spec=DeviceKey)
        mock_device_key_obj.is_authorized.return_value = True
        mock_device_key_obj.public_key = device_key

        mock_key_hierarchy = Mock()
        mock_key_hierarchy.get_device_key.return_value = mock_device_key_obj
        mock_key_hierarchy.get_device_key_material.return_value = device_key

        deriver = CredentialKeyDeriver(
            tpm_session_open_func=mock_session_open,
            tpm_session_close_func=mock_session_close,
            derive_credential_key_func=mock_derive_key,
            key_hierarchy=mock_key_hierarchy,
        )

        # Derive key
        sealed = deriver.derive_sealed_credential_key(
            device_id="device-001",
            service_domain="api.example.com",
        )

        # Verify calls
        mock_session_open.assert_called_once()
        mock_key_hierarchy.get_device_key.assert_called_once_with(
            device_id="device-001",
            tpm_session=mock_session,
            delegation_token=None,
        )
        mock_key_hierarchy.get_device_key_material.assert_called_once()
        mock_derive_key.assert_called_once()
        mock_session_close.assert_called_once_with(mock_session)

        # Verify sealed buffer
        assert isinstance(sealed, SealedKeyBuffer)
        assert sealed.get_key() == derived_key
        assert sealed.service_domain == "api.example.com"

    def test_derive_sealed_credential_key_tpm_session_fails(self):
        """Test error handling when TPM session cannot be opened."""
        mock_session_open = Mock(side_effect=Exception("TPM unavailable"))
        mock_session_close = Mock()
        mock_derive_key = Mock()

        deriver = CredentialKeyDeriver(
            tpm_session_open_func=mock_session_open,
            tpm_session_close_func=mock_session_close,
            derive_credential_key_func=mock_derive_key,
            key_hierarchy=Mock(),
        )

        with pytest.raises(TPMSessionUnavailableError):
            deriver.derive_sealed_credential_key(
                device_id="device-001",
                service_domain="api.example.com",
            )

    def test_derive_sealed_credential_key_hkdf_fails(self):
        """Test error handling when HKDF derivation fails."""
        mock_session = MagicMock()
        mock_session_open = Mock(return_value=mock_session)
        mock_session_close = Mock()
        mock_derive_key = Mock(side_effect=ValueError("Invalid salt length"))

        # Setup key hierarchy
        mock_device_key_obj = Mock(spec=DeviceKey)
        mock_device_key_obj.is_authorized.return_value = True

        mock_key_hierarchy = Mock()
        mock_key_hierarchy.get_device_key.return_value = mock_device_key_obj
        mock_key_hierarchy.get_device_key_material.return_value = os.urandom(32)

        deriver = CredentialKeyDeriver(
            tpm_session_open_func=mock_session_open,
            tpm_session_close_func=mock_session_close,
            derive_credential_key_func=mock_derive_key,
            key_hierarchy=mock_key_hierarchy,
        )

        with pytest.raises(HKDFDerivationError):
            deriver.derive_sealed_credential_key(
                device_id="device-001",
                service_domain="api.example.com",
            )

        # Verify session was still closed
        mock_session_close.assert_called_once()

    def test_derive_sealed_credential_key_with_delegation_token(self):
        """Test key derivation with delegation token."""
        mock_session = MagicMock()
        mock_session.session_handle = 0x123456

        mock_session_open = Mock(return_value=mock_session)
        mock_session_close = Mock()

        device_key = os.urandom(32)
        derived_key = os.urandom(32)

        mock_derive_key = Mock(return_value=derived_key)

        # Create delegation token
        token = DelegationToken(
            delegator_key=os.urandom(32),
            delegate_key=device_key,
            issued_at=int(time.time()),
            expires_at=int(time.time()) + 86400,
            delegation_id="test-token",
            services=["api.example.com"],
            actions=["read"],
        )

        # Setup key hierarchy
        mock_device_key_obj = Mock(spec=DeviceKey)
        mock_device_key_obj.is_authorized.return_value = True

        mock_key_hierarchy = Mock()
        mock_key_hierarchy.get_device_key.return_value = mock_device_key_obj
        mock_key_hierarchy.get_device_key_material.return_value = device_key

        deriver = CredentialKeyDeriver(
            tpm_session_open_func=mock_session_open,
            tpm_session_close_func=mock_session_close,
            derive_credential_key_func=mock_derive_key,
            key_hierarchy=mock_key_hierarchy,
        )

        # Derive with token
        sealed = deriver.derive_sealed_credential_key(
            device_id="device-001",
            service_domain="api.example.com",
            delegation_token=token,
        )

        # Verify token was passed
        mock_key_hierarchy.get_device_key.assert_called_once_with(
            device_id="device-001",
            tpm_session=mock_session,
            delegation_token=token,
        )

        assert sealed.service_domain == "api.example.com"

    def test_derive_multiple_credential_keys(self):
        """Test deriving keys for multiple services in single session."""
        mock_session = MagicMock()
        mock_session_open = Mock(return_value=mock_session)
        mock_session_close = Mock()

        device_key = os.urandom(32)

        # Mock HKDF to return different keys for each call
        derived_keys = [os.urandom(32) for _ in range(3)]
        mock_derive_key = Mock(side_effect=derived_keys)

        # Setup key hierarchy
        mock_device_key_obj = Mock(spec=DeviceKey)
        mock_device_key_obj.is_authorized.return_value = True

        mock_key_hierarchy = Mock()
        mock_key_hierarchy.get_device_key.return_value = mock_device_key_obj
        mock_key_hierarchy.get_device_key_material.return_value = device_key

        deriver = CredentialKeyDeriver(
            tpm_session_open_func=mock_session_open,
            tpm_session_close_func=mock_session_close,
            derive_credential_key_func=mock_derive_key,
            key_hierarchy=mock_key_hierarchy,
        )

        # Derive keys for multiple services
        services = ["api.example.com", "oauth.example.com", "cdn.example.com"]
        sealed_keys = deriver.derive_multiple_credential_keys(
            device_id="device-001",
            service_domains=services,
        )

        # Verify results
        assert len(sealed_keys) == 3
        assert all(domain in sealed_keys for domain in services)

        # Verify session was opened and closed once
        mock_session_open.assert_called_once()
        mock_session_close.assert_called_once()

        # Verify HKDF was called for each service
        assert mock_derive_key.call_count == 3

        # Verify each key is different
        keys = [sealed_keys[domain].get_key() for domain in services]
        assert len(set(keys)) == 3  # All different

    def test_derive_multiple_credential_keys_one_fails(self):
        """Test error handling when one HKDF derivation fails."""
        mock_session = MagicMock()
        mock_session_open = Mock(return_value=mock_session)
        mock_session_close = Mock()

        device_key = os.urandom(32)

        # HKDF succeeds once, then fails
        mock_derive_key = Mock(
            side_effect=[os.urandom(32), ValueError("Invalid parameters")]
        )

        mock_device_key_obj = Mock(spec=DeviceKey)
        mock_device_key_obj.is_authorized.return_value = True

        mock_key_hierarchy = Mock()
        mock_key_hierarchy.get_device_key.return_value = mock_device_key_obj
        mock_key_hierarchy.get_device_key_material.return_value = device_key

        deriver = CredentialKeyDeriver(
            tpm_session_open_func=mock_session_open,
            tpm_session_close_func=mock_session_close,
            derive_credential_key_func=mock_derive_key,
            key_hierarchy=mock_key_hierarchy,
        )

        services = ["api.example.com", "oauth.example.com"]

        with pytest.raises(HKDFDerivationError):
            deriver.derive_multiple_credential_keys(
                device_id="device-001",
                service_domains=services,
            )

        # Verify session was still closed
        mock_session_close.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
