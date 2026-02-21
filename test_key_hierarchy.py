"""
Unit tests for key_hierarchy.py module.

Tests Tier 2 Device Key management and delegation token validation.
"""

import pytest
import os
import tempfile
import time
from key_hierarchy import (
    KeyHierarchy,
    DeviceKey,
    DelegationToken,
    KeyHierarchyError,
    DeviceKeyNotFoundError,
    DelegationTokenInvalidError,
)


class TestDelegationToken:
    """Tests for DelegationToken class."""

    def test_create_delegation_token(self):
        """Test creating a valid delegation token."""
        token = DelegationToken(
            delegator_key=os.urandom(32),
            delegate_key=os.urandom(32),
            issued_at=int(time.time()),
            expires_at=int(time.time()) + 86400,
            delegation_id="550e8400-e29b-41d4-a716-446655440000",
            services=["api.example.com"],
            actions=["read", "write"],
        )

        assert token.is_valid is True
        assert len(token.delegator_key) == 32
        assert len(token.delegate_key) == 32

    def test_delegation_token_fields(self):
        """Test delegation token contains required fields per spec §6.2."""
        now = int(time.time())
        token = DelegationToken(
            delegator_key=os.urandom(32),
            delegate_key=os.urandom(32),
            issued_at=now,
            expires_at=now + 86400,
            delegation_id="test-id",
            services=["example.com"],
            actions=["read"],
        )

        assert token.issued_at == now
        assert token.expires_at == now + 86400
        assert "example.com" in token.services
        assert "read" in token.actions


class TestDeviceKey:
    """Tests for DeviceKey class."""

    def test_create_device_key(self):
        """Test creating a Device Key with valid public key."""
        public_key = os.urandom(32)
        device_key = DeviceKey(public_key=public_key)

        assert device_key.public_key == public_key
        assert len(device_key.public_key) == 32

    def test_device_key_invalid_length(self):
        """Test Device Key validation rejects non-32-byte keys."""
        with pytest.raises(ValueError, match="must be 32 bytes"):
            DeviceKey(public_key=os.urandom(16))

        with pytest.raises(ValueError, match="must be 32 bytes"):
            DeviceKey(public_key=os.urandom(64))

    def test_device_key_with_delegation_token(self):
        """Test Device Key with attached delegation token."""
        public_key = os.urandom(32)
        token = DelegationToken(
            delegator_key=os.urandom(32),
            delegate_key=public_key,
            issued_at=int(time.time()),
            expires_at=int(time.time()) + 86400,
            delegation_id="test-id",
            services=[],
            actions=[],
        )

        device_key = DeviceKey(public_key=public_key, delegation_token=token)
        assert device_key.is_authorized() is True

    def test_device_key_authorization_check(self):
        """Test Device Key authorization validation."""
        public_key = os.urandom(32)
        device_key = DeviceKey(public_key=public_key)

        # Without token, should not be authorized
        assert device_key.is_authorized() is False

        # With valid token, should be authorized
        token = DelegationToken(
            delegator_key=os.urandom(32),
            delegate_key=public_key,
            issued_at=int(time.time()),
            expires_at=int(time.time()) + 86400,
            delegation_id="test-id",
            services=[],
            actions=[],
        )
        device_key.delegation_token = token
        assert device_key.is_authorized() is True

    def test_device_key_service_scope_all(self):
        """Test Device Key permits all services when services list is empty."""
        public_key = os.urandom(32)
        token = DelegationToken(
            delegator_key=os.urandom(32),
            delegate_key=public_key,
            issued_at=int(time.time()),
            expires_at=int(time.time()) + 86400,
            delegation_id="test-id",
            services=[],  # Empty means all services
            actions=[],
        )
        device_key = DeviceKey(public_key=public_key, delegation_token=token)

        assert device_key.check_service_scope("api.example.com") is True
        assert device_key.check_service_scope("other-service.com") is True

    def test_device_key_service_scope_specific(self):
        """Test Device Key service scope restriction."""
        public_key = os.urandom(32)
        token = DelegationToken(
            delegator_key=os.urandom(32),
            delegate_key=public_key,
            issued_at=int(time.time()),
            expires_at=int(time.time()) + 86400,
            delegation_id="test-id",
            services=["api.example.com", "www.example.com"],
            actions=[],
        )
        device_key = DeviceKey(public_key=public_key, delegation_token=token)

        assert device_key.check_service_scope("api.example.com") is True
        assert device_key.check_service_scope("www.example.com") is True
        assert device_key.check_service_scope("other.com") is False

    def test_device_key_service_scope_wildcard(self):
        """Test Device Key wildcard service scope."""
        public_key = os.urandom(32)
        token = DelegationToken(
            delegator_key=os.urandom(32),
            delegate_key=public_key,
            issued_at=int(time.time()),
            expires_at=int(time.time()) + 86400,
            delegation_id="test-id",
            services=["*.example.com"],
            actions=[],
        )
        device_key = DeviceKey(public_key=public_key, delegation_token=token)

        assert device_key.check_service_scope("api.example.com") is True
        assert device_key.check_service_scope("www.example.com") is True
        assert device_key.check_service_scope("other.com") is False


class TestKeyHierarchy:
    """Tests for KeyHierarchy class."""

    def test_key_hierarchy_initialization(self):
        """Test KeyHierarchy initialization creates storage directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            kh = KeyHierarchy(storage_path=tmpdir)
            assert os.path.exists(tmpdir)

    def test_get_device_key_creates_new(self):
        """Test get_device_key creates new Device Key if not present."""
        with tempfile.TemporaryDirectory() as tmpdir:
            kh = KeyHierarchy(storage_path=tmpdir)

            device_key = kh.get_device_key("device-001")

            assert isinstance(device_key, DeviceKey)
            assert len(device_key.public_key) == 32

    def test_get_device_key_returns_existing(self):
        """Test get_device_key returns existing key on second call."""
        with tempfile.TemporaryDirectory() as tmpdir:
            kh = KeyHierarchy(storage_path=tmpdir)

            # First call
            device_key_1 = kh.get_device_key("device-001")

            # Second call should return same key
            device_key_2 = kh.get_device_key("device-001")

            assert device_key_1.public_key == device_key_2.public_key

    def test_get_device_key_with_delegation_token(self):
        """Test get_device_key with valid delegation token."""
        with tempfile.TemporaryDirectory() as tmpdir:
            kh = KeyHierarchy(storage_path=tmpdir)

            # Create device key first to get public key
            device_key = kh.get_device_key("device-001")

            # Create delegation token
            token = DelegationToken(
                delegator_key=os.urandom(32),
                delegate_key=device_key.public_key,
                issued_at=int(time.time()),
                expires_at=int(time.time()) + 86400,
                delegation_id="test-id",
                services=[],
                actions=[],
            )

            # Get key with token
            device_key_with_token = kh.get_device_key(
                "device-001",
                delegation_token=token,
            )

            assert device_key_with_token.is_authorized() is True

    def test_get_device_key_expired_token_fails(self):
        """Test get_device_key raises error for expired delegation token."""
        with tempfile.TemporaryDirectory() as tmpdir:
            kh = KeyHierarchy(storage_path=tmpdir)

            device_key = kh.get_device_key("device-001")

            # Create expired delegation token
            token = DelegationToken(
                delegator_key=os.urandom(32),
                delegate_key=device_key.public_key,
                issued_at=int(time.time()) - 86400,
                expires_at=int(time.time()) - 1,  # Expired
                delegation_id="test-id",
                services=[],
                actions=[],
            )

            with pytest.raises(DelegationTokenInvalidError):
                kh.get_device_key("device-001", delegation_token=token)

    def test_get_device_key_material(self):
        """Test get_device_key_material returns key material."""
        with tempfile.TemporaryDirectory() as tmpdir:
            kh = KeyHierarchy(storage_path=tmpdir)

            device_key = kh.get_device_key("device-001")

            # Mock TPM session
            class MockTPMSession:
                session_handle = 0x123456

            # Create mock token for authorization
            token = DelegationToken(
                delegator_key=os.urandom(32),
                delegate_key=device_key.public_key,
                issued_at=int(time.time()),
                expires_at=int(time.time()) + 86400,
                delegation_id="test-id",
                services=[],
                actions=[],
            )
            device_key.delegation_token = token

            tpm_session = MockTPMSession()
            key_material = kh.get_device_key_material(device_key, tpm_session)

            assert isinstance(key_material, bytes)
            assert len(key_material) == 32

    def test_get_device_key_material_requires_session(self):
        """Test get_device_key_material requires TPM session."""
        with tempfile.TemporaryDirectory() as tmpdir:
            kh = KeyHierarchy(storage_path=tmpdir)

            device_key = kh.get_device_key("device-001")

            # Create authorization
            token = DelegationToken(
                delegator_key=os.urandom(32),
                delegate_key=device_key.public_key,
                issued_at=int(time.time()),
                expires_at=int(time.time()) + 86400,
                delegation_id="test-id",
                services=[],
                actions=[],
            )
            device_key.delegation_token = token

            # Should fail without session
            with pytest.raises(KeyHierarchyError):
                kh.get_device_key_material(device_key, tpm_session=None)

    def test_get_device_key_material_requires_authorization(self):
        """Test get_device_key_material requires Device Key authorization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            kh = KeyHierarchy(storage_path=tmpdir)

            device_key = kh.get_device_key("device-001")

            # Mock TPM session (but key not authorized)
            class MockTPMSession:
                session_handle = 0x123456

            with pytest.raises(KeyHierarchyError):
                kh.get_device_key_material(device_key, MockTPMSession())


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
