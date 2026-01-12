"""
Unit tests for Keycloak OAuth2 integration.

Tests:
1. KeycloakJWTValidator initialization and configuration
2. JWT validation (mocked Keycloak responses)
3. RBAC role mapping
4. Keycloak authentication client
5. Integration with A2ASecurityManager

Run with:
    pytest test_keycloak_integration.py -v
"""

import pytest
import os
import json
import time
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any

# Mock PyJWT and requests before importing keycloak_auth
import sys
sys.modules['jwt'] = MagicMock()
sys.modules['jwt.PyJWKClient'] = MagicMock()

from keycloak_auth import (
    KeycloakJWTValidator,
    KeycloakRBACMapper,
    KeycloakAuthClient
)


class TestKeycloakJWTValidator:
    """Test Keycloak JWT validator"""
    
    def test_initialization(self):
        """Test KeycloakJWTValidator initialization"""
        validator = KeycloakJWTValidator(
            keycloak_url="http://keycloak.example.com",
            realm="test-realm",
            client_id="test-client"
        )
        
        assert validator.keycloak_url == "http://keycloak.example.com"
        assert validator.realm == "test-realm"
        assert validator.client_id == "test-client"
        assert validator.issuer == "http://keycloak.example.com/realms/test-realm"
        assert validator.jwks_uri == "http://keycloak.example.com/realms/test-realm/protocol/openid-connect/certs"
    
    def test_url_normalization(self):
        """Test URL normalization (trailing slash removal)"""
        validator = KeycloakJWTValidator(
            keycloak_url="http://keycloak.example.com/",
            realm="test-realm",
            client_id="test-client"
        )
        
        assert validator.keycloak_url == "http://keycloak.example.com"
        assert not validator.keycloak_url.endswith("/")
    
    @patch('keycloak_auth.jwt')
    @patch('keycloak_auth.PyJWKClient')
    def test_verify_token_success(self, mock_jwks_client, mock_jwt):
        """Test successful JWT verification"""
        # Setup mocks
        mock_signing_key = Mock()
        mock_signing_key.key = "test-public-key"
        
        mock_client = Mock()
        mock_client.get_signing_key_from_jwt.return_value = mock_signing_key
        mock_jwks_client.return_value = mock_client
        
        mock_jwt.decode.return_value = {
            "sub": "user-123",
            "preferred_username": "test-user",
            "realm_access": {
                "roles": ["admin", "user"]
            },
            "aud": "test-client",
            "iss": "http://keycloak.example.com/realms/test-realm"
        }
        
        validator = KeycloakJWTValidator(
            keycloak_url="http://keycloak.example.com",
            realm="test-realm",
            client_id="test-client"
        )
        
        principal, roles, claims = validator.verify_token("fake.jwt.token")
        
        assert principal == "test-user"
        assert "admin" in roles
        assert "user" in roles
        assert claims["sub"] == "user-123"
    
    def test_extract_roles_realm_and_client(self):
        """Test role extraction from both realm and client scopes"""
        validator = KeycloakJWTValidator(
            keycloak_url="http://keycloak.example.com",
            realm="test-realm",
            client_id="test-client"
        )
        
        claims = {
            "realm_access": {
                "roles": ["admin", "user"]
            },
            "resource_access": {
                "test-client": {
                    "roles": ["document-processor", "viewer"]
                }
            }
        }
        
        roles = validator._extract_roles(claims)
        
        assert "admin" in roles
        assert "user" in roles
        assert "document-processor" in roles
        assert "viewer" in roles
        assert len(roles) == 4


class TestKeycloakRBACMapper:
    """Test Keycloak RBAC role mapping"""
    
    def test_default_role_mapping(self):
        """Test default role mappings"""
        mapper = KeycloakRBACMapper()
        
        assert "admin" in mapper.role_mapping
        assert "lambda" in mapper.role_mapping
        assert "orchestrator" in mapper.role_mapping
        assert "document-processor" in mapper.role_mapping
        assert "viewer" in mapper.role_mapping
    
    def test_admin_role_mapping(self):
        """Test admin role gets wildcard permissions"""
        mapper = KeycloakRBACMapper()
        principal, methods = mapper.map_roles_to_principal(["admin"])
        
        assert principal == "admin"
        assert methods == ["*"]
    
    def test_lambda_role_mapping(self):
        """Test lambda role gets wildcard permissions"""
        mapper = KeycloakRBACMapper()
        principal, methods = mapper.map_roles_to_principal(["lambda"])
        
        assert principal == "lambda"
        assert methods == ["*"]
    
    def test_orchestrator_role_mapping(self):
        """Test orchestrator role gets specific permissions"""
        mapper = KeycloakRBACMapper()
        principal, methods = mapper.map_roles_to_principal(["orchestrator"])
        
        assert principal == "orchestrator"
        assert "extract_document" in methods
        assert "validate_document" in methods
        assert "archive_document" in methods
        assert "list_skills" in methods
        assert "get_health" in methods
    
    def test_viewer_role_mapping(self):
        """Test viewer role gets read-only permissions"""
        mapper = KeycloakRBACMapper()
        principal, methods = mapper.map_roles_to_principal(["viewer"])
        
        assert principal == "viewer"
        assert "list_skills" in methods
        assert "get_health" in methods
        assert "process_document" not in methods
    
    def test_multiple_roles_priority(self):
        """Test multiple roles use highest priority"""
        mapper = KeycloakRBACMapper()
        
        # Admin takes priority
        principal, methods = mapper.map_roles_to_principal(["viewer", "admin"])
        assert principal == "admin"
        assert methods == ["*"]
        
        # Lambda takes priority over orchestrator
        principal, methods = mapper.map_roles_to_principal(["orchestrator", "lambda"])
        assert principal == "lambda"
        assert methods == ["*"]
    
    def test_unknown_role(self):
        """Test unknown role returns unknown principal"""
        mapper = KeycloakRBACMapper()
        principal, methods = mapper.map_roles_to_principal(["unknown-role"])
        
        assert principal == "unknown"
        assert len(methods) == 0
    
    def test_custom_role_mapping(self):
        """Test custom role mapping configuration"""
        custom_mapping = {
            "custom-role": {
                "principal": "custom-principal",
                "methods": ["custom_method_1", "custom_method_2"]
            }
        }
        
        mapper = KeycloakRBACMapper(role_mapping=custom_mapping)
        principal, methods = mapper.map_roles_to_principal(["custom-role"])
        
        assert principal == "custom-principal"
        assert "custom_method_1" in methods
        assert "custom_method_2" in methods


class TestKeycloakAuthClient:
    """Test Keycloak authentication client"""
    
    def test_initialization(self):
        """Test KeycloakAuthClient initialization"""
        client = KeycloakAuthClient(
            keycloak_url="http://keycloak.example.com",
            realm="test-realm",
            client_id="test-client",
            client_secret="test-secret"
        )
        
        assert client.keycloak_url == "http://keycloak.example.com"
        assert client.realm == "test-realm"
        assert client.client_id == "test-client"
        assert client.client_secret == "test-secret"
        assert client.token_endpoint == "http://keycloak.example.com/realms/test-realm/protocol/openid-connect/token"
    
    @patch('keycloak_auth.requests.post')
    def test_authenticate_password_success(self, mock_post):
        """Test successful password authentication"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "test-access-token",
            "refresh_token": "test-refresh-token",
            "expires_in": 300
        }
        mock_post.return_value = mock_response
        
        client = KeycloakAuthClient(
            keycloak_url="http://keycloak.example.com",
            realm="test-realm",
            client_id="test-client",
            client_secret="test-secret"
        )
        
        access_token, refresh_token, expires_in = client.authenticate_password(
            username="test-user",
            password="test-password"
        )
        
        assert access_token == "test-access-token"
        assert refresh_token == "test-refresh-token"
        assert expires_in == 300
    
    @patch('keycloak_auth.requests.post')
    def test_authenticate_password_failure(self, mock_post):
        """Test failed password authentication"""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.raise_for_status.side_effect = Exception("Unauthorized")
        mock_post.return_value = mock_response
        
        client = KeycloakAuthClient(
            keycloak_url="http://keycloak.example.com",
            realm="test-realm",
            client_id="test-client",
            client_secret="test-secret"
        )
        
        with pytest.raises(Exception) as exc_info:
            client.authenticate_password(
                username="test-user",
                password="wrong-password"
            )
        
        assert "Authentication failed" in str(exc_info.value)
    
    @patch('keycloak_auth.requests.post')
    def test_refresh_token_success(self, mock_post):
        """Test successful token refresh"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "new-access-token",
            "refresh_token": "new-refresh-token",
            "expires_in": 300
        }
        mock_post.return_value = mock_response
        
        client = KeycloakAuthClient(
            keycloak_url="http://keycloak.example.com",
            realm="test-realm",
            client_id="test-client",
            client_secret="test-secret"
        )
        
        access_token, refresh_token, expires_in = client.refresh_token(
            refresh_token="old-refresh-token"
        )
        
        assert access_token == "new-access-token"
        assert refresh_token == "new-refresh-token"
        assert expires_in == 300


class TestA2ASecurityManagerKeycloakIntegration:
    """Test Keycloak integration with A2ASecurityManager"""
    
    @patch.dict(os.environ, {
        "A2A_USE_KEYCLOAK": "true",
        "KEYCLOAK_URL": "http://keycloak.example.com",
        "KEYCLOAK_REALM": "test-realm",
        "KEYCLOAK_CLIENT_ID": "test-client",
        "A2A_REQUIRE_AUTH": "true"
    })
    @patch('a2a_security.KEYCLOAK_AVAILABLE', True)
    @patch('a2a_security.KeycloakJWTValidator')
    @patch('a2a_security.KeycloakRBACMapper')
    def test_keycloak_enabled(self, mock_mapper, mock_validator):
        """Test A2ASecurityManager with Keycloak enabled"""
        from a2a_security import A2ASecurityManager
        
        security = A2ASecurityManager(agent_id="test-agent")
        
        assert security.use_keycloak is True
        assert mock_validator.called
        assert mock_mapper.called
    
    @patch.dict(os.environ, {"A2A_USE_KEYCLOAK": "false"})
    def test_keycloak_disabled(self):
        """Test A2ASecurityManager with Keycloak disabled"""
        from a2a_security import A2ASecurityManager
        
        security = A2ASecurityManager(agent_id="test-agent")
        
        assert security.use_keycloak is False
        assert security.keycloak_validator is None


@pytest.mark.integration
class TestKeycloakEndToEnd:
    """Integration tests (require actual Keycloak server)"""
    
    @pytest.mark.skip(reason="Requires actual Keycloak server")
    def test_full_authentication_flow(self):
        """Test full authentication flow with real Keycloak"""
        # This test requires a running Keycloak instance
        # Uncomment and configure for integration testing
        
        client = KeycloakAuthClient(
            keycloak_url=os.getenv("KEYCLOAK_URL", "http://keycloak.ca-a2a.local:8080"),
            realm=os.getenv("KEYCLOAK_REALM", "ca-a2a"),
            client_id=os.getenv("KEYCLOAK_CLIENT_ID", "ca-a2a-agents"),
            client_secret=os.getenv("KEYCLOAK_CLIENT_SECRET")
        )
        
        # Authenticate
        access_token, refresh_token, expires_in = client.authenticate_password(
            username=os.getenv("TEST_USERNAME", "admin-user"),
            password=os.getenv("TEST_PASSWORD")
        )
        
        assert access_token is not None
        assert refresh_token is not None
        assert expires_in > 0
        
        # Verify token with validator
        validator = KeycloakJWTValidator(
            keycloak_url=os.getenv("KEYCLOAK_URL", "http://keycloak.ca-a2a.local:8080"),
            realm=os.getenv("KEYCLOAK_REALM", "ca-a2a"),
            client_id=os.getenv("KEYCLOAK_CLIENT_ID", "ca-a2a-agents")
        )
        
        principal, roles, claims = validator.verify_token(access_token)
        
        assert principal is not None
        assert len(roles) > 0
        
        # Refresh token
        new_access_token, new_refresh_token, new_expires_in = client.refresh_token(refresh_token)
        
        assert new_access_token is not None
        assert new_access_token != access_token


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

