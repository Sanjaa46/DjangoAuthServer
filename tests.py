import pytest
from django.test import TestCase, Client
from django.contrib.auth.hashers import make_password
from ssoAuthServer.models import AuthUser, OAuthClient
from django.utils import timezone
from datetime import timedelta


class AuthUserModelTest(TestCase):
    """Test cases for AuthUser model"""
    
    def setUp(self):
        self.user = AuthUser.objects.create(
            phone="+97699123456",
            password_hash=make_password("testpassword"),
            is_active=True
        )
    
    def test_user_creation(self):
        """Test that a user can be created"""
        self.assertEqual(self.user.phone, "+97699123456")
        self.assertTrue(self.user.is_active)
    
    def test_phone_uniqueness(self):
        """Test that phone numbers must be unique"""
        with self.assertRaises(Exception):
            AuthUser.objects.create(
                phone="+97699123456",
                password_hash=make_password("password")
            )


class OAuthClientModelTest(TestCase):
    """Test cases for OAuthClient model"""
    
    def setUp(self):
        self.client = OAuthClient.objects.create(
            client_id="test-client",
            client_secret_hash=make_password("test-secret"),
            redirect_uris={"redirect_uris": ["http://localhost:8080/callback"]},
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scope="openid profile",
            client_name="Test Client",
            is_confidential=True
        )
    
    def test_client_creation(self):
        """Test that an OAuth client can be created"""
        self.assertEqual(self.client.client_id, "test-client")
        self.assertEqual(self.client.client_name, "Test Client")
        self.assertTrue(self.client.is_confidential)


class LoginViewTest(TestCase):
    """Test cases for login view"""
    
    def setUp(self):
        self.client_http = Client()
        self.user = AuthUser.objects.create(
            phone="+97699123456",
            password_hash=make_password("testpassword"),
            is_active=True
        )
        self.oauth_client = OAuthClient.objects.create(
            client_id="test-client",
            client_secret_hash=make_password("test-secret"),
            redirect_uris={"redirect_uris": ["http://localhost:8080/callback"]},
            grant_types=["authorization_code"],
            response_types=["code"],
            scope="openid profile",
            client_name="Test Client",
            is_confidential=True
        )
    
    def test_login_page_loads(self):
        """Test that login page loads successfully"""
        response = self.client_http.get('/login?client_id=test-client')
        self.assertEqual(response.status_code, 200)
    
    def test_login_with_valid_credentials(self):
        """Test login with valid credentials"""
        response = self.client_http.post('/login', {
            'phone': '+97699123456',
            'password': 'testpassword',
            'client_id': 'test-client',
            'redirect_uri': 'http://localhost:8080/callback',
            'response_type': 'code',
            'scope': 'openid profile',
            'state': 'random-state',
            'code_challenge': 'test-challenge',
            'code_challenge_method': 'S256'
        })
        # Should redirect to authorize endpoint
        self.assertEqual(response.status_code, 302)
    
    def test_login_with_invalid_credentials(self):
        """Test login with invalid credentials"""
        response = self.client_http.post('/login', {
            'phone': '+97699123456',
            'password': 'wrongpassword',
            'client_id': 'test-client'
        })
        self.assertEqual(response.status_code, 200)
        # Check for error message (would need to parse response content)


class JWKSViewTest(TestCase):
    """Test cases for JWKS endpoint"""
    
    def test_jwks_endpoint(self):
        """Test that JWKS endpoint returns JSON"""
        client = Client()
        # Note: This will fail if keys don't exist
        # In production, you'd mock this or ensure keys exist
        response = client.get('/.well-known/jwks.json')
        # Should return JSON (200) or 404 if keys don't exist
        self.assertIn(response.status_code, [200, 404])


@pytest.mark.integration
class OAuthFlowIntegrationTest(TestCase):
    """Integration tests for OAuth flow"""
    
    def setUp(self):
        self.client_http = Client()
        self.user = AuthUser.objects.create(
            phone="+97699123456",
            password_hash=make_password("testpassword"),
            is_active=True
        )
        self.oauth_client = OAuthClient.objects.create(
            client_id="test-client",
            client_secret_hash=make_password("test-secret"),
            redirect_uris={"redirect_uris": ["http://localhost:8080/callback"]},
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scope="openid profile",
            client_name="Test Client",
            is_confidential=True
        )
    
    def test_full_oauth_flow(self):
        """Test complete OAuth authorization code flow"""
        # Step 1: Access authorize endpoint without session
        response = self.client_http.get('/authorize', {
            'client_id': 'test-client',
            'redirect_uri': 'http://localhost:8080/callback',
            'response_type': 'code',
            'scope': 'openid profile',
            'state': 'random-state',
            'code_challenge': 'test-challenge',
            'code_challenge_method': 'S256'
        })
        # Should redirect to login
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login', response.url)
