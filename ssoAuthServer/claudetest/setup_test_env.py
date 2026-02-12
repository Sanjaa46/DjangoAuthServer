#!/usr/bin/env python
"""
Setup script for SSO test environment
Run: python setup_test_env.py
"""

import os
import sys
import django

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mysite.settings')
django.setup()

from ssoAuthServer.models import OAuthClient, AuthUser
from django.contrib.auth.hashers import make_password
from django.db import IntegrityError

def setup_test_client():
    """Register test OAuth client"""
    print("\n" + "="*60)
    print("Setting up Test OAuth Client")
    print("="*60)
    
    try:
        client = OAuthClient.objects.create(
            client_id="test-client-1",
            client_secret_hash=make_password("test-secret-1"),
            client_name="Test Frontend Application",
            redirect_uris={
                "redirect_uris": [
                    "http://localhost:8080",
                    "http://127.0.0.1:8080",
                    "http://localhost:8080/test-client.html",
                    "http://127.0.0.1:8080/test-client.html"
                ]
            },
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scope="openid profile",
            is_confidential=True
        )
        print(f"✓ Created OAuth client: {client.client_id}")
        print(f"  Client Secret: test-secret-1")
        print(f"  Redirect URIs: http://localhost:8080")
        
    except IntegrityError:
        print("⚠ OAuth client 'test-client-1' already exists")
        client = OAuthClient.objects.get(client_id="test-client-1")
        print(f"  Using existing client: {client.client_name}")

def setup_test_user():
    """Create test user account"""
    print("\n" + "="*60)
    print("Setting up Test User Account")
    print("="*60)
    
    test_phone = "+97699123456"
    test_password = "TestPassword123!"
    
    try:
        user = AuthUser.objects.create(
            phone=test_phone,
            password_hash=make_password(test_password),
            is_active=True
        )
        print(f"✓ Created test user")
        print(f"  Phone: {test_phone}")
        print(f"  Password: {test_password}")
        print(f"  User ID: {user.id}")
        
    except IntegrityError:
        print(f"⚠ User with phone '{test_phone}' already exists")
        user = AuthUser.objects.get(phone=test_phone)
        print(f"  User ID: {user.id}")
        print(f"  To reset password, use Django shell")

def display_summary():
    """Display setup summary"""
    print("\n" + "="*60)
    print("Setup Complete!")
    print("="*60)
    print("\n📋 Test Credentials:")
    print("   Phone: +97699123456")
    print("   Password: TestPassword123!")
    print("\n🔑 OAuth Client:")
    print("   Client ID: test-client-1")
    print("   Client Secret: test-secret-1")
    print("   Redirect URI: http://localhost:8080")
    print("\n🚀 Next Steps:")
    print("   1. Start Django server:")
    print("      python manage.py runserver 8000")
    print("   2. Start test client server:")
    print("      python3 serve_test_client.py")
    print("   3. Open browser:")
    print("      http://localhost:8080/test-client.html")
    print("\n📖 Full guide: TESTING_GUIDE.md")
    print("="*60 + "\n")

def check_prerequisites():
    """Check if required services are configured"""
    print("\n" + "="*60)
    print("Checking Prerequisites")
    print("="*60)
    
    # Check if keys exist
    from django.conf import settings
    keys_dir = settings.BASE_DIR / "ssoAuthServer" / "keys"
    
    if not (keys_dir / "private_key.pem").exists():
        print("❌ RSA keys not found!")
        print("   Run: python manage.py genkeys")
        return False
    else:
        print("✓ RSA keys exist")
    
    # Check database connection
    try:
        from django.db import connection
        connection.ensure_connection()
        print("✓ Database connection successful")
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        print("   Make sure MySQL is running and database 'sso_db' exists")
        return False
    
    # Check Redis connection
    try:
        from django.core.cache import cache
        cache.set('test_key', 'test_value', 1)
        if cache.get('test_key') == 'test_value':
            print("✓ Redis connection successful")
            cache.delete('test_key')
    except Exception as e:
        print(f"❌ Redis connection failed: {e}")
        print("   Make sure Redis is running (redis-server)")
        return False
    
    return True

def main():
    print("""
    ╔═══════════════════════════════════════════════════════╗
    ║        SSO Test Environment Setup                     ║
    ║                                                       ║
    ║  This script will create:                            ║
    ║  • Test OAuth client (test-client-1)                 ║
    ║  • Test user account (+97699123456)                  ║
    ╚═══════════════════════════════════════════════════════╝
    """)
    
    # Check prerequisites
    if not check_prerequisites():
        print("\n⚠ Please fix the issues above before continuing.\n")
        sys.exit(1)
    
    # Setup
    setup_test_client()
    setup_test_user()
    display_summary()

if __name__ == "__main__":
    main()