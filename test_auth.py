#!/usr/bin/env python3
"""
Test script for NFCGate server authentication system.

This script tests the authentication helper functions and configuration logic.
"""

import os
import sys
import hmac
import hashlib
import uuid
import datetime

# Add parent directory to path to import server modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import authentication functions from server
from server import verify_hmac, create_session, is_session_valid


def test_verify_hmac():
    """Test HMAC verification function."""
    print("Testing HMAC verification...")
    
    secret = "test_secret_123"
    nonce = "random_nonce_abc"
    
    # Generate correct HMAC
    correct_hmac = hmac.new(
        secret.encode('utf-8'),
        nonce.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    # Test correct HMAC
    assert verify_hmac(secret, nonce, correct_hmac), "Valid HMAC should pass"
    print("  ✓ Valid HMAC verification passed")
    
    # Test incorrect HMAC
    wrong_hmac = "0" * 64
    assert not verify_hmac(secret, nonce, wrong_hmac), "Invalid HMAC should fail"
    print("  ✓ Invalid HMAC verification failed (as expected)")
    
    # Test empty secret
    assert not verify_hmac("", nonce, correct_hmac), "Empty secret should fail"
    print("  ✓ Empty secret verification failed (as expected)")
    
    print("✓ All HMAC tests passed\n")


def test_create_session():
    """Test session creation."""
    print("Testing session creation...")
    
    client_ip = "192.168.1.100"
    session_id, session_data = create_session(client_ip)
    
    assert isinstance(session_id, str), "Session ID should be a string"
    assert len(session_id) == 32, "Session ID should be 32 hex chars (UUID4)"
    print(f"  ✓ Session ID created: {session_id[:8]}...")
    
    assert session_data["client_ip"] == client_ip, "Client IP should match"
    assert isinstance(session_data["created"], datetime.datetime), "Created should be datetime"
    assert isinstance(session_data["expires"], datetime.datetime), "Expires should be datetime"
    assert session_data["expires"] > session_data["created"], "Expiry should be after creation"
    print(f"  ✓ Session data valid")
    print(f"    - Client IP: {session_data['client_ip']}")
    print(f"    - Created: {session_data['created']}")
    print(f"    - Expires: {session_data['expires']}")
    
    print("✓ Session creation tests passed\n")


def test_session_validation():
    """Test session validation logic."""
    print("Testing session validation...")
    
    client_ip = "192.168.1.100"
    sessions = {}
    
    # Create a valid session
    session_id, session_data = create_session(client_ip)
    sessions[session_id] = session_data
    
    # Test valid session
    assert is_session_valid(sessions, session_id, client_ip), "Valid session should pass"
    print("  ✓ Valid session check passed")
    
    # Test non-existent session
    fake_id = uuid.uuid4().hex
    assert not is_session_valid(sessions, fake_id, client_ip), "Non-existent session should fail"
    print("  ✓ Non-existent session check failed (as expected)")
    
    # Test wrong IP
    assert not is_session_valid(sessions, session_id, "192.168.1.200"), "Wrong IP should fail"
    print("  ✓ Wrong IP check failed (as expected)")
    
    # Test expired session
    sessions[session_id]["expires"] = datetime.datetime.now() - datetime.timedelta(seconds=1)
    assert not is_session_valid(sessions, session_id, client_ip), "Expired session should fail"
    print("  ✓ Expired session check failed (as expected)")
    
    print("✓ Session validation tests passed\n")


def test_configuration():
    """Test configuration loading."""
    print("Testing configuration...")
    
    # Note: This doesn't actually modify the running server, just checks env var reading
    test_secret = os.getenv("NFCGATE_SECRET", "")
    if test_secret:
        print(f"  ✓ NFCGATE_SECRET is set (length: {len(test_secret)} chars)")
    else:
        print("  ℹ NFCGATE_SECRET is not set (authentication will be disabled)")
    
    auth_enabled = os.getenv("ENABLE_AUTHENTICATION", "false").lower() == "true"
    print(f"  ℹ ENABLE_AUTHENTICATION: {auth_enabled}")
    
    tls_enabled = os.getenv("ENABLE_TLS", "false").lower() == "true"
    print(f"  ℹ ENABLE_TLS: {tls_enabled}")
    
    print("✓ Configuration test complete\n")


def main():
    """Run all tests."""
    print("=" * 60)
    print("NFCGate Server Authentication System Tests")
    print("=" * 60 + "\n")
    
    try:
        test_verify_hmac()
        test_create_session()
        test_session_validation()
        test_configuration()
        
        print("=" * 60)
        print("✓ All tests passed successfully!")
        print("=" * 60)
        return 0
        
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        return 1
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
