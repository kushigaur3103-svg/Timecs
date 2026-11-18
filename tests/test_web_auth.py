"""
Unit tests for direct bcrypt authentication helpers in app.py.
Verifies elimination of passlib, truncation safety at 72 bytes,
multi-byte Unicode handling, legacy hash backward compatibility,
and robust handling of corrupt/invalid hashes without exceptions.
"""

import bcrypt
import pytest
from app import hash_password, verify_password


def test_normal_password_hash_verify_roundtrip():
    """Verify standard password hashing and verification roundtrip."""
    plain = "Secur3_P@ssw0rd!_2026"
    hashed = hash_password(plain)
    
    assert isinstance(hashed, str)
    assert hashed.startswith("$2b$")
    assert verify_password(plain, hashed) is True
    assert verify_password("wrong_password_attempt", hashed) is False


def test_long_password_ascii_exceeding_72_bytes():
    """Verify password > 72 ASCII characters hashes and verifies cleanly without ValueError."""
    # Modern bcrypt >= 4.0 raises ValueError if secret > 72 bytes.
    # Our helper strictly truncates UTF-8 bytes to 72.
    long_plain = "A" * 120
    hashed = hash_password(long_plain)

    assert isinstance(hashed, str)
    assert hashed.startswith("$2b$")
    assert verify_password(long_plain, hashed) is True
    # First 72 characters should also match because of the 72-byte truncation contract
    assert verify_password("A" * 72, hashed) is True
    assert verify_password("B" * 120, hashed) is False


def test_multibyte_unicode_and_emoji_password():
    """Verify password with multi-byte characters and emoji (>72 UTF-8 bytes) hashes and verifies."""
    # In UTF-8, Devanagari characters take 3 bytes and emojis take 4 bytes
    unicode_plain = "पासवर्ड_सुरक्षा_गोपनीयता_🔒🔑🛡️_१२३४५६७८९०" * 3
    encoded_bytes = unicode_plain.encode("utf-8")
    assert len(encoded_bytes) > 72

    hashed = hash_password(unicode_plain)
    assert isinstance(hashed, str)
    assert hashed.startswith("$2b$")
    assert verify_password(unicode_plain, hashed) is True
    assert verify_password("गलत_पासवर्ड", hashed) is False


def test_legacy_passlib_hash_backward_compatibility():
    """Verify legacy $2b$ and $2a$ passlib-generated hashes verify seamlessly."""
    plain = "TimeCodeSecLegacy2024!"
    
    # Pre-generated 60-character bcrypt hash with $2b$ prefix (matching passlib output)
    legacy_2b_hash = "$2b$12$j56c9RouHRDfJ1NpBM3llOVr7RO5toZijbXjVjHGBhwAH1nKMino2"
    assert verify_password(plain, legacy_2b_hash) is True
    assert verify_password("wrong_password", legacy_2b_hash) is False

    # Pre-generated 60-character bcrypt hash with $2a$ prefix
    legacy_2a_hash = "$2a$12$IBDW0YMu46W2l8NqxG.MU..hUcaCH85as0XjLGHbhuEgpZvAZ/Zv2"
    assert verify_password(plain, legacy_2a_hash) is True
    assert verify_password("wrong_password", legacy_2a_hash) is False

    # Dynamic $2b$ hash generated at cost 12
    dynamic_salt = bcrypt.gensalt(rounds=12, prefix=b"2b")
    dynamic_legacy = bcrypt.hashpw(b"another_legacy_pw", dynamic_salt).decode("utf-8")
    assert verify_password("another_legacy_pw", dynamic_legacy) is True
    assert verify_password("different_pw", dynamic_legacy) is False


def test_invalid_and_corrupt_hash_returns_false():
    """Verify corrupt, malformed, or empty hashes return False instead of raising 500 exceptions."""
    assert verify_password("password123", "not_a_valid_bcrypt_hash") is False
    assert verify_password("password123", "$2b$12$corrupted_short") is False
    assert verify_password("password123", "$2b$invalid_salt_characters!@#$%^&*()") is False
    assert verify_password("password123", "") is False
    assert verify_password("password123", None) is False
    assert verify_password("", "$2b$12$j56c9RouHRDfJ1NpBM3llOVr7RO5toZijbXjVjHGBhwAH1nKMino2") is False
    assert verify_password(None, "$2b$12$j56c9RouHRDfJ1NpBM3llOVr7RO5toZijbXjVjHGBhwAH1nKMino2") is False
    assert verify_password("password123", 12345) is False
