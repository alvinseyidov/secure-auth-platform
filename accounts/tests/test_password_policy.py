from django.test import TestCase

from accounts.security import validate_password_strength


class PasswordPolicyTests(TestCase):

    def test_weak_password_returns_errors(self):
        """Short and common passwords should fail validation."""
        errors = validate_password_strength('password')
        self.assertTrue(len(errors) > 0)

    def test_numeric_only_password_returns_errors(self):
        """Numeric-only passwords should fail validation."""
        errors = validate_password_strength('123456789012')
        self.assertTrue(len(errors) > 0)

    def test_short_password_returns_errors(self):
        """Passwords shorter than 12 chars should fail."""
        errors = validate_password_strength('Abc123!@#')
        self.assertTrue(len(errors) > 0)

    def test_strong_password_returns_no_errors(self):
        """Strong passwords should pass all validators."""
        errors = validate_password_strength('Xk9$mNp2@qLw')
        self.assertEqual(errors, [])

