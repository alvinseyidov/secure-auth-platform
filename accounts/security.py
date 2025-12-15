from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError


def validate_password_strength(password: str, user=None) -> list[str]:
    """
    Validate password against configured validators.
    Returns list of human-readable error messages, empty if valid.
    """
    try:
        validate_password(password, user=user)
        return []
    except ValidationError as e:
        return list(e.messages)

