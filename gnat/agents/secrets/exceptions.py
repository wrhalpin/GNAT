class SecretsError(Exception):
    """Base exception for secrets broker errors."""


class SecretNotFoundError(SecretsError):
    """Raised when a referenced secret does not exist."""


class SecretPolicyError(SecretsError):
    """Raised when a secret operation is blocked by policy."""


class SecretProviderError(SecretsError):
    """Raised when a provider backend fails."""
