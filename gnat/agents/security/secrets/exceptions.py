class SecretError(Exception): pass
class SecretPolicyError(SecretError): pass
class SecretProviderError(SecretError): pass
class UnsupportedProviderAction(SecretProviderError): pass
