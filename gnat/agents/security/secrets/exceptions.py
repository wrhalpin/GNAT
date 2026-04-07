# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
class SecretError(Exception):
    pass


class SecretPolicyError(SecretError):
    pass


class SecretProviderError(SecretError):
    pass


class UnsupportedProviderAction(SecretProviderError):
    pass
