"""
Constants for GoldenGMSA Python.
Centralized module for all project constants.
"""

# KDS key cycle duration in nanoseconds (6 minutes = 360 seconds)
KEY_CYCLE_DURATION = 360000000000

# Default size of KDS root key data (in bytes)
KDS_ROOT_KEY_DATA_SIZE_DEFAULT = 64

# Default GMSA security descriptor
DEFAULT_GMSA_SECURITY_DESCRIPTOR = bytes([
    0x01, 0x00, 0x04, 0x80, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x14, 0x00, 0x00, 0x00, 0x02, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0x00, 0x9F, 0x01, 0x12, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x09,
    0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00
])

# Default LDAP filters
GMSA_LDAP_FILTER = "(objectCategory=msDS-GroupManagedServiceAccount)"
KDS_ROOT_KEY_LDAP_FILTER = "(objectClass=msKds-ProvRootKey)"

# Required LDAP attributes for gMSAs
GMSA_REQUIRED_ATTRIBUTES = [
    "msds-ManagedPasswordID",
    "samAccountName",
    "objectSid",
    "distinguishedName"
]

# Required LDAP attributes for KDS root keys
KDS_ROOT_KEY_REQUIRED_ATTRIBUTES = [
    "msKds-SecretAgreementParam",
    "msKds-RootKeyData",
    "msKds-KDFParam",
    "msKds-KDFAlgorithmID",
    "msKds-CreateTime",
    "msKds-UseStartTime",
    "msKds-Version",
    "msKds-DomainID",
    "cn",
    "msKds-PrivateKeyLength",
    "msKds-PublicKeyLength",
    "msKds-SecretAgreementAlgorithmID"
]

# LDAP configuration
LDAP_PORT = 389
LDAPS_PORT = 636
LDAP_PAGE_SIZE = 100
LDAP_TIMEOUT = 10
