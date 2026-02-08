"""
GoldenGMSA Python Package

Python equivalent of the original GoldenGMSA tool written in C#.
Tool for exploiting Group Managed Service Accounts (gMSA) in Active Directory.

Based on research by Yuval Gordon (@YuG0rd).
"""

__version__ = "1.0.0"
__author__ = "GoldenGMSA Python Team"
__description__ = "Tool for exploiting Group Managed Service Accounts (gMSA)"

# Main imports
from .gmsa_account import GmsaAccount
from .root_key import RootKey
from .gmsa_password import GmsaPassword
from .msds_managed_password_id import MsdsManagedPasswordId
from .ldap_utils import LdapUtils, LdapConnection
from .kds_utils import KdsUtils
from . import config

__all__ = [
    'GmsaAccount',
    'RootKey', 
    'GmsaPassword',
    'MsdsManagedPasswordId',
    'LdapUtils',
    'LdapConnection',
    'KdsUtils',
    'config'
]