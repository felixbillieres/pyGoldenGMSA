"""
Module for managing Group Managed Service Account (gMSA) accounts.
"""

import logging
import struct
from typing import Optional, List, Iterator
from .msds_managed_password_id import MsdsManagedPasswordId
from .ldap_utils import LdapUtils

logger = logging.getLogger(__name__)


def convert_sid_to_string(sid_bytes: bytes) -> str:
    """
    Converts a SID from bytes to its string representation.

    Args:
        sid_bytes: SID in bytes format

    Returns:
        SID in string format (e.g.: S-1-5-21-...)
    """
    if not sid_bytes or len(sid_bytes) < 8:
        return str(sid_bytes)
    
    try:
        # SID structure:
        # byte 0: Revision (always 1)
        # byte 1: Number of sub-authorities
        # bytes 2-7: Authority (6 bytes, big-endian)
        # bytes 8+: Sub-authorities (4 bytes each, little-endian)
        
        revision = sid_bytes[0]
        sub_auth_count = sid_bytes[1]
        
        # Authority (6 bytes big-endian, but we use 8 bytes with padding)
        authority = struct.unpack('>Q', b'\x00\x00' + sid_bytes[2:8])[0]
        
        # Build the SID
        sid = f'S-{revision}-{authority}'
        
        # Append sub-authorities
        for i in range(sub_auth_count):
            offset = 8 + (i * 4)
            if offset + 4 <= len(sid_bytes):
                sub_auth = struct.unpack('<I', sid_bytes[offset:offset + 4])[0]
                sid += f'-{sub_auth}'
        
        return sid
    except Exception as e:
        logger.warning(f"Error while converting SID: {e}")
        return str(sid_bytes)


class GmsaAccount:
    """
    Class representing a Group Managed Service Account (gMSA).
    """
    
    # Required LDAP attributes for gMSA
    GMSA_REQUIRED_LDAP_ATTRIBUTES = [
        "msDS-ManagedPasswordId",
        "sAMAccountName", 
        "objectSid",
        "distinguishedName"
    ]
    
    MSDS_MANAGED_PASSWORD_ID_ATTRIBUTE_NAME = "msDS-ManagedPasswordId"
    IS_GMSA_ACCOUNT_LDAP_FILTER = "(objectCategory=msDS-GroupManagedServiceAccount)"
    
    def __init__(self, sam_account_name: str, dn: str, sid: str, pwd_id: MsdsManagedPasswordId):
        """
        Initializes a GmsaAccount instance.

        Args:
            sam_account_name: SAM account name
            dn: Distinguished Name
            sid: Security Identifier (SID)
            pwd_id: Managed password identifier
        """
        self.distinguished_name = dn
        self.managed_password_id = pwd_id
        self.sid = sid
        self.sam_account_name = sam_account_name
    
    @staticmethod
    def get_gmsa_account_by_sid(domain_fqdn: str, sid: str) -> Optional['GmsaAccount']:
        """
        Returns gMSA account information by its SID.

        Args:
            domain_fqdn: FQDN of the domain to search
            sid: The SID of the gMSA

        Returns:
            GmsaAccount instance or None if not found
        """
        if not sid:
            raise ValueError("The sid parameter cannot be None")
        
        if not domain_fqdn:
            raise ValueError("The domain_fqdn parameter cannot be None")
        
        ldap_filter = f"(&{GmsaAccount.IS_GMSA_ACCOUNT_LDAP_FILTER}(objectsid={sid}))"
        results = LdapUtils.find_in_domain(domain_fqdn, ldap_filter, GmsaAccount.GMSA_REQUIRED_LDAP_ATTRIBUTES)
        
        if not results:
            return None
        
        return GmsaAccount._get_gmsa_from_search_result(results[0])
    
    @staticmethod
    def find_all_gmsa_accounts_in_domain(domain_fqdn: str) -> Iterator['GmsaAccount']:
        """
        Returns all gMSA accounts in the domain.

        Args:
            domain_fqdn: FQDN of the domain to search

        Yields:
            GmsaAccount instances
        """
        if not domain_fqdn:
            raise ValueError("The domain_fqdn parameter cannot be empty")
        
        results = LdapUtils.find_in_domain(
            domain_fqdn, 
            GmsaAccount.IS_GMSA_ACCOUNT_LDAP_FILTER, 
            GmsaAccount.GMSA_REQUIRED_LDAP_ATTRIBUTES
        )
        
        if not results:
            return
        
        for result in results:
            gmsa = None
            try:
                gmsa = GmsaAccount._get_gmsa_from_search_result(result)
            except Exception as ex:
                dn = result.get('distinguishedName', ['Unknown'])[0]
                logger.warning(f"{dn}: {ex}")
            
            if gmsa:
                yield gmsa
    
    @staticmethod
    def _get_gmsa_from_search_result(search_result: dict) -> 'GmsaAccount':
        """
        Creates a GmsaAccount instance from an LDAP search result.

        Args:
            search_result: LDAP search result

        Returns:
            GmsaAccount instance

        Raises:
            KeyError: If a required attribute is missing
        """
        if not search_result:
            raise ValueError("The search_result parameter cannot be None")
        
        # Verify that all required attributes are present
        for attr in GmsaAccount.GMSA_REQUIRED_LDAP_ATTRIBUTES:
            if attr not in search_result:
                raise KeyError(f"Attribute {attr} was not found")
        
        dn = search_result['distinguishedName'][0]
        if isinstance(dn, bytes):
            dn = dn.decode('utf-8')
            
        pwd_blob = search_result[GmsaAccount.MSDS_MANAGED_PASSWORD_ID_ATTRIBUTE_NAME][0]
        pwd_id = MsdsManagedPasswordId(pwd_blob)
        
        sid_bytes = search_result['objectSid'][0]
        sid = convert_sid_to_string(sid_bytes)
        
        sam_id = search_result['sAMAccountName'][0]
        if isinstance(sam_id, bytes):
            sam_id = sam_id.decode('utf-8')
        
        return GmsaAccount(sam_id, dn, sid, pwd_id)
    
    def to_string(self) -> str:
        """
        Returns a string representation of the GmsaAccount object.

        Returns:
            Formatted string containing gMSA information
        """
        import base64
        
        result = f"sAMAccountName:         {self.sam_account_name}\n"
        result += f"objectSid:              {self.sid}\n"
        result += f"distinguishedName:      {self.distinguished_name}\n"
        result += f"rootKeyGuid:            {self.managed_password_id.root_key_identifier}\n"
        result += f"domainName:             {self.managed_password_id.domain_name}\n"
        result += f"forestName:             {self.managed_password_id.forest_name}\n"
        result += f"L0 Index:               {self.managed_password_id.l0_index}\n"
        result += f"L1 Index:               {self.managed_password_id.l1_index}\n"
        result += f"L2 Index:               {self.managed_password_id.l2_index}\n"
        result += f"msDS-ManagedPasswordId: {base64.b64encode(self.managed_password_id.msds_managed_password_id_bytes).decode('utf-8')}\n"
        result += "----------------------------------------------\n"
        
        return result
    
    def __str__(self) -> str:
        """Returns the string representation of the object."""
        return self.to_string()
    
    def __repr__(self) -> str:
        """Returns the official representation of the object."""
        return f"GmsaAccount(sam_account_name='{self.sam_account_name}', sid='{self.sid}')"
