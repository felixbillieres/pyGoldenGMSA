"""
Module for handling MSDS managed password identifiers.
"""

import struct
import uuid
from typing import Optional
from .ldap_utils import LdapUtils


def format_guid(guid_bytes: bytes) -> str:
    """
    Formats a GUID from bytes to its UUID string representation.

    Args:
        guid_bytes: GUID in bytes format (16 bytes)

    Returns:
        GUID in string format (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
    """
    if not guid_bytes or len(guid_bytes) != 16:
        return str(guid_bytes)
    
    try:
        # Convert the bytes to a standard UUID
        # Microsoft GUIDs use a mixed byte order (little-endian for the first 3 groups)
        guid_uuid = uuid.UUID(bytes_le=guid_bytes)
        return str(guid_uuid)
    except Exception:
        # Fallback: simple hex format
        return '-'.join([
            guid_bytes[0:4].hex(),
            guid_bytes[4:6].hex(),
            guid_bytes[6:8].hex(),
            guid_bytes[8:10].hex(),
            guid_bytes[10:16].hex()
        ])


class MsdsManagedPasswordId:
    """
    Class representing an MSDS managed password identifier.
    """
    
    def __init__(self, pwd_blob: bytes):
        """
        Initializes an MsdsManagedPasswordId instance from a binary blob.

        Args:
            pwd_blob: Binary data of the managed password blob
        """
        self.msds_managed_password_id_bytes = pwd_blob
        
        # Parse the binary blob
        self.version = struct.unpack('<I', pwd_blob[0:4])[0]
        self.reserved = struct.unpack('<I', pwd_blob[4:8])[0]
        self.is_public_key = struct.unpack('<I', pwd_blob[8:12])[0]
        self.l0_index = struct.unpack('<I', pwd_blob[12:16])[0]
        self.l1_index = struct.unpack('<I', pwd_blob[16:20])[0]
        self.l2_index = struct.unpack('<I', pwd_blob[20:24])[0]
        
        # GUID (16 bytes)
        self.root_key_identifier = format_guid(pwd_blob[24:40])
        
        self.cb_unknown = struct.unpack('<I', pwd_blob[40:44])[0]
        self.cb_domain_name = struct.unpack('<I', pwd_blob[44:48])[0]
        self.cb_forest_name = struct.unpack('<I', pwd_blob[48:52])[0]
        
        # Read the unknown data
        if self.cb_unknown > 0:
            self.unknown = pwd_blob[52:52+self.cb_unknown]
        else:
            self.unknown = None
        
        # Read the domain name
        domain_start = 52 + self.cb_unknown
        self.domain_name = pwd_blob[domain_start:domain_start+self.cb_domain_name].decode('utf-16le')
        
        # Read the forest name
        forest_start = domain_start + self.cb_domain_name
        self.forest_name = pwd_blob[forest_start:forest_start+self.cb_forest_name].decode('utf-16le')
    
    @staticmethod
    def get_managed_password_id_by_sid(domain_name: str, sid: str) -> Optional['MsdsManagedPasswordId']:
        """
        Retrieves the managed password identifier by SID.

        Args:
            domain_name: Domain name
            sid: SID of the object

        Returns:
            MsdsManagedPasswordId instance or None if not found
        """
        import logging
        logger = logging.getLogger(__name__)
        
        # Try different variants of the attribute (case-insensitive)
        attributes_variants = [
            "msds-ManagedPasswordID",
            "msDS-ManagedPasswordID",
            "MSDS-ManagedPasswordID",
            "msds-ManagedPasswordId"
        ]
        
        ldap_filter = f"(objectSID={sid})"
        
        logger.debug(f"Searching pwd_id for SID: {sid}, domain: {domain_name}")
        logger.debug(f"LDAP filter: {ldap_filter}")
        
        results = LdapUtils.find_in_domain(domain_name, ldap_filter, attributes_variants)
        
        if not results:
            logger.warning(f"No results found for SID {sid}")
            return None
        
        logger.debug(f"Results found: {len(results)}")
        logger.debug(f"Available attributes in result: {list(results[0].keys()) if results else 'None'}")
        
        # Search for the attribute with different casings
        pwd_id_blob = None
        for attr_name in attributes_variants:
            if attr_name in results[0] and results[0][attr_name]:
                pwd_id_blob = results[0][attr_name][0]
                logger.debug(f"Found with attribute: {attr_name}")
                break
        
        # If still not found, search all keys (case-insensitive)
        if not pwd_id_blob:
            for key in results[0].keys():
                if key.lower() == "msds-managedpasswordid":
                    pwd_id_blob = results[0][key][0]
                    logger.debug(f"Found with key (case-insensitive): {key}")
                    break
        
        if not pwd_id_blob:
            logger.warning(f"Attribute msds-ManagedPasswordID not found in results")
            return None
        
        return MsdsManagedPasswordId(pwd_id_blob)
    
    def to_string(self) -> str:
        """
        Returns a string representation of the object.

        Returns:
            Formatted string containing the information
        """
        import base64
        
        result = f"Version: {self.version}\n"
        result += f"Reserved: {self.reserved}\n"
        result += f"Is Public Key: {self.is_public_key}\n"
        result += f"L0 Index: {self.l0_index}\n"
        result += f"L1 Index: {self.l1_index}\n"
        result += f"L2 Index: {self.l2_index}\n"
        result += f"Root Key Identifier: {self.root_key_identifier}\n"
        result += f"Domain Name: {self.domain_name}\n"
        result += f"Forest Name: {self.forest_name}\n"
        result += f"Base64 Blob: {base64.b64encode(self.msds_managed_password_id_bytes).decode('utf-8')}\n"
        
        return result
    
    def __str__(self) -> str:
        """Returns the string representation of the object."""
        return self.to_string()

    def __repr__(self) -> str:
        """Returns the official representation of the object."""
        return f"MsdsManagedPasswordId(root_key_id='{self.root_key_identifier}', domain='{self.domain_name}')"
