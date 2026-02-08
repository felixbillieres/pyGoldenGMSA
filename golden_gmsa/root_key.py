"""
Module for managing KDS (Key Distribution Service) root keys.
"""

import logging
import struct
from typing import List, Iterator, Optional
from .ldap_utils import LdapUtils
from .config import KDS_ROOT_KEY_REQUIRED_ATTRIBUTES, KDS_ROOT_KEY_DATA_SIZE_DEFAULT

logger = logging.getLogger(__name__)


class RootKey:
    """
    Class representing a KDS (Key Distribution Service) root key.
    """
    
    def __init__(self, search_result: dict = None, file_path: str = None, root_key_bytes: bytes = None):
        """
        Initialize a RootKey instance.

        Args:
            search_result: LDAP search result
            file_path: Path to a root key file
            root_key_bytes: Binary data of the root key
        """
        if search_result is not None:
            self._init_from_search_result(search_result)
        elif file_path is not None:
            self._init_from_file(file_path)
        elif root_key_bytes is not None:
            if not root_key_bytes:
                raise ValueError("root_key_bytes cannot be an empty byte string")
            self._init_from_bytes(root_key_bytes)
        else:
            raise ValueError("A parameter must be provided (search_result, file_path, or root_key_bytes)")
    
    def _init_from_search_result(self, search_result: dict):
        """Initialize from an LDAP search result."""
        self.ms_kds_version = int(search_result['msKds-Version'][0])
        self.cn = search_result['cn'][0].decode('utf-8')
        self.prob_reserved = 0
        self.ms_kds_version2 = int(search_result['msKds-Version'][0])
        self.prob_reserved2 = 0
        self.ms_kds_kdf_algorithm_id = search_result['msKds-KDFAlgorithmID'][0].decode('utf-8')
        self.ms_kds_kdf_param = search_result['msKds-KDFParam'][0]
        self.kdf_param_size = len(self.ms_kds_kdf_param)
        self.prob_reserved3 = 0
        self.kds_secret_agreement_algorithm_id = search_result['msKds-SecretAgreementAlgorithmID'][0].decode('utf-8')
        self.kds_secret_agreement_param = search_result['msKds-SecretAgreementParam'][0]
        self.secret_algorithm_param_size = len(self.kds_secret_agreement_param)
        self.private_key_length = int(search_result['msKds-PrivateKeyLength'][0])
        self.public_key_length = int(search_result['msKds-PublicKeyLength'][0])
        self.prob_reserved4 = 0
        self.prob_reserved5 = 0
        self.prob_reserved6 = 0
        self.flag = 1
        self.flag2 = 1
        self.kds_domain_id = search_result['msKds-DomainID'][0].decode('utf-8')
        self.kds_create_time = int(search_result['msKds-CreateTime'][0])
        self.kds_use_start_time = int(search_result['msKds-UseStartTime'][0])
        self.prob_reserved7 = 0
        self.kds_root_key_data_size = KDS_ROOT_KEY_DATA_SIZE_DEFAULT
        self.kds_root_key_data = search_result['msKds-RootKeyData'][0]
    
    def _init_from_file(self, file_path: str):
        """Initialize from a file."""
        import os
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        if len(lines) < 12:
            raise ValueError("Invalid root key file")
        
        self.ms_kds_version = int(lines[0].strip())
        self.cn = lines[1].strip()
        self.prob_reserved = 0
        self.ms_kds_version2 = int(lines[0].strip())
        self.prob_reserved2 = 0
        self.ms_kds_kdf_algorithm_id = lines[2].strip()
        
        import base64
        self.ms_kds_kdf_param = base64.b64decode(lines[3].strip())
        self.kdf_param_size = len(self.ms_kds_kdf_param)
        self.prob_reserved3 = 0
        self.kds_secret_agreement_algorithm_id = lines[4].strip()
        self.kds_secret_agreement_param = base64.b64decode(lines[5].strip())
        self.secret_algorithm_param_size = len(self.kds_secret_agreement_param)
        self.private_key_length = int(lines[6].strip())
        self.public_key_length = int(lines[7].strip())
        self.prob_reserved4 = 0
        self.prob_reserved5 = 0
        self.prob_reserved6 = 0
        self.flag = 1
        self.flag2 = 1
        self.kds_domain_id = lines[8].strip()
        self.kds_create_time = int(lines[9].strip())
        self.kds_use_start_time = int(lines[10].strip())
        self.prob_reserved7 = 0
        self.kds_root_key_data_size = KDS_ROOT_KEY_DATA_SIZE_DEFAULT
        self.kds_root_key_data = base64.b64decode(lines[11].strip())
    
    def _init_from_bytes(self, root_key_bytes: bytes):
        """Initialize from binary data."""
        track_size = 32
        
        # Read the first fields
        self.ms_kds_version = struct.unpack('<I', root_key_bytes[0:4])[0]
        # Extract the GUID (16 bytes) after ms_kds_version
        cn_bytes = root_key_bytes[4:20]  # GUID is 16 bytes
        self.cn = '-'.join([cn_bytes[:4][::-1].hex(), cn_bytes[4:6][::-1].hex(), cn_bytes[6:8][::-1].hex(), cn_bytes[8:10].hex(), cn_bytes[10:].hex()])  # GUID as bytes
        self.prob_reserved = struct.unpack('<I', root_key_bytes[20:24])[0]
        self.ms_kds_version2 = struct.unpack('<I', root_key_bytes[24:28])[0]
        self.prob_reserved2 = struct.unpack('<I', root_key_bytes[28:32])[0]
        
        # Read msKdsKDFAlgorithmID
        ms_kdf_algorithm_id_size = struct.unpack('<I', root_key_bytes[track_size:track_size+4])[0]
        self.ms_kds_kdf_algorithm_id = root_key_bytes[track_size+4:track_size+4+ms_kdf_algorithm_id_size].decode('utf-16le')
        track_size += ms_kdf_algorithm_id_size + 4
        
        # Read KDFParamSize
        self.kdf_param_size = struct.unpack('<I', root_key_bytes[track_size:track_size+4])[0]
        if self.kdf_param_size > 0:
            self.ms_kds_kdf_param = root_key_bytes[track_size+4:track_size+4+self.kdf_param_size]
            track_size += self.kdf_param_size + 4
        else:
            self.ms_kds_kdf_param = None
            track_size += 4
        
        self.prob_reserved3 = struct.unpack('<I', root_key_bytes[track_size:track_size+4])[0]
        track_size += 4
        
        # Read kdsSecretAgreementAlgorithmID
        kds_secret_agreement_algorithm_id_size = struct.unpack('<I', root_key_bytes[track_size:track_size+4])[0]
        self.kds_secret_agreement_algorithm_id = root_key_bytes[track_size+4:track_size+4+kds_secret_agreement_algorithm_id_size].decode('utf-16le')
        track_size += kds_secret_agreement_algorithm_id_size + 4
        
        self.secret_algorithm_param_size = struct.unpack('<I', root_key_bytes[track_size:track_size+4])[0]
        if self.secret_algorithm_param_size > 0:
            self.kds_secret_agreement_param = root_key_bytes[track_size+4:track_size+4+self.secret_algorithm_param_size]
            track_size += self.secret_algorithm_param_size + 4
        else:
            self.kds_secret_agreement_param = None
            track_size += 4
        
        # Read the other fields
        self.private_key_length = struct.unpack('<I', root_key_bytes[track_size:track_size+4])[0]
        self.public_key_length = struct.unpack('<I', root_key_bytes[track_size+4:track_size+8])[0]
        self.prob_reserved4 = struct.unpack('<I', root_key_bytes[track_size+8:track_size+12])[0]
        self.prob_reserved5 = struct.unpack('<I', root_key_bytes[track_size+12:track_size+16])[0]
        self.prob_reserved6 = struct.unpack('<I', root_key_bytes[track_size+16:track_size+20])[0]
        self.flag = struct.unpack('<Q', root_key_bytes[track_size+20:track_size+28])[0]
        self.flag2 = struct.unpack('<Q', root_key_bytes[track_size+28:track_size+36])[0]
        track_size += 36
        
        # Read kdsDomainID
        kds_domain_id_size = struct.unpack('<I', root_key_bytes[track_size:track_size+4])[0]
        self.kds_domain_id = root_key_bytes[track_size+4:track_size+4+kds_domain_id_size].decode('utf-16le')
        track_size += kds_domain_id_size + 4
        
        # Read the timestamps
        self.kds_create_time = struct.unpack('<Q', root_key_bytes[track_size:track_size+8])[0]
        self.kds_use_start_time = struct.unpack('<Q', root_key_bytes[track_size+8:track_size+16])[0]
        self.prob_reserved7 = struct.unpack('<Q', root_key_bytes[track_size+16:track_size+24])[0]
        self.kds_root_key_data_size = struct.unpack('<Q', root_key_bytes[track_size+24:track_size+32])[0]
        
        if self.kds_root_key_data_size > 0:
            self.kds_root_key_data = root_key_bytes[track_size+32:track_size+32+self.kds_root_key_data_size]
        else:
            self.kds_root_key_data = None
    
    @staticmethod
    def get_root_key_by_guid(forest_name: str, root_key_id: str) -> Optional['RootKey']:
        """
        Retrieve a root key by its GUID.

        Args:
            forest_name: Name of the forest
            root_key_id: GUID of the root key

        Returns:
            RootKey instance or None if not found
        """
        try:
            config_naming_context = LdapUtils._get_config_naming_context(forest_name)
            ldap_filter = f"(&(objectClass=msKds-ProvRootKey)(cn={root_key_id}))"
            
            results = LdapUtils.find_in_config_partition(forest_name, ldap_filter, KDS_ROOT_KEY_REQUIRED_ATTRIBUTES)
            
            if not results:
                return None
            
            return RootKey(search_result=results[0])
            
        except Exception as ex:
            logger.error(f"Error retrieving root key {root_key_id}: {ex}")
            return None
    
    @staticmethod
    def get_all_root_keys(forest_name: str) -> Iterator['RootKey']:
        """
        Retrieve all root keys from the forest.

        Args:
            forest_name: Name of the forest

        Yields:
            RootKey instances
        """
        try:
            config_naming_context = LdapUtils._get_config_naming_context(forest_name)
            ldap_filter = "(objectClass=msKds-ProvRootKey)"
            
            results = LdapUtils.find_in_config_partition(forest_name, ldap_filter, KDS_ROOT_KEY_REQUIRED_ATTRIBUTES)

            if not results:
                return
            
            for result in results:
                root_key = None
                try:
                    root_key = RootKey(search_result=result)
                except Exception as ex:
                    dn = result.get('distinguishedName', [b'Unknown'])[0]
                    if isinstance(dn, bytes):
                        dn = dn.decode('utf-8', errors='ignore')
                    logger.warning(f"{dn}: {ex}")
                
                if root_key:
                    yield root_key
                    
        except Exception as ex:
            logger.error(f"Error retrieving root keys: {ex}")
            return
    
    def serialize(self) -> bytes:
        """
        Serialize the root key to binary data.

        Returns:
            Binary data of the root key
        """
        track_size = 36
        
        # Calculate the total size
        total_size = (124 + 
                     len(self.ms_kds_kdf_algorithm_id.encode('utf-16le')) + 
                     (len(self.ms_kds_kdf_param) if self.ms_kds_kdf_param else 0) + 
                     (len(self.kds_secret_agreement_param) if self.kds_secret_agreement_param else 0) +
                     len(self.kds_secret_agreement_algorithm_id.encode('utf-16le')) + 
                     len(self.kds_domain_id.encode('utf-16le')) + 
                     (len(self.kds_root_key_data) if self.kds_root_key_data else 0))
        
        root_key_bytes = bytearray(total_size)
        
        # Write the first fields
        struct.pack_into('<I', root_key_bytes, 0, self.ms_kds_version)
        
        # Note: Simplified GUID conversion
        cn_bytes = bytes.fromhex(self.cn.replace('-', ''))
        struct.pack_into('<IHH', root_key_bytes, 4, int.from_bytes(cn_bytes[:4]), int.from_bytes(cn_bytes[4:6]), int.from_bytes(cn_bytes[6:8]))
        struct.pack_into('>Q', root_key_bytes, 12, int.from_bytes(cn_bytes[8:]))

        struct.pack_into('<I', root_key_bytes, 20, self.prob_reserved)
        struct.pack_into('<I', root_key_bytes, 24, self.ms_kds_version2)
        struct.pack_into('<I', root_key_bytes, 28, self.prob_reserved2)
        
        # Write msKdsKDFAlgorithmID
        ms_kds_kdf_algorithm_id_bytes = self.ms_kds_kdf_algorithm_id.encode('utf-16le')
        ms_kds_kdf_algorithm_id_length = len(ms_kds_kdf_algorithm_id_bytes)

        struct.pack_into('<I', root_key_bytes, 32, ms_kds_kdf_algorithm_id_length)
        struct.pack_into(f'<{ms_kds_kdf_algorithm_id_length}s', root_key_bytes, track_size, ms_kds_kdf_algorithm_id_bytes)

        track_size += ms_kds_kdf_algorithm_id_length

        # Write msKdsKDFParam
        struct.pack_into('<I', root_key_bytes, track_size, self.kdf_param_size)
        track_size += 4
        root_key_bytes[track_size:track_size+len(self.ms_kds_kdf_param)] = self.ms_kds_kdf_param
        track_size += len(self.ms_kds_kdf_param)

        struct.pack_into('<I', root_key_bytes, track_size, self.prob_reserved3)
        track_size += 4

        # Write msKdsKDFAgreementAlgorithmID
        kds_secret_agreement_algorithm_id_bytes = self.ms_kds_kdf_algorithm_id.encode('utf-16le')
        kds_secret_agreement_algorithm_id_length = len(kds_secret_agreement_algorithm_id_bytes)

        struct.pack_into('<I', root_key_bytes, track_size, kds_secret_agreement_algorithm_id_length)
        track_size += 4
        struct.pack_into(f'<{kds_secret_agreement_algorithm_id_length}s', root_key_bytes, track_size, kds_secret_agreement_algorithm_id_bytes)
        track_size += kds_secret_agreement_algorithm_id_length

        struct.pack_into('<I', root_key_bytes, track_size, self.secret_algorithm_param_size)
        track_size += 4

        root_key_bytes[track_size:track_size+self.secret_algorithm_param_size] = self.kds_secret_agreement_param
        track_size += self.secret_algorithm_param_size

        struct.pack_into('<I', root_key_bytes, track_size, self.private_key_length)
        struct.pack_into('<I', root_key_bytes, track_size + 4, self.public_key_length)
        struct.pack_into('<I', root_key_bytes, track_size + 8, self.prob_reserved4)
        struct.pack_into('<I', root_key_bytes, track_size + 12, self.prob_reserved5)
        struct.pack_into('<I', root_key_bytes, track_size + 16, self.prob_reserved6)
        struct.pack_into('<Q', root_key_bytes, track_size + 20, self.flag)
        struct.pack_into('<Q', root_key_bytes, track_size + 28, self.flag2)
        track_size += 36

        # Write KdsDomainID
        kds_domain_id_bytes = self.kds_domain_id.encode('utf-16le')
        kds_domain_id_length = len(kds_domain_id_bytes)

        struct.pack_into('<I', root_key_bytes, track_size, kds_domain_id_length)
        track_size += 4
        struct.pack_into(f'<{kds_domain_id_length}s', root_key_bytes, track_size, kds_domain_id_bytes)
        track_size += kds_domain_id_length

        struct.pack_into('<Q', root_key_bytes, track_size, self.kds_create_time)
        struct.pack_into('<Q', root_key_bytes, track_size + 8, self.kds_use_start_time)
        struct.pack_into('<Q', root_key_bytes, track_size + 16, self.prob_reserved7)
        struct.pack_into('<Q', root_key_bytes, track_size + 24, self.kds_root_key_data_size)
        root_key_bytes[track_size+32:track_size+32+self.kds_root_key_data_size] = self.kds_root_key_data


        return bytes(root_key_bytes)
    
    def to_base64_string(self) -> str:
        """
        Return the Base64 representation of the root key.

        Returns:
            Base64 string
        """
        import base64
        return base64.b64encode(self.serialize()).decode('utf-8')
    
    def to_string(self) -> str:
        """
        Return a string representation of the root key.

        Returns:
            Formatted string
        """
        result = f"Guid:\t\t{self.cn}\n"
        result += f"Base64 blob:\t{self.to_base64_string()}\n"
        result += "----------------------------------------------\n"
        return result
    
    def __str__(self) -> str:
        """Return the string representation of the object."""
        return self.to_string()
    
    def __repr__(self) -> str:
        """Return the official representation of the object."""
        return f"RootKey(guid='{self.cn}', version={self.ms_kds_version})"
