"""
Module for managing group key envelopes.
"""

import struct
from typing import Optional


class GroupKeyEnvelope:
    """
    Class representing a group key envelope.
    """
    
    def __init__(self):
        """Initialize an empty GroupKeyEnvelope instance."""
        self.version = 0
        self.reserved = 0
        self.is_public_key = 0
        self.l0_index = 0
        self.l1_index = 0
        self.l2_index = 0
        self.root_key_identifier = ""
        self.cb_kdf_algorithm = 0
        self.cb_kdf_parameters = 0
        self.cb_secret_agreement_algorithm = 0
        self.cb_secret_agreement_parameters = 0
        self.private_key_length = 0
        self.public_key_length = 0
        self.cb_l1_key = 0
        self.cb_l2_key = 0
        self.cb_domain_name = 0
        self.cb_forest_name = 0
        self.kdf_algorithm = ""
        self.kdf_parameters = b""
        self.secret_agreement_algorithm = ""
        self.secret_agreement_parameters = b""
        self.domain_name = ""
        self.forest_name = ""
        self.l1_key = None  # 64 bytes
        self.l2_key = None  # 64 bytes
    
    def __init__(self, gke_bytes: bytes = None):
        """
        Initialize a GroupKeyEnvelope instance.

        Args:
            gke_bytes: Binary data of the envelope (optional)
        """
        if gke_bytes:
            self._init_from_bytes(gke_bytes)
        else:
            self._init_empty()
    
    def _init_empty(self):
        """Initialize an empty instance."""
        self.version = 0
        self.reserved = 0
        self.is_public_key = 0
        self.l0_index = 0
        self.l1_index = 0
        self.l2_index = 0
        self.root_key_identifier = ""
        self.cb_kdf_algorithm = 0
        self.cb_kdf_parameters = 0
        self.cb_secret_agreement_algorithm = 0
        self.cb_secret_agreement_parameters = 0
        self.private_key_length = 0
        self.public_key_length = 0
        self.cb_l1_key = 0
        self.cb_l2_key = 0
        self.cb_domain_name = 0
        self.cb_forest_name = 0
        self.kdf_algorithm = ""
        self.kdf_parameters = b""
        self.secret_agreement_algorithm = ""
        self.secret_agreement_parameters = b""
        self.domain_name = ""
        self.forest_name = ""
        self.l1_key = None
        self.l2_key = None
    
    def _init_from_bytes(self, gke_bytes: bytes):
        """Initialize from binary data."""
        self.version = struct.unpack('<I', gke_bytes[0:4])[0]
        self.reserved = struct.unpack('<I', gke_bytes[4:8])[0]
        self.is_public_key = struct.unpack('<I', gke_bytes[8:12])[0]
        self.l0_index = struct.unpack('<I', gke_bytes[12:16])[0]
        self.l1_index = struct.unpack('<I', gke_bytes[16:20])[0]
        self.l2_index = struct.unpack('<I', gke_bytes[20:24])[0]
        
        # GUID (16 bytes)
        self.root_key_identifier = str(gke_bytes[24:40])
        
        self.cb_kdf_algorithm = struct.unpack('<I', gke_bytes[40:44])[0]
        self.cb_kdf_parameters = struct.unpack('<I', gke_bytes[44:48])[0]
        self.cb_secret_agreement_algorithm = struct.unpack('<I', gke_bytes[48:52])[0]
        self.cb_secret_agreement_parameters = struct.unpack('<I', gke_bytes[52:56])[0]
        self.private_key_length = struct.unpack('<I', gke_bytes[56:60])[0]
        self.public_key_length = struct.unpack('<I', gke_bytes[60:64])[0]
        self.cb_l1_key = struct.unpack('<I', gke_bytes[64:68])[0]
        self.cb_l2_key = struct.unpack('<I', gke_bytes[68:72])[0]
        self.cb_domain_name = struct.unpack('<I', gke_bytes[72:76])[0]
        self.cb_forest_name = struct.unpack('<I', gke_bytes[76:80])[0]
        
        cur_index = 80
        
        # Read KDFAlgorithm
        self.kdf_algorithm = gke_bytes[cur_index:cur_index+self.cb_kdf_algorithm].decode('utf-16le')
        cur_index += self.cb_kdf_algorithm
        
        # Read KDFParameters
        if self.cb_kdf_parameters > 0:
            self.kdf_parameters = gke_bytes[cur_index:cur_index+self.cb_kdf_parameters]
        cur_index += self.cb_kdf_parameters
        
        # Read SecretAgreementAlgorithm
        self.secret_agreement_algorithm = gke_bytes[cur_index:cur_index+self.cb_secret_agreement_algorithm].decode('utf-16le')
        cur_index += self.cb_secret_agreement_algorithm
        
        # Read SecretAgreementParameters
        if self.cb_secret_agreement_parameters > 0:
            self.secret_agreement_parameters = gke_bytes[cur_index:cur_index+self.cb_secret_agreement_parameters]
        cur_index += self.cb_secret_agreement_parameters
        
        # Read DomainName
        self.domain_name = gke_bytes[cur_index:cur_index+self.cb_domain_name].decode('utf-16le')
        cur_index += self.cb_domain_name
        
        # Read ForestName
        self.forest_name = gke_bytes[cur_index:cur_index+self.cb_forest_name].decode('utf-16le')
        cur_index += self.cb_forest_name
        
        # Read L1Key
        if self.cb_l1_key > 0:
            self.l1_key = gke_bytes[cur_index:cur_index+self.cb_l1_key]
        
        # Read L2Key
        if self.cb_l2_key > 0:
            self.l2_key = gke_bytes[cur_index+self.cb_l1_key:cur_index+self.cb_l1_key+self.cb_l2_key]
    
    def serialize(self) -> bytes:
        """
        Serialize the envelope to binary data.

        Returns:
            Binary data of the envelope
        """
        gke_size = (80 + self.cb_kdf_algorithm + self.cb_kdf_parameters + 
                   self.cb_secret_agreement_algorithm + self.cb_secret_agreement_parameters + 
                   self.cb_domain_name + self.cb_forest_name + self.cb_l1_key + self.cb_l2_key)
        
        gke_bytes = bytearray(gke_size)
        
        # Write fixed fields
        struct.pack_into('<I', gke_bytes, 0, self.version)
        struct.pack_into('<I', gke_bytes, 4, self.reserved)
        struct.pack_into('<I', gke_bytes, 8, self.is_public_key)
        struct.pack_into('<I', gke_bytes, 12, self.l0_index)
        struct.pack_into('<I', gke_bytes, 16, self.l1_index)
        struct.pack_into('<I', gke_bytes, 20, self.l2_index)
        
        # GUID
        gke_bytes[24:40] = self.root_key_identifier.encode('utf-8')[:16].ljust(16, b'\x00')
        
        struct.pack_into('<I', gke_bytes, 40, self.cb_kdf_algorithm)
        struct.pack_into('<I', gke_bytes, 44, self.cb_kdf_parameters)
        struct.pack_into('<I', gke_bytes, 48, self.cb_secret_agreement_algorithm)
        struct.pack_into('<I', gke_bytes, 52, self.cb_secret_agreement_parameters)
        struct.pack_into('<I', gke_bytes, 56, self.private_key_length)
        struct.pack_into('<I', gke_bytes, 60, self.public_key_length)
        struct.pack_into('<I', gke_bytes, 64, self.cb_l1_key)
        struct.pack_into('<I', gke_bytes, 68, self.cb_l2_key)
        struct.pack_into('<I', gke_bytes, 72, self.cb_domain_name)
        struct.pack_into('<I', gke_bytes, 76, self.cb_forest_name)
        
        # Write variable fields
        cur_index = 80
        
        # KDFAlgorithm
        kdf_algorithm_bytes = self.kdf_algorithm.encode('utf-16le')
        gke_bytes[cur_index:cur_index+len(kdf_algorithm_bytes)] = kdf_algorithm_bytes
        cur_index += self.cb_kdf_algorithm
        
        # KDFParameters
        if self.cb_kdf_parameters > 0:
            gke_bytes[cur_index:cur_index+self.cb_kdf_parameters] = self.kdf_parameters
        cur_index += self.cb_kdf_parameters
        
        # SecretAgreementAlgorithm
        secret_agreement_algorithm_bytes = self.secret_agreement_algorithm.encode('utf-16le')
        gke_bytes[cur_index:cur_index+len(secret_agreement_algorithm_bytes)] = secret_agreement_algorithm_bytes
        cur_index += self.cb_secret_agreement_algorithm
        
        # SecretAgreementParameters
        if self.cb_secret_agreement_parameters > 0:
            gke_bytes[cur_index:cur_index+self.cb_secret_agreement_parameters] = self.secret_agreement_parameters
        cur_index += self.cb_secret_agreement_parameters
        
        # DomainName
        domain_name_bytes = self.domain_name.encode('utf-16le')
        gke_bytes[cur_index:cur_index+len(domain_name_bytes)] = domain_name_bytes
        cur_index += self.cb_domain_name
        
        # ForestName
        forest_name_bytes = self.forest_name.encode('utf-16le')
        gke_bytes[cur_index:cur_index+len(forest_name_bytes)] = forest_name_bytes
        cur_index += self.cb_forest_name
        
        # L1Key
        if self.cb_l1_key > 0 and self.l1_key:
            gke_bytes[cur_index:cur_index+self.cb_l1_key] = self.l1_key
            cur_index += self.cb_l1_key
        
        # L2Key
        if self.cb_l2_key > 0 and self.l2_key:
            gke_bytes[cur_index:cur_index+self.cb_l2_key] = self.l2_key
        
        return bytes(gke_bytes)
    
    def to_base64_string(self) -> str:
        """
        Return the Base64 representation of the envelope.

        Returns:
            Base64 string
        """
        import base64
        return base64.b64encode(self.serialize()).decode('utf-8')
    
    def __str__(self) -> str:
        """Return the string representation of the object."""
        return f"GroupKeyEnvelope(version={self.version}, l0={self.l0_index}, l1={self.l1_index}, l2={self.l2_index})"
    
    def __repr__(self) -> str:
        """Return the official representation of the object."""
        return f"GroupKeyEnvelope(version={self.version}, root_key_id='{self.root_key_identifier}')"
