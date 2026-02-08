"""
Module for managing L0 keys.
"""

from .root_key import RootKey


class L0Key(RootKey):
    """
    Class representing an L0 key.
    Inherits from RootKey and adds an L0KeyID field.
    """

    def __init__(self, root_key: RootKey, l0_key_id: int, derived_key: bytes):
        """
        Initialize an L0Key instance.

        Args:
            root_key: Base root key
            l0_key_id: L0 key identifier
            derived_key: Derived key
        """
        # Do not call super().__init__() as we manually copy all attributes
        
        # Manually copy attributes
        self.ms_kds_version = root_key.ms_kds_version
        self.cn = root_key.cn
        self.prob_reserved = 0
        self.ms_kds_version2 = root_key.ms_kds_version
        self.prob_reserved2 = 0
        self.ms_kds_kdf_algorithm_id = root_key.ms_kds_kdf_algorithm_id
        self.ms_kds_kdf_param = root_key.ms_kds_kdf_param[:] if root_key.ms_kds_kdf_param else None
        self.kdf_param_size = root_key.kdf_param_size
        self.prob_reserved3 = root_key.prob_reserved3
        self.kds_secret_agreement_algorithm_id = root_key.kds_secret_agreement_algorithm_id
        self.kds_secret_agreement_param = root_key.kds_secret_agreement_param[:] if root_key.kds_secret_agreement_param else None
        self.secret_algorithm_param_size = root_key.secret_algorithm_param_size
        self.private_key_length = root_key.private_key_length
        self.public_key_length = root_key.public_key_length
        self.prob_reserved4 = root_key.prob_reserved4
        self.prob_reserved5 = root_key.prob_reserved5
        self.prob_reserved6 = root_key.prob_reserved6
        self.flag = root_key.flag
        self.flag2 = root_key.flag2
        self.kds_domain_id = root_key.kds_domain_id
        self.kds_create_time = root_key.kds_create_time
        self.kds_use_start_time = root_key.kds_use_start_time
        self.prob_reserved7 = root_key.prob_reserved7
        self.kds_root_key_data_size = root_key.kds_root_key_data_size
        
        # Replace root key data with the derived key
        self.kds_root_key_data = derived_key
        
        # Add the L0 identifier
        self.l0_key_id = l0_key_id
    
    def __str__(self) -> str:
        """Return the string representation of the object."""
        return f"L0Key(l0_key_id={self.l0_key_id}, root_key_id='{self.cn}')"
    
    def __repr__(self) -> str:
        """Return the official representation of the object."""
        return f"L0Key(l0_key_id={self.l0_key_id}, version={self.ms_kds_version})"
