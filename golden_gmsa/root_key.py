"""
Module pour la gestion des clés racine KDS (Key Distribution Service).
"""

import logging
import struct
from typing import List, Iterator, Optional
from .ldap_utils import LdapUtils
from .config import KDS_ROOT_KEY_REQUIRED_ATTRIBUTES, KDS_ROOT_KEY_DATA_SIZE_DEFAULT

logger = logging.getLogger(__name__)


class RootKey:
    """
    Classe représentant une clé racine KDS (Key Distribution Service).
    """
    
    def __init__(self, search_result: dict = None, file_path: str = None, root_key_bytes: bytes = None):
        """
        Initialise une instance de RootKey.
        
        Args:
            search_result: Résultat de recherche LDAP
            file_path: Chemin vers un fichier de clé racine
            root_key_bytes: Données binaires de la clé racine
        """
        if search_result is not None:
            self._init_from_search_result(search_result)
        elif file_path is not None:
            self._init_from_file(file_path)
        elif root_key_bytes is not None:
            if not root_key_bytes:
                raise ValueError("root_key_bytes ne peut pas être une chaîne vide")
            self._init_from_bytes(root_key_bytes)
        else:
            raise ValueError("Un paramètre doit être fourni (search_result, file_path, ou root_key_bytes)")
    
    def _init_from_search_result(self, search_result: dict):
        """Initialise à partir d'un résultat de recherche LDAP."""
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
        """Initialise à partir d'un fichier."""
        import os
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Fichier non trouvé: {file_path}")
        
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        if len(lines) < 12:
            raise ValueError("Fichier de clé racine invalide")
        
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
        """Initialise à partir de données binaires."""
        track_size = 32
        
        # Lire les premiers champs
        self.ms_kds_version = struct.unpack('<I', root_key_bytes[0:4])[0]
        self.cn = str(root_key_bytes[4:20])  # GUID en bytes
        self.prob_reserved = struct.unpack('<I', root_key_bytes[20:24])[0]
        self.ms_kds_version2 = struct.unpack('<I', root_key_bytes[24:28])[0]
        self.prob_reserved2 = struct.unpack('<I', root_key_bytes[28:32])[0]
        
        # Lire msKdsKDFAlgorithmID
        ms_kdf_algorithm_id_size = struct.unpack('<I', root_key_bytes[track_size:track_size+4])[0]
        self.ms_kds_kdf_algorithm_id = root_key_bytes[track_size+4:track_size+4+ms_kdf_algorithm_id_size].decode('utf-16le')
        track_size += ms_kdf_algorithm_id_size + 4
        
        # Lire KDFParamSize
        self.kdf_param_size = struct.unpack('<I', root_key_bytes[track_size:track_size+4])[0]
        if self.kdf_param_size > 0:
            self.ms_kds_kdf_param = root_key_bytes[track_size+4:track_size+4+self.kdf_param_size]
            track_size += self.kdf_param_size + 4
        else:
            self.ms_kds_kdf_param = None
            track_size += 4
        
        self.prob_reserved3 = struct.unpack('<I', root_key_bytes[track_size:track_size+4])[0]
        track_size += 4
        
        # Lire kdsSecretAgreementAlgorithmID
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
        
        # Lire les autres champs
        self.private_key_length = struct.unpack('<I', root_key_bytes[track_size:track_size+4])[0]
        self.public_key_length = struct.unpack('<I', root_key_bytes[track_size+4:track_size+8])[0]
        self.prob_reserved4 = struct.unpack('<I', root_key_bytes[track_size+8:track_size+12])[0]
        self.prob_reserved5 = struct.unpack('<I', root_key_bytes[track_size+12:track_size+16])[0]
        self.prob_reserved6 = struct.unpack('<I', root_key_bytes[track_size+16:track_size+20])[0]
        self.flag = struct.unpack('<Q', root_key_bytes[track_size+20:track_size+28])[0]
        self.flag2 = struct.unpack('<Q', root_key_bytes[track_size+28:track_size+36])[0]
        track_size += 36
        
        # Lire kdsDomainID
        kds_domain_id_size = struct.unpack('<I', root_key_bytes[track_size:track_size+4])[0]
        self.kds_domain_id = root_key_bytes[track_size+4:track_size+4+kds_domain_id_size].decode('utf-16le')
        track_size += kds_domain_id_size + 4
        
        # Lire les timestamps
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
        Récupère une clé racine par son GUID.
        
        Args:
            forest_name: Nom de la forêt
            root_key_id: GUID de la clé racine
            
        Returns:
            Instance de RootKey ou None si non trouvée
        """
        try:
            config_naming_context = LdapUtils._get_config_naming_context(forest_name)
            ldap_filter = f"(&(objectClass=msKds-ProvRootKey)(cn={root_key_id}))"
            
            results = LdapUtils.find_in_config_partition(forest_name, ldap_filter, KDS_ROOT_KEY_REQUIRED_ATTRIBUTES)
            
            if not results:
                return None
            
            return RootKey(search_result=results[0])
            
        except Exception as ex:
            logger.error(f"Erreur lors de la récupération de la clé racine {root_key_id}: {ex}")
            return None
    
    @staticmethod
    def get_all_root_keys(forest_name: str) -> Iterator['RootKey']:
        """
        Récupère toutes les clés racine de la forêt.
        
        Args:
            forest_name: Nom de la forêt
            
        Yields:
            Instances de RootKey
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
                    dn = result.get('distinguishedName', [b'Inconnu'])[0]
                    if isinstance(dn, bytes):
                        dn = dn.decode('utf-8', errors='ignore')
                    logger.warning(f"{dn}: {ex}")
                
                if root_key:
                    yield root_key
                    
        except Exception as ex:
            logger.error(f"Erreur lors de la récupération des clés racine: {ex}")
            return
    
    def serialize(self) -> bytes:
        """
        Sérialise la clé racine en données binaires.
        
        Returns:
            Données binaires de la clé racine
        """
        track_size = 36
        
        # Calculer la taille totale
        total_size = (124 + 
                     len(self.ms_kds_kdf_algorithm_id.encode('utf-16le')) + 
                     (len(self.ms_kds_kdf_param) if self.ms_kds_kdf_param else 0) + 
                     (len(self.kds_secret_agreement_param) if self.kds_secret_agreement_param else 0) +
                     len(self.kds_secret_agreement_algorithm_id.encode('utf-16le')) + 
                     len(self.kds_domain_id.encode('utf-16le')) + 
                     (len(self.kds_root_key_data) if self.kds_root_key_data else 0))
        
        root_key_bytes = bytearray(total_size)
        
        # Écrire les premiers champs
        struct.pack_into('<I', root_key_bytes, 0, self.ms_kds_version)
        # Note: GUID conversion simplifiée
        root_key_bytes[4:20] = self.cn.encode('utf-8')[:16].ljust(16, b'\x00')
        struct.pack_into('<I', root_key_bytes, 20, self.prob_reserved)
        struct.pack_into('<I', root_key_bytes, 24, self.ms_kds_version2)
        struct.pack_into('<I', root_key_bytes, 28, self.prob_reserved2)
        
        # Écrire msKdsKDFAlgorithmID
        ms_kds_kdf_algorithm_id_bytes = self.ms_kds_kdf_algorithm_id.encode('utf-16le')
        struct.pack_into('<I', root_key_bytes, 32, len(ms_kds_kdf_algorithm_id_bytes))
        root_key_bytes[36:36+len(ms_kds_kdf_algorithm_id_bytes)] = ms_kds_kdf_algorithm_id_bytes
        struct.pack_into('<I', root_key_bytes, 36+len(ms_kds_kdf_algorithm_id_bytes), self.kdf_param_size)
        if self.ms_kds_kdf_param:
            root_key_bytes[40+len(ms_kds_kdf_algorithm_id_bytes):40+len(ms_kds_kdf_algorithm_id_bytes)+len(self.ms_kds_kdf_param)] = self.ms_kds_kdf_param
            track_size += len(self.ms_kds_kdf_param) + len(ms_kds_kdf_algorithm_id_bytes) + 4
        else:
            track_size += len(ms_kds_kdf_algorithm_id_bytes) + 4
        
        # Continuer avec les autres champs...
        # (Implémentation simplifiée pour l'exemple)
        
        return bytes(root_key_bytes)
    
    def to_base64_string(self) -> str:
        """
        Retourne la représentation Base64 de la clé racine.
        
        Returns:
            String Base64
        """
        import base64
        return base64.b64encode(self.serialize()).decode('utf-8')
    
    def to_string(self) -> str:
        """
        Retourne une représentation string de la clé racine.
        
        Returns:
            String formatée
        """
        result = f"Guid:\t\t{self.cn}\n"
        result += f"Base64 blob:\t{self.to_base64_string()}\n"
        result += "----------------------------------------------\n"
        return result
    
    def __str__(self) -> str:
        """Retourne la représentation string de l'objet."""
        return self.to_string()
    
    def __repr__(self) -> str:
        """Retourne la représentation officielle de l'objet."""
        return f"RootKey(guid='{self.cn}', version={self.ms_kds_version})"
