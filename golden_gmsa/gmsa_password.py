"""
Module pour la génération de mots de passe GMSA.
"""

import hashlib
import hmac
import struct
import logging
from typing import Tuple, Optional
from .root_key import RootKey
from .msds_managed_password_id import MsdsManagedPasswordId
from .group_key_envelope import GroupKeyEnvelope
from .l0_key import L0Key
from .kds_utils import KdsUtils
from .config import DEFAULT_GMSA_SECURITY_DESCRIPTOR, KEY_CYCLE_DURATION, KDS_ROOT_KEY_DATA_SIZE_DEFAULT

logger = logging.getLogger(__name__)


class GmsaPassword:
    """
    Classe pour la génération de mots de passe GMSA.
    """
    
    @staticmethod
    def get_password(sid: str, root_key: RootKey, pwd_id: MsdsManagedPasswordId, 
                    domain_name: str, forest_name: str) -> bytes:
        """
        Génère le mot de passe GMSA.
        
        Args:
            sid: SID du gMSA
            root_key: Clé racine KDS
            pwd_id: Identifiant de mot de passe géré
            domain_name: Nom du domaine
            forest_name: Nom de la forêt
            
        Returns:
            Mot de passe généré en bytes
        """
        l0_key_id, l1_key_id, l2_key_id = KdsUtils.get_current_interval_id(
            KEY_CYCLE_DURATION, 0
        )
        
        gke, gke_size = GmsaPassword._get_sid_key_local(
            DEFAULT_GMSA_SECURITY_DESCRIPTOR,
            len(DEFAULT_GMSA_SECURITY_DESCRIPTOR),
            root_key,
            l0_key_id, l1_key_id, l2_key_id,
            0,
            domain_name, forest_name
        )
        
        password_blob_size = 256
        sid_bytes = GmsaPassword._sid_to_bytes(sid)
        
        password_blob = GmsaPassword._generate_gmsa_password(
            gke, gke_size,
            pwd_id.msds_managed_password_id_bytes,
            sid_bytes,
            password_blob_size
        )
        
        return password_blob
    
    @staticmethod
    def _get_sid_key_local(security_descriptor: bytes, sd_size: int, root_key: RootKey,
                          l0_key_id: int, l1_key_id: int, l2_key_id: int, access_check_failed: int,
                          domain_name: str, forest_name: str) -> Tuple[GroupKeyEnvelope, int]:
        """
        Obtient la clé SID locale (équivalent à GetSidKeyLocal du code C#).
        
        Returns:
            Tuple contenant (GroupKeyEnvelope, taille)
        """
        l0_key = GmsaPassword._compute_l0_key(root_key, l0_key_id)
        
        l1_key, l2_key = GmsaPassword._compute_sid_private_key(
            l0_key,
            security_descriptor, sd_size,
            l1_key_id,
            l2_key_id,
            access_check_failed
        )
        
        guid_exists = 1 if root_key.cn and root_key.cn != "" else 0
        
        gke, gke_size = GmsaPassword._format_return_blob(
            l0_key,
            guid_exists,
            l1_key, l1_key_id,
            l2_key, l2_key_id,
            None, 0,
            domain_name, forest_name
        )
        
        return gke, gke_size
    
    @staticmethod
    def _compute_l0_key(root_key: RootKey, l0_key_id: int) -> L0Key:
        """
        Calcule la clé L0.
        
        Returns:
            Instance de L0Key
        """
        root_key_guid = root_key.cn.encode('utf-8')[:16].ljust(16, b'\x00')
        
        # Générer le contexte KDF
        kdf_context = GmsaPassword._generate_kdf_context(
            root_key_guid, l0_key_id,
            0xffffffff, 0xffffffff,
            0
        )
        
        # Générer la clé dérivée
        generate_derived_key = GmsaPassword._generate_derived_key(
            root_key.ms_kds_kdf_algorithm_id,
            root_key.ms_kds_kdf_param or b"",
            root_key.kdf_param_size,
            root_key.kds_root_key_data or b"",
            root_key.kds_root_key_data_size if root_key.kds_root_key_data else 0,
            kdf_context, len(kdf_context),
            1, generate_derived_key := bytearray(KDS_ROOT_KEY_DATA_SIZE_DEFAULT),
            KDS_ROOT_KEY_DATA_SIZE_DEFAULT, 0
        )
        
        l0_key = L0Key(root_key, l0_key_id, generate_derived_key)
        return l0_key
    
    @staticmethod
    def _generate_l1_key(security_descriptor: bytes, sd_size: int, l0_key: L0Key,
                        l1_key_id: int) -> Tuple[bytes, Optional[bytes]]:
        """
        Génère la clé L1.
        
        Returns:
            Tuple contenant (clé dérivée principale, clé dérivée secondaire)
        """
        root_key_guid = l0_key.cn.encode('utf-8')[:16].ljust(16, b'\x00')
        derived_key = bytearray(KDS_ROOT_KEY_DATA_SIZE_DEFAULT)
        derived_key2 = None
        
        # Générer le contexte KDF
        kdf_context = GmsaPassword._generate_kdf_context(
            root_key_guid, int(l0_key.l0_key_id),
            0x1f, 0xffffffff, 1
        )
        
        # Modifier le contexte avec le descripteur de sécurité
        kdf_context_modified = bytearray(len(kdf_context) + sd_size)
        kdf_context_modified[:len(kdf_context)] = kdf_context
        kdf_context_modified[len(kdf_context):] = security_descriptor
        
        # Générer la première clé dérivée
        derived_key = GmsaPassword._generate_derived_key(
            l0_key.ms_kds_kdf_algorithm_id,
            l0_key.ms_kds_kdf_param or b"",
            l0_key.kdf_param_size,
            l0_key.kds_root_key_data or b"",
            64,
            kdf_context_modified, len(kdf_context_modified),
            1, derived_key,
            KDS_ROOT_KEY_DATA_SIZE_DEFAULT, 0
        )
        
        # Générer la clé secondaire si nécessaire
        if l1_key_id != 31:
            kdf_context_copy = bytearray(kdf_context)
            # Simuler la modification du contexte (simplifié)
            generated_derived_key = derived_key.copy()
            
            derived_key = GmsaPassword._generate_derived_key(
                l0_key.ms_kds_kdf_algorithm_id, l0_key.ms_kds_kdf_param or b"",
                l0_key.kdf_param_size, generated_derived_key,
                64, kdf_context_copy, len(kdf_context_copy),
                31 - l1_key_id, derived_key,
                KDS_ROOT_KEY_DATA_SIZE_DEFAULT, 0
            )
        
        if l1_key_id > 0:
            kdf_context_copy = bytearray(kdf_context)
            # Simuler la modification du contexte (simplifié)
            derived_key2 = bytearray(KDS_ROOT_KEY_DATA_SIZE_DEFAULT)
            generated_derived_key = derived_key.copy()
            
            derived_key2 = GmsaPassword._generate_derived_key(
                l0_key.ms_kds_kdf_algorithm_id, l0_key.ms_kds_kdf_param or b"",
                l0_key.kdf_param_size, generated_derived_key,
                64, kdf_context_copy, len(kdf_context_copy),
                1, derived_key2,
                KDS_ROOT_KEY_DATA_SIZE_DEFAULT, 0
            )
        
        return bytes(derived_key), bytes(derived_key2) if derived_key2 else None
    
    @staticmethod
    def _generate_l2_key(l0_key: L0Key, l1_derived_key: bytes, l1_key_id: int, l2_key_id: int) -> bytes:
        """
        Génère la clé L2.
        
        Returns:
            Clé L2 générée
        """
        root_key_guid = l0_key.cn.encode('utf-8')[:16].ljust(16, b'\x00')
        derived_key = bytearray(KDS_ROOT_KEY_DATA_SIZE_DEFAULT)
        
        # Générer le contexte KDF
        kdf_context = GmsaPassword._generate_kdf_context(
            root_key_guid, int(l0_key.l0_key_id),
            l1_key_id, 0x1f, 2
        )
        
        some_flag = 32 - l2_key_id
        
        derived_key = GmsaPassword._generate_derived_key(
            l0_key.ms_kds_kdf_algorithm_id, l0_key.ms_kds_kdf_param or b"",
            l0_key.kdf_param_size, l1_derived_key,
            64, kdf_context, len(kdf_context),
            some_flag, derived_key,
            KDS_ROOT_KEY_DATA_SIZE_DEFAULT, 0
        )
        
        return bytes(derived_key)
    
    @staticmethod
    def _compute_sid_private_key(l0_key: L0Key, security_descriptor: bytes, sd_size: int,
                                l1_key_id: int, l2_key_id: int, access_check_failed: int) -> Tuple[Optional[bytes], Optional[bytes]]:
        """
        Calcule la clé privée SID.
        
        Returns:
            Tuple contenant (clé L1, clé L2)
        """
        l1_key_first, l2_key_second = GmsaPassword._generate_l1_key(
            security_descriptor, sd_size, l0_key, l1_key_id
        )
        
        if l2_key_id == 31 and access_check_failed == 0:
            return l1_key_first, None
        
        l2_key = GmsaPassword._generate_l2_key(l0_key, l1_key_first, l1_key_id, l2_key_id)
        
        if l1_key_id > 0:
            l1_key = l2_key_second
        else:
            l1_key = None
        
        return l1_key, l2_key
    
    @staticmethod
    def _format_return_blob(l0_key: L0Key, guid_exists: int, l1_key: Optional[bytes], l1_key_id: int,
                           l2_key: Optional[bytes], l2_key_id: int, public_key: Optional[bytes], public_key_size: int,
                           domain_name: str, forest_name: str) -> Tuple[GroupKeyEnvelope, int]:
        """
        Formate le blob de retour.
        
        Returns:
            Tuple contenant (GroupKeyEnvelope, taille)
        """
        gke = GroupKeyEnvelope()
        gke.version = 1
        gke.reserved = 1263748171
        gke.l0_index = int(l0_key.l0_key_id)
        gke.l1_index = l1_key_id
        gke.l2_index = l2_key_id
        gke.root_key_identifier = l0_key.cn
        gke.cb_kdf_algorithm = len(l0_key.ms_kds_kdf_algorithm_id.encode('utf-16le'))
        gke.cb_kdf_parameters = l0_key.kdf_param_size
        gke.cb_secret_agreement_algorithm = len(l0_key.kds_secret_agreement_algorithm_id.encode('utf-16le'))
        gke.cb_secret_agreement_parameters = l0_key.secret_algorithm_param_size
        gke.private_key_length = l0_key.private_key_length
        gke.public_key_length = l0_key.public_key_length
        gke.cb_domain_name = len(domain_name.encode('utf-16le'))
        gke.cb_forest_name = len(forest_name.encode('utf-16le'))
        gke.kdf_algorithm = l0_key.ms_kds_kdf_algorithm_id
        gke.kdf_parameters = l0_key.ms_kds_kdf_param.copy() if l0_key.ms_kds_kdf_param else b""
        gke.secret_agreement_algorithm = l0_key.kds_secret_agreement_algorithm_id
        gke.secret_agreement_parameters = l0_key.kds_secret_agreement_param.copy() if l0_key.kds_secret_agreement_param else b""
        gke.domain_name = domain_name
        gke.forest_name = forest_name
        
        first_key_size = 64
        second_key_size = 64
        
        if public_key is not None:
            second_key_size = public_key_size
            first_key_size = 0
        elif l2_key_id == 31:
            second_key_size = 0
        else:
            if l1_key_id == 0:
                first_key_size = 0
        
        gke.cb_l1_key = first_key_size
        gke.cb_l2_key = second_key_size
        
        is_public_key = 0
        if public_key is not None:
            is_public_key |= 1
        is_public_key |= 2
        gke.is_public_key = is_public_key
        
        if first_key_size != 0 and l1_key is not None:
            gke.l1_key = l1_key
        
        if second_key_size != 0:
            if public_key is not None:
                gke.l2_key = public_key
            elif l2_key is not None:
                gke.l2_key = l2_key
        
        gke_size = (80 + gke.cb_kdf_algorithm + gke.cb_kdf_parameters + 
                   gke.cb_secret_agreement_algorithm + gke.cb_secret_agreement_parameters +
                   gke.cb_domain_name + gke.cb_forest_name + gke.cb_l1_key + gke.cb_l2_key)
        
        return gke, gke_size
    
    @staticmethod
    def _generate_gmsa_password(gke: GroupKeyEnvelope, gke_size: int, msds_managed_password_id: bytes,
                               sid: bytes, pwd_blob_size: int) -> bytes:
        """
        Génère le mot de passe GMSA.
        
        Returns:
            Mot de passe généré
        """
        label_str = "GMSA PASSWORD\x00"
        label = label_str.encode('utf-16le')
        pwd_blob = bytearray(pwd_blob_size)
        
        # Parser le résultat de la clé SID
        result = KdsUtils.parse_sid_key_result(gke, gke_size, msds_managed_password_id)
        
        l1_key = result['l1_key']
        l2_key = result['l2_key']
        l1_key_diff = result['l1_key_diff']
        l2_key_diff = result['l2_key_diff']
        new_l1_key_id = result['new_l1_key_id']
        new_l2_key_id = result['new_l2_key_id']
        
        if l1_key_diff > 0 or l2_key_diff > 0:
            # Implémentation simplifiée de ClientComputeL2Key
            if l1_key_diff > 0:
                # Calculer la clé L1 mise à jour
                pass
            
            if l2_key_diff > 0:
                # Calculer la clé L2 mise à jour
                if l2_key is None:
                    l2_key = bytearray(KDS_ROOT_KEY_DATA_SIZE_DEFAULT)
                
                # Générer la clé dérivée pour L2
                pwd_blob = GmsaPassword._generate_derived_key(
                    gke.kdf_algorithm, gke.kdf_parameters or b"",
                    len(gke.kdf_parameters) if gke.kdf_parameters else 0, l2_key,
                    64, sid, len(sid),
                    0, pwd_blob, pwd_blob_size, 0
                )
        
        # Génération finale du mot de passe
        pwd_blob = GmsaPassword._generate_derived_key(
            gke.kdf_algorithm, gke.kdf_parameters or b"",
            len(gke.kdf_parameters) if gke.kdf_parameters else 0, l2_key if l2_key else l1_key,
            64, sid, len(sid),
            0, pwd_blob, pwd_blob_size, 0
        )
        
        return bytes(pwd_blob)
    
    @staticmethod
    def _generate_kdf_context(root_key_guid: bytes, context_init: int, context_init2: int,
                             context_init3: int, flag: int) -> bytes:
        """
        Génère un contexte KDF (implémentation simplifiée).
        
        Returns:
            Contexte KDF généré
        """
        # Implémentation simplifiée - dans le vrai code, ceci utiliserait kdscli.dll
        context_data = bytearray()
        context_data.extend(root_key_guid)
        context_data.extend(struct.pack('<I', context_init))
        context_data.extend(struct.pack('<I', context_init2))
        context_data.extend(struct.pack('<I', context_init3))
        context_data.extend(struct.pack('<I', flag))
        
        return bytes(context_data)
    
    @staticmethod
    def _generate_derived_key(kdf_algorithm_id: str, kdf_param: bytes, kdf_param_size: int,
                             pb_secret: bytes, cb_secret: int, context: bytes, context_size: int,
                             not_sure: int, pb_derived_key: bytearray, cb_derived_key: int,
                             always_zero: int) -> bytearray:
        """
        Génère une clé dérivée (implémentation simplifiée).
        
        Returns:
            Clé dérivée générée
        """
        # Implémentation simplifiée utilisant HMAC-SHA256
        # Dans le vrai code, ceci utiliserait kdscli.dll avec l'algorithme KDF approprié
        
        if kdf_algorithm_id == "SP800_108_CTR_HMAC":
            # Utiliser HMAC-SHA256 comme approximation
            key_material = pb_secret + context
            derived_key = hashlib.pbkdf2_hmac('sha256', key_material, b'salt', 10000, cb_derived_key)
            pb_derived_key[:len(derived_key)] = derived_key
        else:
            # Fallback: utiliser HMAC simple
            key_material = pb_secret + context
            hmac_key = hashlib.sha256(key_material).digest()
            derived_key = hmac.new(hmac_key, context, hashlib.sha256).digest()
            pb_derived_key[:min(len(derived_key), cb_derived_key)] = derived_key[:cb_derived_key]
        
        return pb_derived_key
    
    @staticmethod
    def _sid_to_bytes(sid: str) -> bytes:
        """
        Convertit un SID en bytes (implémentation simplifiée).
        
        Args:
            sid: SID sous forme de string
            
        Returns:
            SID en bytes
        """
        # Implémentation simplifiée - dans le vrai code, ceci utiliserait ConvertStringSidToSid
        # Pour l'instant, on encode simplement le SID en UTF-16LE
        return sid.encode('utf-16le')
