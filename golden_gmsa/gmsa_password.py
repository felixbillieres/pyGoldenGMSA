"""
Module pour la génération de mots de passe GMSA.
"""

import hashlib
import hmac
import struct
import logging
import uuid
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
        # Convertir le GUID en bytes au format Windows (.NET Guid.ToByteArray() format)
        # .NET Guid.ToByteArray() utilise un format "mixed-endian" qui correspond à uuid.UUID().bytes_le
        try:
            root_key_guid = uuid.UUID(root_key.cn).bytes_le  # Utiliser bytes_le pour correspondre à .NET Guid.ToByteArray()
        except (ValueError, AttributeError):
            # Si cn n'est pas un UUID valide, essayer de le parser comme string
            root_key_guid = uuid.UUID(root_key.cn.replace('-', '')).bytes_le if '-' in str(root_key.cn) else uuid.UUID(str(root_key.cn)).bytes_le
        
        # Générer le contexte KDF (retourne contexte et flag2)
        kdf_context, kdf_context_flag = GmsaPassword._generate_kdf_context(
            root_key_guid, l0_key_id,
            0xffffffff, 0xffffffff,
            0
        )
        
        # Générer la clé dérivée (pas de label pour L0)
        # not_sure est une liste pour simuler ref int en C#
        not_sure_ref = [kdf_context_flag]
        generate_derived_key = GmsaPassword._generate_derived_key(
            root_key.ms_kds_kdf_algorithm_id,
            root_key.ms_kds_kdf_param or b"",
            root_key.kdf_param_size,
            root_key.kds_root_key_data or b"",
            root_key.kds_root_key_data_size if root_key.kds_root_key_data else 0,
            kdf_context, len(kdf_context),
            not_sure_ref, b"", 0,  # Pas de label pour L0
            1,  # notsure_flag = 1 pour L0
            generate_derived_key := bytearray(KDS_ROOT_KEY_DATA_SIZE_DEFAULT),
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
        # Convertir le GUID en bytes au format Windows (.NET Guid.ToByteArray() format)
        try:
            root_key_guid = uuid.UUID(l0_key.cn).bytes_le  # Utiliser bytes_le pour correspondre à .NET Guid.ToByteArray()
        except (ValueError, AttributeError):
            root_key_guid = uuid.UUID(l0_key.cn.replace('-', '')).bytes_le if '-' in str(l0_key.cn) else uuid.UUID(str(l0_key.cn)).bytes_le
        derived_key = bytearray(KDS_ROOT_KEY_DATA_SIZE_DEFAULT)
        derived_key2 = None
        
        # Générer le contexte KDF (retourne contexte et flag2)
        kdf_context, kdf_context_flag = GmsaPassword._generate_kdf_context(
            root_key_guid, int(l0_key.l0_key_id),
            0x1f, 0xffffffff, 1
        )
        
        # Modifier le contexte avec le descripteur de sécurité
        kdf_context_modified = bytearray(len(kdf_context) + sd_size)
        kdf_context_modified[:len(kdf_context)] = kdf_context
        kdf_context_modified[len(kdf_context):] = security_descriptor
        
        # Générer la première clé dérivée (pas de label pour L1)
        not_sure_ref = [kdf_context_flag]
        derived_key = GmsaPassword._generate_derived_key(
            l0_key.ms_kds_kdf_algorithm_id,
            l0_key.ms_kds_kdf_param or b"",
            l0_key.kdf_param_size,
            l0_key.kds_root_key_data or b"",
            64,
            kdf_context_modified, len(kdf_context_modified),
            not_sure_ref, b"", 0,  # Pas de label pour L1
            1,  # notsure_flag = 1 pour L1 premier appel
            derived_key,
            KDS_ROOT_KEY_DATA_SIZE_DEFAULT, 0
        )
        
        # Générer la clé secondaire si nécessaire
        if l1_key_id != 31:
            kdf_context_copy = bytearray(kdf_context)
            # Modifier le contexte à l'index flag comme dans le code C#
            if kdf_context_flag < len(kdf_context_copy):
                kdf_context_copy[kdf_context_flag] = (kdf_context_copy[kdf_context_flag] - 1) & 0xFF
            generated_derived_key = derived_key.copy()
            
            not_sure_ref2 = [kdf_context_flag]
            derived_key = GmsaPassword._generate_derived_key(
                l0_key.ms_kds_kdf_algorithm_id, l0_key.ms_kds_kdf_param or b"",
                l0_key.kdf_param_size, generated_derived_key,
                64, kdf_context_copy, len(kdf_context_copy),
                not_sure_ref2, b"", 0,  # Pas de label
                31 - l1_key_id,  # notsure_flag = 31 - l1_key_id
                derived_key,
                KDS_ROOT_KEY_DATA_SIZE_DEFAULT, 0
            )
        
        if l1_key_id > 0:
            kdf_context_copy = bytearray(kdf_context)
            # Modifier le contexte à l'index flag comme dans le code C#
            if kdf_context_flag < len(kdf_context_copy):
                kdf_context_copy[kdf_context_flag] = (l1_key_id - 1) & 0xFF
            derived_key2 = bytearray(KDS_ROOT_KEY_DATA_SIZE_DEFAULT)
            generated_derived_key = derived_key.copy()
            
            not_sure_ref3 = [kdf_context_flag]
            derived_key2 = GmsaPassword._generate_derived_key(
                l0_key.ms_kds_kdf_algorithm_id, l0_key.ms_kds_kdf_param or b"",
                l0_key.kdf_param_size, generated_derived_key,
                64, kdf_context_copy, len(kdf_context_copy),
                not_sure_ref3, b"", 0,  # Pas de label
                1,  # notsure_flag = 1
                derived_key2,
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
        # Convertir le GUID en bytes au format Windows (.NET Guid.ToByteArray() format)
        try:
            root_key_guid = uuid.UUID(l0_key.cn).bytes_le  # Utiliser bytes_le pour correspondre à .NET Guid.ToByteArray()
        except (ValueError, AttributeError):
            root_key_guid = uuid.UUID(l0_key.cn.replace('-', '')).bytes_le if '-' in str(l0_key.cn) else uuid.UUID(str(l0_key.cn)).bytes_le
        derived_key = bytearray(KDS_ROOT_KEY_DATA_SIZE_DEFAULT)
        
        # Générer le contexte KDF (retourne contexte et flag2)
        kdf_context, flag_kdf_context = GmsaPassword._generate_kdf_context(
            root_key_guid, int(l0_key.l0_key_id),
            l1_key_id, 0x1f, 2
        )
        
        some_flag = 32 - l2_key_id
        
        not_sure_ref = [flag_kdf_context]
        derived_key = GmsaPassword._generate_derived_key(
            l0_key.ms_kds_kdf_algorithm_id, l0_key.ms_kds_kdf_param or b"",
            l0_key.kdf_param_size, l1_derived_key,
            64, kdf_context, len(kdf_context),
            not_sure_ref, b"", 0,  # Pas de label pour L2
            some_flag,  # notsure_flag = 32 - l2_key_id
            derived_key,
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
        gke.kdf_parameters = l0_key.ms_kds_kdf_param[:] if l0_key.ms_kds_kdf_param else b""
        gke.secret_agreement_algorithm = l0_key.kds_secret_agreement_algorithm_id
        gke.secret_agreement_parameters = l0_key.kds_secret_agreement_param[:] if l0_key.kds_secret_agreement_param else b""
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
        
        # ClientComputeL2Key: mettre à jour les clés L1/L2 si nécessaire
        if l1_key_diff > 0 or l2_key_diff > 0:
            # Extraire le GUID de la clé racine
            from .msds_managed_password_id import MsdsManagedPasswordId
            # Convertir le GUID en bytes au format Windows (.NET Guid.ToByteArray() format)
            try:
                root_key_guid = uuid.UUID(gke.root_key_identifier).bytes_le  # Utiliser bytes_le pour correspondre à .NET Guid.ToByteArray()
            except (ValueError, AttributeError):
                root_key_guid = uuid.UUID(gke.root_key_identifier.replace('-', '')).bytes_le if '-' in str(gke.root_key_identifier) else uuid.UUID(str(gke.root_key_identifier)).bytes_le
            kdf_param = gke.kdf_parameters if gke.kdf_parameters and len(gke.kdf_parameters) > 0 else None
            
            # Mettre à jour L1 si nécessaire
            if l1_key_diff > 0:
                # Générer le contexte KDF pour L1
                kdf_context_l1, kdf_context_flag_l1 = GmsaPassword._generate_kdf_context(
                    root_key_guid, gke.l0_index,
                    new_l1_key_id, 0xffffffff,
                    1
                )
                
                # Générer la clé dérivée pour mettre à jour L1
                not_sure_ref_l1 = [kdf_context_flag_l1]
                l1_key = GmsaPassword._generate_derived_key(
                    gke.kdf_algorithm, kdf_param or b"",
                    len(kdf_param) if kdf_param else 0, l1_key,
                    64, kdf_context_l1, len(kdf_context_l1),
                    not_sure_ref_l1, b"", 0,  # Pas de label
                    l1_key_diff,  # notsure_flag = l1_key_diff
                    bytearray(KDS_ROOT_KEY_DATA_SIZE_DEFAULT),
                    KDS_ROOT_KEY_DATA_SIZE_DEFAULT, 0
                )
                l1_key = bytes(l1_key)
            
            # Mettre à jour L1 avec L2 si nécessaire (comme dans le code C#)
            if msds_managed_password_id is None or gke.l1_index <= MsdsManagedPasswordId(msds_managed_password_id).l1_index:
                if gke.cb_l2_key > 0:
                    l1_key = l2_key
            
            # Mettre à jour L2 si nécessaire
            if l2_key_diff > 0:
                # Déterminer "something" comme dans le code C#
                if msds_managed_password_id is None:
                    something = gke.l1_index
                else:
                    msds_pwd_id = MsdsManagedPasswordId(msds_managed_password_id)
                    something = msds_pwd_id.l1_index
                
                # Générer le contexte KDF pour L2
                kdf_context_l2, kdf_context_flag_l2 = GmsaPassword._generate_kdf_context(
                    root_key_guid, gke.l0_index,
                    something, new_l2_key_id,
                    2
                )
                
                # Initialiser l2_key si null
                if l2_key is None:
                    l2_key = bytearray(KDS_ROOT_KEY_DATA_SIZE_DEFAULT)
                else:
                    l2_key = bytearray(l2_key)
                
                # Générer la clé dérivée pour mettre à jour L2
                not_sure_ref_l2 = [kdf_context_flag_l2]
                l2_key = GmsaPassword._generate_derived_key(
                    gke.kdf_algorithm, kdf_param or b"",
                    len(kdf_param) if kdf_param else 0, l1_key,
                    64, kdf_context_l2, len(kdf_context_l2),
                    not_sure_ref_l2, b"", 0,  # Pas de label
                    l2_key_diff,  # notsure_flag = l2_key_diff
                    l2_key,
                    KDS_ROOT_KEY_DATA_SIZE_DEFAULT, 0
                )
                l2_key = bytes(l2_key)
        
        # Génération finale du mot de passe (avec label "GMSA PASSWORD\x0")
        flag_ref = [0]  # flag est initialisé à 0 dans le code C#
        pwd_blob = GmsaPassword._generate_derived_key(
            gke.kdf_algorithm, gke.kdf_parameters or b"",
            len(gke.kdf_parameters) if gke.kdf_parameters else 0, l2_key if l2_key else l1_key,
            64, sid, len(sid),
            flag_ref, label, len(label),  # Label "GMSA PASSWORD\x0" pour le password blob final
            1,  # notsure_flag = 1 pour le password blob final
            pwd_blob, pwd_blob_size, 0
        )
        
        return bytes(pwd_blob)
    
    @staticmethod
    def _generate_kdf_context(root_key_guid: bytes, context_init: int, context_init2: int,
                             context_init3: int, flag: int) -> Tuple[bytes, int]:
        """
        Génère un contexte KDF (réplique de kdscli.dll GenerateKDFContext).
        
        Args:
            root_key_guid: GUID de la clé racine (16 bytes)
            context_init: Valeur d'initialisation du contexte 1
            context_init2: Valeur d'initialisation du contexte 2 (long)
            context_init3: Valeur d'initialisation du contexte 3 (long)
            flag: Flag d'initialisation
        
        Returns:
            Tuple contenant (contexte KDF, flag2)
        """
        # Répliquer exactement ce que fait kdscli.dll GenerateKDFContext
        # Le contexte est construit comme: GUID || context_init || context_init2 || context_init3 || flag
        context_data = bytearray()
        context_data.extend(root_key_guid[:16])  # GUID (16 bytes)
        context_data.extend(struct.pack('<I', context_init))  # int (4 bytes, little-endian)
        context_data.extend(struct.pack('<Q', context_init2 & 0xFFFFFFFFFFFFFFFF))  # long (8 bytes, little-endian)
        context_data.extend(struct.pack('<Q', context_init3 & 0xFFFFFFFFFFFFFFFF))  # long (8 bytes, little-endian)
        context_data.extend(struct.pack('<I', flag))  # int (4 bytes, little-endian)
        
        # flag2 est l'index dans le contexte où se trouve context_init (après le GUID)
        flag2 = 16  # Position après le GUID
        
        return bytes(context_data), flag2
    
    @staticmethod
    def _generate_derived_key(kdf_algorithm_id: str, kdf_param: bytes, kdf_param_size: int,
                             pb_secret: bytes, cb_secret: int, context: bytes, context_size: int,
                             not_sure: list, label: bytes, label_size: int,
                             notsure_flag: int, pb_derived_key: bytearray, cb_derived_key: int,
                             always_zero: int) -> bytearray:
        """
        Génère une clé dérivée en utilisant SP800-108 CTR HMAC (réplique de kdscli.dll GenerateDerivedKey).
        
        Args:
            kdf_algorithm_id: Identifiant de l'algorithme KDF (ex: "SP800_108_CTR_HMAC")
            kdf_param: Paramètres KDF optionnels
            kdf_param_size: Taille des paramètres KDF
            pb_secret: Clé secrète d'entrée
            cb_secret: Taille de la clé secrète
            context: Contexte KDF
            context_size: Taille du contexte
            not_sure: Liste avec un seul élément (référence, peut être modifié) [flag]
            label: Label KDF (ex: "GMSA PASSWORD" + null byte en UTF-16LE)
            label_size: Taille du label
            notsure_flag: Nombre d'itérations à faire (c'est le vrai paramètre d'itération!)
            pb_derived_key: Buffer de sortie pour la clé dérivée
            cb_derived_key: Taille désirée de la clé dérivée
            always_zero: Toujours zéro
        
        Returns:
            Clé dérivée générée
        """
        if kdf_algorithm_id == "SP800_108_CTR_HMAC":
            # Implémentation de SP800-108 CTR HMAC selon la spécification NIST
            # notsure_flag indique le nombre d'itérations à faire
            # Diviser la sortie désirée en blocs de la taille du hash (32 bytes pour SHA-256)
            hash_size = 32  # SHA-256
            num_blocks = (cb_derived_key + hash_size - 1) // hash_size
            
            # Extraire la clé HMAC du secret (utiliser les premiers cb_secret bytes)
            hmac_key = pb_secret[:cb_secret] if cb_secret > 0 else pb_secret
            
            # Extraire le label et le contexte
            label_bytes = label[:label_size] if label_size > 0 else b""
            context_bytes = context[:context_size] if context_size > 0 else b""
            
            # Construire le FixedInputData selon SP800-108 CTR HMAC
            # Format standard SP800-108: InputBlock = Label || 0x00 || Context || Counter
            # Mais Windows peut utiliser un format différent
            # Testons SANS le 0x00 (Windows peut utiliser Label || Context directement)
            if label_size > 0:
                # Windows peut utiliser Label || Context (sans 0x00)
                fixed_input_data = label_bytes + context_bytes
            else:
                fixed_input_data = context_bytes
            
            # Faire notsure_flag itérations (notsure_flag indique le nombre d'itérations KDF)
            current_secret = hmac_key
            current_context = context_bytes
            derived_key_bytes = bytearray()
            
            for iteration in range(notsure_flag if notsure_flag > 0 else 1):
                # Générer chaque bloc pour cette itération CTR
                iteration_derived = bytearray()
                for i in range(1, num_blocks + 1):
                    # Construire InputBlock = FixedInputData || Counter
                    # où Counter est l'index du bloc encodé sur 4 bytes en big-endian
                    counter_bytes = struct.pack('>I', i)  # Big-endian 32-bit integer
                    
                    # Reconstruire fixed_input_data avec le contexte actuel pour cette itération
                    if label_size > 0:
                        input_block = label_bytes + current_context + counter_bytes
                    else:
                        input_block = current_context + counter_bytes
                    
                    # K(i) = HMAC-SHA256(K_I, InputBlock)
                    k_i = hmac.new(current_secret, input_block, hashlib.sha256).digest()
                    iteration_derived.extend(k_i)
                
                # Pour l'itération suivante, utiliser la clé dérivée comme nouvelle clé secrète
                if iteration < (notsure_flag if notsure_flag > 0 else 1) - 1:
                    current_secret = iteration_derived[:cb_secret] if cb_secret > 0 else iteration_derived
                    # Modifier le contexte à l'index not_sure[0] si possible (décrémenter)
                    if len(current_context) > 0 and not_sure and len(not_sure) > 0 and not_sure[0] < len(current_context):
                        current_context = bytearray(current_context)
                        current_context[not_sure[0]] = (current_context[not_sure[0]] - 1) & 0xFF
                        current_context = bytes(current_context)
                else:
                    # Dernière itération, utiliser cette clé dérivée
                    derived_key_bytes = iteration_derived
            
            # Tronquer à la taille désirée
            result = derived_key_bytes[:cb_derived_key]
            pb_derived_key[:len(result)] = result
            
            return pb_derived_key
        else:
            # Fallback: utiliser HMAC simple pour autres algorithmes
            key_material = pb_secret[:cb_secret] if cb_secret > 0 else pb_secret
            context_bytes = context[:context_size] if context_size > 0 else b""
            hmac_key = hashlib.sha256(key_material).digest()
            derived_key = hmac.new(hmac_key, context_bytes, hashlib.sha256).digest()
            result = derived_key[:cb_derived_key]
            pb_derived_key[:len(result)] = result
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
