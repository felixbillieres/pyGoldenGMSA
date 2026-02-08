"""
Module for GMSA password generation.
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
    Class for GMSA password generation.
    """
    
    @staticmethod
    def get_password(sid: str, root_key: RootKey, pwd_id: MsdsManagedPasswordId, 
                    domain_name: str, forest_name: str) -> bytes:
        """
        Generates the GMSA password.

        Args:
            sid: SID of the gMSA
            root_key: KDS root key
            pwd_id: Managed password identifier
            domain_name: Domain name
            forest_name: Forest name

        Returns:
            Generated password as bytes
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
        Gets the local SID key (equivalent to GetSidKeyLocal in the C# code).

        Returns:
            Tuple containing (GroupKeyEnvelope, size)
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
        Computes the L0 key.

        Returns:
            L0Key instance
        """
        # Convert the GUID to bytes in Windows format (.NET Guid.ToByteArray() format)
        # .NET Guid.ToByteArray() uses a "mixed-endian" format which corresponds to uuid.UUID().bytes_le
        try:
            root_key_guid = uuid.UUID(root_key.cn).bytes_le  # Use bytes_le to match .NET Guid.ToByteArray()
        except (ValueError, AttributeError):
            # If cn is not a valid UUID, try to parse it as a string
            root_key_guid = uuid.UUID(root_key.cn.replace('-', '')).bytes_le if '-' in str(root_key.cn) else uuid.UUID(str(root_key.cn)).bytes_le

        # Generate the KDF context (returns context and flag2)
        kdf_context, kdf_context_flag = GmsaPassword._generate_kdf_context(
            root_key_guid, l0_key_id,
            0xffffffff, 0xffffffff,
            0
        )
        
        # Generate the derived key (no label for L0)
        # not_sure is a list to simulate ref int in C#
        not_sure_ref = [kdf_context_flag]
        generate_derived_key = GmsaPassword._generate_derived_key(
            root_key.ms_kds_kdf_algorithm_id,
            root_key.ms_kds_kdf_param or b"",
            root_key.kdf_param_size,
            root_key.kds_root_key_data or b"",
            root_key.kds_root_key_data_size if root_key.kds_root_key_data else 0,
            kdf_context, len(kdf_context),
            not_sure_ref, b"", 0,  # No label for L0
            1,  # notsure_flag = 1 for L0
            generate_derived_key := bytearray(KDS_ROOT_KEY_DATA_SIZE_DEFAULT),
            KDS_ROOT_KEY_DATA_SIZE_DEFAULT, 0
        )
        
        l0_key = L0Key(root_key, l0_key_id, generate_derived_key)
        return l0_key
    
    @staticmethod
    def _generate_l1_key(security_descriptor: bytes, sd_size: int, l0_key: L0Key,
                        l1_key_id: int) -> Tuple[bytes, Optional[bytes]]:
        """
        Generates the L1 key.

        Returns:
            Tuple containing (primary derived key, secondary derived key)
        """
        # Convert the GUID to bytes in Windows format (.NET Guid.ToByteArray() format)
        try:
            root_key_guid = uuid.UUID(l0_key.cn).bytes_le  # Use bytes_le to match .NET Guid.ToByteArray()
        except (ValueError, AttributeError):
            root_key_guid = uuid.UUID(l0_key.cn.replace('-', '')).bytes_le if '-' in str(l0_key.cn) else uuid.UUID(str(l0_key.cn)).bytes_le
        derived_key = bytearray(KDS_ROOT_KEY_DATA_SIZE_DEFAULT)
        derived_key2 = None

        # Generate the KDF context (returns context and flag2)
        kdf_context, kdf_context_flag = GmsaPassword._generate_kdf_context(
            root_key_guid, int(l0_key.l0_key_id),
            0x1f, 0xffffffff, 1
        )

        # Modify the context with the security descriptor
        kdf_context_modified = bytearray(len(kdf_context) + sd_size)
        kdf_context_modified[:len(kdf_context)] = kdf_context
        kdf_context_modified[len(kdf_context):] = security_descriptor
        
        # Generate the first derived key (no label for L1)
        not_sure_ref = [kdf_context_flag]
        derived_key = GmsaPassword._generate_derived_key(
            l0_key.ms_kds_kdf_algorithm_id,
            l0_key.ms_kds_kdf_param or b"",
            l0_key.kdf_param_size,
            l0_key.kds_root_key_data or b"",
            64,
            kdf_context_modified, len(kdf_context_modified),
            not_sure_ref, b"", 0,  # No label for L1
            1,  # notsure_flag = 1 for L1 first call
            derived_key,
            KDS_ROOT_KEY_DATA_SIZE_DEFAULT, 0
        )
        
        # Generate the secondary key if needed
        if l1_key_id != 31:
            kdf_context_copy = bytearray(kdf_context)
            # Modify the context at the flag index as in the C# code
            if kdf_context_flag < len(kdf_context_copy):
                kdf_context_copy[kdf_context_flag] = (kdf_context_copy[kdf_context_flag] - 1) & 0xFF
            generated_derived_key = derived_key.copy()

            not_sure_ref2 = [kdf_context_flag]
            derived_key = GmsaPassword._generate_derived_key(
                l0_key.ms_kds_kdf_algorithm_id, l0_key.ms_kds_kdf_param or b"",
                l0_key.kdf_param_size, generated_derived_key,
                64, kdf_context_copy, len(kdf_context_copy),
                not_sure_ref2, b"", 0,  # No label
                31 - l1_key_id,  # notsure_flag = 31 - l1_key_id
                derived_key,
                KDS_ROOT_KEY_DATA_SIZE_DEFAULT, 0
            )
        
        if l1_key_id > 0:
            kdf_context_copy = bytearray(kdf_context)
            # Modify the context at the flag index as in the C# code
            if kdf_context_flag < len(kdf_context_copy):
                kdf_context_copy[kdf_context_flag] = (l1_key_id - 1) & 0xFF
            derived_key2 = bytearray(KDS_ROOT_KEY_DATA_SIZE_DEFAULT)
            generated_derived_key = derived_key.copy()
            
            not_sure_ref3 = [kdf_context_flag]
            derived_key2 = GmsaPassword._generate_derived_key(
                l0_key.ms_kds_kdf_algorithm_id, l0_key.ms_kds_kdf_param or b"",
                l0_key.kdf_param_size, generated_derived_key,
                64, kdf_context_copy, len(kdf_context_copy),
                not_sure_ref3, b"", 0,  # No label
                1,  # notsure_flag = 1
                derived_key2,
                KDS_ROOT_KEY_DATA_SIZE_DEFAULT, 0
            )
        
        return bytes(derived_key), bytes(derived_key2) if derived_key2 else None
    
    @staticmethod
    def _generate_l2_key(l0_key: L0Key, l1_derived_key: bytes, l1_key_id: int, l2_key_id: int) -> bytes:
        """
        Generates the L2 key.

        Returns:
            Generated L2 key
        """
        # Convert the GUID to bytes in Windows format (.NET Guid.ToByteArray() format)
        try:
            root_key_guid = uuid.UUID(l0_key.cn).bytes_le  # Use bytes_le to match .NET Guid.ToByteArray()
        except (ValueError, AttributeError):
            root_key_guid = uuid.UUID(l0_key.cn.replace('-', '')).bytes_le if '-' in str(l0_key.cn) else uuid.UUID(str(l0_key.cn)).bytes_le
        derived_key = bytearray(KDS_ROOT_KEY_DATA_SIZE_DEFAULT)

        # Generate the KDF context (returns context and flag2)
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
            not_sure_ref, b"", 0,  # No label for L2
            some_flag,  # notsure_flag = 32 - l2_key_id
            derived_key,
            KDS_ROOT_KEY_DATA_SIZE_DEFAULT, 0
        )
        
        return bytes(derived_key)
    
    @staticmethod
    def _compute_sid_private_key(l0_key: L0Key, security_descriptor: bytes, sd_size: int,
                                l1_key_id: int, l2_key_id: int, access_check_failed: int) -> Tuple[Optional[bytes], Optional[bytes]]:
        """
        Computes the SID private key.

        Returns:
            Tuple containing (L1 key, L2 key)
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
        Formats the return blob.

        Returns:
            Tuple containing (GroupKeyEnvelope, size)
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
        Generates the GMSA password.

        Returns:
            Generated password
        """
        # Label: "GMSA PASSWORD" with null terminator UTF-16LE (2 bytes: 0x00 0x00)
        label_str = "GMSA PASSWORD"
        label = label_str.encode('utf-16le') + b'\x00\x00'  # Add UTF-16LE null terminator
        pwd_blob = bytearray(pwd_blob_size)
        
        # Parse the SID key result
        result = KdsUtils.parse_sid_key_result(gke, gke_size, msds_managed_password_id)
        
        l1_key = result['l1_key']
        l2_key = result['l2_key']
        l1_key_diff = result['l1_key_diff']
        l2_key_diff = result['l2_key_diff']
        new_l1_key_id = result['new_l1_key_id']
        new_l2_key_id = result['new_l2_key_id']
        
        # ClientComputeL2Key: update L1/L2 keys if needed
        if l1_key_diff > 0 or l2_key_diff > 0:
            # Extract the root key GUID
            from .msds_managed_password_id import MsdsManagedPasswordId
            # Convert the GUID to bytes in Windows format (.NET Guid.ToByteArray() format)
            try:
                root_key_guid = uuid.UUID(gke.root_key_identifier).bytes_le  # Use bytes_le to match .NET Guid.ToByteArray()
            except (ValueError, AttributeError):
                root_key_guid = uuid.UUID(gke.root_key_identifier.replace('-', '')).bytes_le if '-' in str(gke.root_key_identifier) else uuid.UUID(str(gke.root_key_identifier)).bytes_le
            kdf_param = gke.kdf_parameters if gke.kdf_parameters and len(gke.kdf_parameters) > 0 else None
            
            # Update L1 if needed
            if l1_key_diff > 0:
                # Generate the KDF context for L1
                kdf_context_l1, kdf_context_flag_l1 = GmsaPassword._generate_kdf_context(
                    root_key_guid, gke.l0_index,
                    new_l1_key_id, 0xffffffff,
                    1
                )
                
                # Generate the derived key to update L1
                not_sure_ref_l1 = [kdf_context_flag_l1]
                l1_key = GmsaPassword._generate_derived_key(
                    gke.kdf_algorithm, kdf_param or b"",
                    len(kdf_param) if kdf_param else 0, l1_key,
                    64, kdf_context_l1, len(kdf_context_l1),
                    not_sure_ref_l1, b"", 0,  # No label
                    l1_key_diff,  # notsure_flag = l1_key_diff
                    bytearray(KDS_ROOT_KEY_DATA_SIZE_DEFAULT),
                    KDS_ROOT_KEY_DATA_SIZE_DEFAULT, 0
                )
                l1_key = bytes(l1_key)
            
            # Update L1 with L2 if needed (as in the C# code)
            if msds_managed_password_id is None or gke.l1_index <= MsdsManagedPasswordId(msds_managed_password_id).l1_index:
                if gke.cb_l2_key > 0:
                    l1_key = l2_key
            
            # Update L2 if needed
            if l2_key_diff > 0:
                # Determine "something" as in the C# code
                if msds_managed_password_id is None:
                    something = gke.l1_index
                else:
                    msds_pwd_id = MsdsManagedPasswordId(msds_managed_password_id)
                    something = msds_pwd_id.l1_index
                
                # Generate the KDF context for L2
                kdf_context_l2, kdf_context_flag_l2 = GmsaPassword._generate_kdf_context(
                    root_key_guid, gke.l0_index,
                    something, new_l2_key_id,
                    2
                )
                
                # Initialize l2_key if null
                if l2_key is None:
                    l2_key = bytearray(KDS_ROOT_KEY_DATA_SIZE_DEFAULT)
                else:
                    l2_key = bytearray(l2_key)
                
                # Generate the derived key to update L2
                not_sure_ref_l2 = [kdf_context_flag_l2]
                l2_key = GmsaPassword._generate_derived_key(
                    gke.kdf_algorithm, kdf_param or b"",
                    len(kdf_param) if kdf_param else 0, l1_key,
                    64, kdf_context_l2, len(kdf_context_l2),
                    not_sure_ref_l2, b"", 0,  # No label
                    l2_key_diff,  # notsure_flag = l2_key_diff
                    l2_key,
                    KDS_ROOT_KEY_DATA_SIZE_DEFAULT, 0
                )
                l2_key = bytes(l2_key)
        
        # Final password generation (with label "GMSA PASSWORD\x0")
        flag_ref = [0]  # flag is initialized to 0 in the C# code
        pwd_blob = GmsaPassword._generate_derived_key(
            gke.kdf_algorithm, gke.kdf_parameters or b"",
            len(gke.kdf_parameters) if gke.kdf_parameters else 0, l2_key if l2_key else l1_key,
            64, sid, len(sid),
            flag_ref, label, len(label),  # Label "GMSA PASSWORD\x0" for the final password blob
            1,  # notsure_flag = 1 for the final password blob
            pwd_blob, pwd_blob_size, 0
        )
        
        return bytes(pwd_blob)
    
    @staticmethod
    def _parse_hash_from_kdf_param(kdf_param: bytes):
        """Parse the hash algorithm name from the KDF param blob."""
        if kdf_param and len(kdf_param) > 0:
            try:
                for name, func, size in [
                    ('SHA512', hashlib.sha512, 64),
                    ('SHA384', hashlib.sha384, 48),
                    ('SHA256', hashlib.sha256, 32),
                    ('SHA1', hashlib.sha1, 20),
                ]:
                    if name.encode('utf-16le') in kdf_param:
                        return func, size
            except Exception:
                pass
        return hashlib.sha256, 32

    @staticmethod
    def _generate_kdf_context(root_key_guid: bytes, context_init: int, context_init2: int,
                             context_init3: int, flag: int) -> Tuple[bytes, int]:
        """
        Generates a KDF context (replica of kdscli.dll GenerateKDFContext).

        Args:
            root_key_guid: Root key GUID (16 bytes)
            context_init: Context initialization value 1
            context_init2: Context initialization value 2 (long)
            context_init3: Context initialization value 3 (long)
            flag: Initialization flag

        Returns:
            Tuple containing (KDF context, flag2)
        """
        # MS-GKDI spec: the context is built as:
        # RKID(16) || L0_int32_LE(4) || L1_int32_LE(4) || L2_int32_LE(4) = 28 bytes
        # ALL integers are 32-bit little-endian (not int64!)
        context_data = bytearray()
        context_data.extend(root_key_guid[:16])  # RKID (16 bytes)
        context_data.extend(struct.pack('<I', context_init & 0xFFFFFFFF))  # int32 LE (4 bytes)
        context_data.extend(struct.pack('<I', context_init2 & 0xFFFFFFFF))  # int32 LE (4 bytes)
        context_data.extend(struct.pack('<I', context_init3 & 0xFFFFFFFF))  # int32 LE (4 bytes)
        # Total: 28 bytes

        # flag2 = byte offset in the context of the counter to decrement between iterations
        # flag=0 (L0): points to contextInit (int32 at offset 16)
        # flag=1 (L1): points to contextInit2 (int32 at offset 20)
        # flag=2 (L2): points to contextInit3 (int32 at offset 24)
        if flag == 0:
            flag2 = 16
        elif flag == 1:
            flag2 = 20
        elif flag == 2:
            flag2 = 24
        else:
            flag2 = 16

        return bytes(context_data), flag2
    
    @staticmethod
    def _generate_derived_key(kdf_algorithm_id: str, kdf_param: bytes, kdf_param_size: int,
                             pb_secret: bytes, cb_secret: int, context: bytes, context_size: int,
                             not_sure: list, label: bytes, label_size: int,
                             notsure_flag: int, pb_derived_key: bytearray, cb_derived_key: int,
                             always_zero: int) -> bytearray:
        """
        Generates a derived key using SP800-108 CTR HMAC (replica of kdscli.dll GenerateDerivedKey).

        Args:
            kdf_algorithm_id: KDF algorithm identifier (e.g., "SP800_108_CTR_HMAC")
            kdf_param: Optional KDF parameters
            kdf_param_size: Size of KDF parameters
            pb_secret: Input secret key
            cb_secret: Size of the secret key
            context: KDF context
            context_size: Size of the context
            not_sure: List with a single element (reference, can be modified) [flag]
            label: KDF label (e.g., "GMSA PASSWORD" + null byte in UTF-16LE)
            label_size: Size of the label
            notsure_flag: Number of iterations to perform (this is the actual iteration parameter!)
            pb_derived_key: Output buffer for the derived key
            cb_derived_key: Desired size of the derived key
            always_zero: Always zero

        Returns:
            Generated derived key
        """
        if kdf_algorithm_id == "SP800_108_CTR_HMAC":
            # SP800-108 CTR HMAC implementation according to the Windows kdscli.dll implementation
            # Microsoft format: [i]_2 || Label || 0x00 || Context || [L]_2
            # Reference: https://github.com/microsoft/referencesource/blob/master/System.Web/Security/Cryptography/SP800_108.cs

            # Determine the hash algorithm from kdf_param
            hash_func, hash_size = GmsaPassword._parse_hash_from_kdf_param(kdf_param)
            num_blocks = (cb_derived_key + hash_size - 1) // hash_size

            # Extract the HMAC key from the secret
            hmac_key = pb_secret[:cb_secret] if cb_secret > 0 else pb_secret

            # MS-GKDI: when the label is empty, kdscli.dll uses "KDS service\0" in UTF-16LE
            if label_size > 0:
                label_bytes = label[:label_size]
            else:
                label_bytes = "KDS service\0".encode('utf-16le')
                label_size = len(label_bytes)
            context_bytes = context[:context_size] if context_size > 0 else b""

            # notsure_flag = number of KDF iterations
            # Each iteration uses the previous result as the new secret key
            # and decrements the context at index not_sure[0]
            current_secret = hmac_key
            current_context = bytearray(context_bytes)

            iterations = notsure_flag if notsure_flag > 0 else 1

            iteration_derived = None

            for iteration in range(iterations):
                iteration_derived = bytearray()
                for i in range(num_blocks):
                    # [i]_2: Counter 32-bit big-endian, starts at 1
                    counter_bytes = struct.pack('>I', i + 1)

                    # [L]_2: Length in BITS (32-bit big-endian)
                    length_in_bits = cb_derived_key * 8
                    length_bytes = struct.pack('>I', length_in_bits)

                    # Format: [i] || Label || 0x00 || Context || [L]
                    if label_size > 0:
                        input_block = counter_bytes + label_bytes + b'\x00' + bytes(current_context) + length_bytes
                    else:
                        input_block = counter_bytes + b'\x00' + bytes(current_context) + length_bytes

                    k_i = hmac.new(current_secret, input_block, hash_func).digest()
                    iteration_derived.extend(k_i)

                # For the next iteration
                if iteration < iterations - 1:
                    current_secret = iteration_derived[:cb_secret] if cb_secret > 0 else iteration_derived[:hash_size]
                    if len(current_context) > 0 and not_sure and len(not_sure) > 0 and not_sure[0] < len(current_context):
                        current_context[not_sure[0]] = (current_context[not_sure[0]] - 1) & 0xFF

            if iteration_derived is None:
                iteration_derived = bytearray(cb_derived_key)
            result = iteration_derived[:cb_derived_key]
            pb_derived_key[:len(result)] = result

            return pb_derived_key
        else:
            # Fallback: use simple HMAC for other algorithms
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
        Converts a SID to bytes in Windows binary format.

        Windows SID binary format:
        - 1 byte: Revision (always 1)
        - 1 byte: Number of sub-authorities
        - 6 bytes: Authority identifier (48 bits, big-endian)
        - 4 bytes per sub-authority (32 bits, little-endian)

        Args:
            sid: SID as a string (e.g., "S-1-5-21-4163040651-2381858556-3943169962-1104")

        Returns:
            SID as bytes in Windows binary format
        """
        # Parse the SID string (format: S-1-5-21-...)
        parts = sid.split('-')
        if len(parts) < 3 or parts[0] != 'S':
            raise ValueError(f"Invalid SID: {sid}")
        
        revision = int(parts[1])
        num_sub_auths = len(parts) - 3  # Number of sub-authorities

        # Authority identifier (48 bits, big-endian)
        # Parts 2 to 7 form the authority identifier
        # But generally only part 2 (5) is used
        # and the others are sub-authorities
        authority_value = int(parts[2])
        
        # Build the binary SID
        sid_bytes = bytearray()
        sid_bytes.append(revision)  # Revision (1 byte)
        sid_bytes.append(num_sub_auths)  # Number of sub-authorities (1 byte)

        # Authority identifier (6 bytes, big-endian)
        # The 48 bits are stored in big-endian over 6 bytes
        authority_bytes = struct.pack('>Q', authority_value)[2:]  # Take the last 6 bytes
        sid_bytes.extend(authority_bytes)
        
        # Sub-authorities (4 bytes each, little-endian)
        for i in range(3, len(parts)):
            sub_auth = int(parts[i])
            sid_bytes.extend(struct.pack('<I', sub_auth))  # Little-endian 32-bit
        
        return bytes(sid_bytes)
