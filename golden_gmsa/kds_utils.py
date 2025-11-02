"""
Utilitaires pour les opérations KDS (Key Distribution Service).
"""

import struct
import time
from typing import List
from .config import KEY_CYCLE_DURATION


class KdsUtils:
    """
    Classe utilitaire pour les opérations KDS.
    """
    
    @staticmethod
    def get_interval_id(timestamp: int) -> List[int]:
        """
        Calcule les identifiants d'intervalle pour un timestamp donné.
        
        Args:
            timestamp: Timestamp en nanosecondes
            
        Returns:
            Liste contenant [L0KeyID, L1KeyID, L2KeyID]
        """
        L1_KEY_ITERATION = 32
        L2_KEY_ITERATION = 32
        
        l0_key_id = timestamp // (KEY_CYCLE_DURATION * L2_KEY_ITERATION * L1_KEY_ITERATION)
        l1_key_id = (timestamp // (KEY_CYCLE_DURATION * L2_KEY_ITERATION)) & (L1_KEY_ITERATION - 1)
        l2_key_id = (timestamp // KEY_CYCLE_DURATION) & (L2_KEY_ITERATION - 1)
        
        return [l0_key_id, l1_key_id, l2_key_id]
    
    @staticmethod
    def get_current_interval_id(kds_key_cycle_duration: int = KEY_CYCLE_DURATION, some_flag: int = 0) -> tuple:
        """
        Calcule les identifiants d'intervalle actuels.
        
        Args:
            kds_key_cycle_duration: Durée du cycle de clé KDS
            some_flag: Flag optionnel pour ajuster le temps
            
        Returns:
            Tuple contenant (l0_key_id, l1_key_id, l2_key_id)
        """
        # Convertir le temps actuel en nanosecondes (équivalent à DateTime.Now.ToFileTimeUtc())
        current_time = int(time.time() * 10000000) + 116444736000000000
        
        if some_flag != 0:
            current_time += 3000000000  # Ajouter 5 minutes
        
        temp = current_time // kds_key_cycle_duration
        l0_key_id = temp // 1024
        l1_key_id = (temp // 32) & 31
        l2_key_id = temp & 31
        
        return l0_key_id, l1_key_id, l2_key_id
    
    @staticmethod
    def get_interval_start_time(kds_key_cycle_duration: int, l0_key_id: int, 
                              l1_key_id: int, l2_key_id: int) -> int:
        """
        Calcule le temps de début de l'intervalle.
        
        Args:
            kds_key_cycle_duration: Durée du cycle de clé KDS
            l0_key_id: Identifiant de clé L0
            l1_key_id: Identifiant de clé L1
            l2_key_id: Identifiant de clé L2
            
        Returns:
            Timestamp de début de l'intervalle
        """
        return kds_key_cycle_duration * (l2_key_id + 32 * (l1_key_id + 32 * l0_key_id))
    
    @staticmethod
    def parse_sid_key_result(gke, gke_size: int, msds_managed_password_id: bytes = None) -> dict:
        """
        Parse le résultat de la clé SID (équivalent à ParseSIDKeyResult du code C#).
        
        Args:
            gke: Group Key Envelope
            gke_size: Taille du GKE
            msds_managed_password_id: Identifiant de mot de passe géré
            
        Returns:
            Dictionnaire contenant les clés calculées
        """
        from .msds_managed_password_id import MsdsManagedPasswordId
        
        new_l2_key_id = 31
        l1_key_diff = 0
        l2_key_diff = 0
        new_l1_key_id = 0
        
        if msds_managed_password_id:
            msds_managed_password_id_obj = MsdsManagedPasswordId(msds_managed_password_id)
            l1_key_diff = gke.l1_index - msds_managed_password_id_obj.l1_index
            l2_key_diff = 32 - msds_managed_password_id_obj.l2_index
            
            if gke.cb_l2_key > 0:
                l1_key_diff -= 1
                if l1_key_diff > 0:
                    new_l1_key_id = gke.l1_index - 2
                if gke.l1_index <= msds_managed_password_id_obj.l1_index:
                    l2_key_diff = gke.l2_index - msds_managed_password_id_obj.l2_index
                    if l2_key_diff > 0:
                        new_l2_key_id = gke.l2_index - 1
            elif l1_key_diff > 0:
                new_l1_key_id = gke.l1_index - 1
        elif gke.l2_index == 0:
            l2_key_diff = 1
        
        l1_key = gke.l1_key if gke.cb_l1_key > 0 else None
        l2_key = gke.l2_key if gke.cb_l2_key > 0 else None
        public_key = None
        
        return {
            'l1_key': l1_key,
            'l2_key': l2_key,
            'public_key': public_key,
            'l1_key_diff': l1_key_diff,
            'l2_key_diff': l2_key_diff,
            'new_l1_key_id': new_l1_key_id,
            'new_l2_key_id': new_l2_key_id
        }
