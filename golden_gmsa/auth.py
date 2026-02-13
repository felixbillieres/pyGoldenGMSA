"""
Module for advanced authentication management (PTH, PTT).
"""

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)


class AuthMethod:
    """Class to manage different authentication methods."""
    
    def __init__(self, 
                 username: Optional[str] = None,
                 password: Optional[str] = None,
                 nt_hash: Optional[str] = None,
                 lm_hash: Optional[str] = None,
                 aes_key: Optional[str] = None,
                 ccache: Optional[str] = None,
                 use_kerberos: bool = False):
        """
        Initialize authentication method.
        
        Args:
            username: Username
            password: Plaintext password
            nt_hash: NT hash (Pass-the-Hash)
            lm_hash: LM hash (optional, used with NTLM)
            aes_key: Kerberos AES key
            ccache: Kerberos ccache file (Pass-the-Ticket)
            use_kerberos: Force Kerberos usage
        """
        self.username = username
        self.password = password
        self.nt_hash = nt_hash
        self.lm_hash = lm_hash or 'aad3b435b51404eeaad3b435b51404ee'  # Empty LM hash
        self.aes_key = aes_key
        self.ccache = ccache
        self.use_kerberos = use_kerberos
        
        # Determine authentication mode
        self.auth_mode = self._determine_auth_mode()
        
    def _determine_auth_mode(self) -> str:
        """
        Determine authentication mode based on provided parameters.
        
        Returns:
            Authentication mode: 'password', 'ntlm', 'kerberos', 'ccache'
        """
        if self.ccache:
            return 'ccache'
        elif self.nt_hash:
            return 'ntlm'
        elif self.aes_key or self.use_kerberos:
            return 'kerberos'
        elif self.password:
            return 'password'
        else:
            return 'anonymous'
    
    def get_hashes_string(self) -> str:
        """
        Return hashes in impacket expected format (LM:NT).
        
        Returns:
            String in "lmhash:nthash" format
        """
        return f"{self.lm_hash}:{self.nt_hash}"
    
    def setup_kerberos_ccache(self):
        """Configure Kerberos ccache file."""
        if self.ccache and os.path.exists(self.ccache):
            os.environ['KRB5CCNAME'] = self.ccache
            logger.info(f"Using Kerberos ccache: {self.ccache}")
        elif self.ccache:
            logger.warning(f"Kerberos ccache file not found: {self.ccache}")
    
    def __str__(self) -> str:
        """String representation of authentication."""
        if self.auth_mode == 'ccache':
            return f"Kerberos (ccache: {self.ccache})"
        elif self.auth_mode == 'ntlm':
            return f"NTLM (NT hash: {self.nt_hash[:8]}...)"
        elif self.auth_mode == 'kerberos':
            return "Kerberos"
        elif self.auth_mode == 'password':
            return "Password"
        else:
            return "Anonymous"


def create_ldap3_connection(domain: str, auth: AuthMethod, dc_ip: Optional[str] = None, 
                            use_ssl: bool = False):
    """
    Create LDAP3 connection with PTH/PTT support.
    
    Args:
        domain: Domain FQDN
        auth: Authentication method
        dc_ip: DC IP address (optional)
        use_ssl: Use SSL/TLS
        
    Returns:
        LDAP3 connection object
    """
    try:
        from ldap3 import Server, Connection, NTLM, SIMPLE, Tls
        import ssl
        
        target = dc_ip if dc_ip else domain
        port = 636 if use_ssl else 389
        
        # TLS configuration
        tls = None
        if use_ssl:
            tls = Tls(validate=ssl.CERT_NONE)
        
        # Create server
        server = Server(target, port=port, use_ssl=use_ssl, tls=tls, get_info='ALL')
        
        # Determine authentication method
        if auth.auth_mode == 'ntlm':
            # Pass-the-Hash
            username = f"{domain}\\{auth.username}"
            conn = Connection(
                server,
                user=username,
                password=auth.get_hashes_string(),
                authentication=NTLM,
                auto_bind=True
            )
            logger.info(f"Authenticated via NTLM with NT hash: {auth.username}")
            
        elif auth.auth_mode == 'ccache' or auth.auth_mode == 'kerberos':
            # Pass-the-Ticket or Kerberos
            auth.setup_kerberos_ccache()
            
            # For Kerberos, use SASL with GSSAPI
            # Note: Requires python-gssapi
            try:
                from ldap3 import SASL, KERBEROS
                conn = Connection(
                    server,
                    authentication=SASL,
                    sasl_mechanism=KERBEROS,
                    auto_bind=True
                )
                logger.info("Authenticated with Kerberos")
            except ImportError:
                logger.error("python-gssapi not installed. Install with: pip install python-gssapi")
                raise
                
        else:
            # Password authentication
            username = f"{auth.username}@{domain}"
            conn = Connection(
                server,
                user=username,
                password=auth.password,
                authentication=SIMPLE,
                auto_bind=True
            )
            logger.info(f"Authenticated with password: {auth.username}")
        
        return conn
        
    except ImportError:
        logger.error("ldap3 not installed. Install with: pip install ldap3")
        raise
    except Exception as e:
        logger.error(f"LDAP3 connection failed: {e}")
        raise


def create_impacket_ldap_connection(domain: str, auth: AuthMethod, dc_ip: Optional[str] = None):
    """
    Create LDAP connection via impacket with PTH/PTT support.
    
    Args:
        domain: Domain FQDN
        auth: Authentication method
        dc_ip: DC IP address (optional)
        
    Returns:
        Impacket LDAP connection object
    """
    try:
        from impacket.ldap import ldap as impacket_ldap
        from impacket.ldap import ldapasn1
        
        target = dc_ip if dc_ip else domain
        
        # Configure Kerberos if necessary
        if auth.auth_mode in ['kerberos', 'ccache']:
            auth.setup_kerberos_ccache()
        
        # Create LDAP connection
        ldap_conn = impacket_ldap.LDAPConnection(
            f'ldap://{target}',
            baseDN=f'DC={",DC=".join(domain.split("."))}',
            dstIp=dc_ip
        )
        
        # Authentication
        if auth.auth_mode == 'ntlm':
            # Pass-the-Hash
            ldap_conn.login(
                user=auth.username,
                password='',
                domain=domain,
                lmhash=auth.lm_hash,
                nthash=auth.nt_hash
            )
            logger.info(f"Impacket LDAP: Authenticated via NTLM with NT hash")
            
        elif auth.auth_mode in ['kerberos', 'ccache']:
            # Kerberos
            ldap_conn.kerberosLogin(
                user=auth.username,
                password='',
                domain=domain,
                lmhash='',
                nthash='',
                aesKey=auth.aes_key,
                kdcHost=dc_ip
            )
            logger.info(f"Impacket LDAP: Authenticated with Kerberos")
            
        else:
            # Password
            ldap_conn.login(
                user=auth.username,
                password=auth.password,
                domain=domain
            )
            logger.info(f"Impacket LDAP: Authenticated with password")
        
        return ldap_conn
        
    except ImportError:
        logger.error("Impacket not installed properly")
        raise
    except Exception as e:
        logger.error(f"Impacket LDAP connection failed: {e}")
        raise

