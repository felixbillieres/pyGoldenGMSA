"""
Utilities for LDAP operations with Active Directory.
"""

import logging
import socket
from typing import List, Optional, Dict, Any
import ldap
import ldap.filter

logger = logging.getLogger(__name__)


class LdapConnection:
    """
    Class to manage LDAP connection with credentials.
    Supports: Password, Pass-the-Hash (PTH), Pass-the-Ticket (PTT)
    """
    
    def __init__(self, domain: str, username: Optional[str] = None, 
                 password: Optional[str] = None, use_ssl: bool = False,
                 dc_ip: Optional[str] = None,
                 nt_hash: Optional[str] = None,
                 lm_hash: Optional[str] = None,
                 aes_key: Optional[str] = None,
                 ccache: Optional[str] = None,
                 use_kerberos: bool = False):
        """
        Initialize LDAP connection.
        
        Args:
            domain: Domain name (FQDN)
            username: Username (format: user@domain.com or DOMAIN\\user)
            password: Password
            use_ssl: Use LDAPS (port 636)
            dc_ip: Domain controller IP address (optional)
            nt_hash: NTLM hash for Pass-the-Hash
            lm_hash: LM hash for Pass-the-Hash (optional)
            aes_key: AES key for Kerberos
            ccache: Kerberos ccache file for Pass-the-Ticket
            use_kerberos: Force Kerberos usage
        """
        # Normalize the domain to lowercase (case-insensitive)
        self.domain = domain.lower() if domain else domain
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.dc_ip = dc_ip
        self.nt_hash = nt_hash
        self.lm_hash = lm_hash
        self.aes_key = aes_key
        self.ccache = ccache
        self.use_kerberos = use_kerberos
        self.conn = None
        self._root_dse_cache = None
        self._use_advanced_auth = nt_hash or ccache or aes_key or use_kerberos
        self._is_ldap3 = False
        
    def connect(self):
        """Establish LDAP connection."""
        # If using PTH/PTT, use ldap3 or impacket
        if self._use_advanced_auth:
            self._connect_advanced()
        else:
            self._connect_simple()
    
    def _connect_simple(self):
        """Simple LDAP connection with python-ldap."""
        try:
            target = self.dc_ip if self.dc_ip else self.domain
            protocol = "ldaps" if self.use_ssl else "ldap"
            port = 636 if self.use_ssl else 389
            server_uri = f"{protocol}://{target}:{port}"
            
            logger.info(f"Connecting to {server_uri}...")
            
            self.conn = ldap.initialize(server_uri)
            self.conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
            self.conn.set_option(ldap.OPT_REFERRALS, 0)
            self.conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)
            
            if self.use_ssl:
                self.conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            
            if self.username and self.password:
                bind_dn = self._format_bind_dn(self.username)
                logger.info(f"Authenticating with {bind_dn}...")
                self.conn.simple_bind_s(bind_dn, self.password)
                logger.info("Authentication successful")
            else:
                logger.info("Anonymous connection...")
                self.conn.simple_bind_s("", "")
                
        except ldap.INVALID_CREDENTIALS:
            logger.error("Invalid credentials")
            raise Exception("Authentication failed: invalid credentials")
        except ldap.SERVER_DOWN:
            logger.error(f"Unable to reach server {target}")
            raise Exception(f"LDAP server unreachable: {target}")
        except Exception as ex:
            logger.error(f"LDAP connection error: {ex}")
            raise
    
    def _connect_advanced(self):
        """Advanced LDAP connection with PTH/PTT via impacket."""
        try:
            from impacket.ldap import ldap as impacket_ldap
            from impacket.ldap import ldapasn1
            
            target = self.dc_ip if self.dc_ip else self.domain
            
            # Setup Kerberos ccache if needed
            if self.ccache:
                import os
                if os.path.exists(self.ccache):
                    os.environ['KRB5CCNAME'] = self.ccache
                    logger.info(f"Using Kerberos ccache: {self.ccache}")
            
            # Determine base DN
            base_dn = ','.join([f'DC={part}' for part in self.domain.split('.')])
            
            # Create connection
            logger.info(f"Connecting to {target} via impacket LDAP...")
            
            self.conn = impacket_ldap.LDAPConnection(
                f'ldap://{target}',
                base_dn,
                self.dc_ip
            )
            
            # Authenticate based on method
            if self.nt_hash:
                # Pass-the-Hash with NTLM
                logger.info(f"Authenticating with NTLM hash for user {self.username}...")
                lm_hash = self.lm_hash or 'aad3b435b51404eeaad3b435b51404ee'
                self.conn.login(
                    user=self.username,
                    password='',
                    domain=self.domain,
                    lmhash=lm_hash,
                    nthash=self.nt_hash
                )
                logger.info("Authentication successful (Pass-the-Hash)")
                
            elif self.use_kerberos or self.aes_key or self.ccache:
                # Kerberos authentication
                logger.info(f"Authenticating with Kerberos for user {self.username}...")
                self.conn.kerberosLogin(
                    user=self.username,
                    password='',
                    domain=self.domain,
                    lmhash='',
                    nthash='',
                    aesKey=self.aes_key or '',
                    kdcHost=self.dc_ip or self.domain
                )
                logger.info("Authentication successful (Kerberos)")
            else:
                # Fallback to password
                logger.info(f"Authenticating with password for user {self.username}...")
                self.conn.login(
                    user=self.username,
                    password=self.password,
                    domain=self.domain
                )
                logger.info("Authentication successful (Password)")
            
            # Mark as impacket connection
            self._is_ldap3 = True  # Using same flag for compatibility
            
        except ImportError as e:
            logger.error("Impacket required for PTH/PTT. Install with: pip install impacket")
            raise
        except Exception as ex:
            logger.error(f"Advanced LDAP connection error: {ex}")
            raise
            
    def _format_bind_dn(self, username: str) -> str:
        """
        Format the bind DN according to the provided format.

        Args:
            username: Username

        Returns:
            Formatted DN
        """
        if '@' in username:
            return username
        elif '\\' in username:
            return username.split('\\')[1] + '@' + self.domain
        else:
            return username + '@' + self.domain
            
    def disconnect(self):
        """Close LDAP connection."""
        if self.conn:
            try:
                if self._is_ldap3:
                    # For impacket LDAP
                    if hasattr(self.conn, 'close'):
                        self.conn.close()
                    elif hasattr(self.conn, 'unbind'):
                        self.conn.unbind()
                else:
                    # For python-ldap
                    self.conn.unbind_s()
                logger.info("LDAP connection closed")
            except:
                pass
                
    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()


class LdapUtils:
    """
    Utility class for LDAP operations with Active Directory.
    """
    
    # Global variable to store the current connection
    _current_connection: Optional[LdapConnection] = None
    
    @staticmethod
    def set_connection(connection: LdapConnection):
        """
        Set the LDAP connection to use for all operations.

        Args:
            connection: LdapConnection instance
        """
        LdapUtils._current_connection = connection
        
    @staticmethod
    def get_connection() -> Optional[LdapConnection]:
        """
        Return the current LDAP connection.

        Returns:
            LdapConnection instance or None
        """
        return LdapUtils._current_connection
    
    @staticmethod
    def find_in_config_partition(domain_fqdn: str, ldap_filter: str, attributes: List[str]) -> List[Dict[str, Any]]:
        """
        Search in the configuration partition.

        Args:
            domain_fqdn: Domain FQDN
            ldap_filter: LDAP filter
            attributes: List of attributes to retrieve

        Returns:
            List of search results

        Raises:
            Exception: If the search fails
        """
        config_naming_context = LdapUtils._get_config_naming_context(domain_fqdn)
        return LdapUtils._perform_ldap_search(domain_fqdn, config_naming_context, ldap_filter, attributes)
    
    @staticmethod
    def find_in_domain(domain_fqdn: str, ldap_filter: str, attributes: List[str]) -> List[Dict[str, Any]]:
        """
        Search in the domain.

        Args:
            domain_fqdn: Domain FQDN
            ldap_filter: LDAP filter
            attributes: List of attributes to retrieve

        Returns:
            List of search results

        Raises:
            Exception: If the search fails
        """
        default_naming_context = LdapUtils._get_default_naming_context(domain_fqdn)
        return LdapUtils._perform_ldap_search(domain_fqdn, default_naming_context, ldap_filter, attributes)
    
    @staticmethod
    def get_root_dse(domain_fqdn: str = None) -> Dict[str, Any]:
        """
        Retrieve the RootDSE information.

        Args:
            domain_fqdn: Domain FQDN (optional if a connection is active)

        Returns:
            Dictionary containing the RootDSE information
        """
        try:
            conn_obj = LdapUtils._current_connection
            
            if conn_obj and conn_obj.conn:
                if conn_obj._root_dse_cache:
                    return conn_obj._root_dse_cache
                
                # Check if using impacket (marked as _is_ldap3 for compatibility)
                if hasattr(conn_obj, '_is_ldap3') and conn_obj._is_ldap3:
                    # Use impacket LDAP to get RootDSE
                    from impacket.ldap import ldapasn1 as ldapasn1_impacket
                    search_results = conn_obj.conn.search(
                        searchFilter='(objectClass=*)',
                        attributes=['*'],
                        searchBase='',
                        scope=0  # BASE scope
                    )

                    root_dse = {}
                    if search_results:
                        for item in search_results:
                            if not isinstance(item, ldapasn1_impacket.SearchResultEntry):
                                continue
                            for attribute in item['attributes']:
                                attr_name = str(attribute['type'])
                                attr_values = []
                                for val in attribute['vals']:
                                    attr_values.append(val.asOctets())
                                root_dse[attr_name] = attr_values
                            break  # Only need first entry

                    if root_dse:
                        conn_obj._root_dse_cache = root_dse
                        return root_dse
                    else:
                        raise Exception("Unable to retrieve RootDSE information")
                else:
                    result = conn_obj.conn.search_s("", ldap.SCOPE_BASE, "(objectClass=*)")
                    if result and len(result) > 0:
                        conn_obj._root_dse_cache = result[0][1]
                        return conn_obj._root_dse_cache
                    else:
                        raise Exception("Unable to retrieve RootDSE information")
            else:
                if not domain_fqdn:
                    raise ValueError("domain_fqdn required if no active connection")
                    
                domain_escaped = ldap.filter.escape_filter_chars(domain_fqdn)
                server_uri = f"ldap://{domain_escaped}"
                
                conn = ldap.initialize(server_uri)
                conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
                conn.set_option(ldap.OPT_REFERRALS, 0)
                
                result = conn.search_s("", ldap.SCOPE_BASE, "(objectClass=*)")
                conn.unbind()
                
                if result and len(result) > 0:
                    return result[0][1]
                else:
                    raise Exception("Unable to retrieve RootDSE information")
                
        except Exception as ex:
            logger.error(f"Error retrieving RootDSE: {ex}")
            raise
    
    @staticmethod
    def get_current_domain() -> str:
        """
        Determine the current domain using system information or the active connection.

        Returns:
            Current domain name (normalized to lowercase)
        """
        try:
            conn_obj = LdapUtils._current_connection
            if conn_obj:
                return conn_obj.domain
                
            hostname = socket.getfqdn()
            if '.' in hostname:
                domain = hostname.split('.', 1)[1]
                return domain.lower() if domain else domain
            
            return hostname.lower() if hostname else hostname
            
        except Exception as ex:
            logger.warning(f"Unable to determine the current domain: {ex}")
            return "localhost"
    
    @staticmethod
    def get_current_forest() -> str:
        """
        Determine the current forest.

        Returns:
            Current forest name
        """
        return LdapUtils.get_current_domain()
    
    @staticmethod
    def _get_default_naming_context(domain_name: str) -> str:
        """
        Retrieve the default naming context.

        Args:
            domain_name: Domain name

        Returns:
            Default naming context
        """
        root_dse = LdapUtils.get_root_dse(domain_name)
        
        # Try different case variations
        for key in ['defaultNamingContext', 'DefaultNamingContext', 'defaultnamingcontext']:
            if key in root_dse and root_dse[key]:
                value = root_dse[key][0]
                if isinstance(value, bytes):
                    return value.decode('utf-8')
                return str(value)
        
        # Fallback: construct from domain name
        logger.warning(f"defaultNamingContext not found in RootDSE, constructing from domain name")
        return ','.join([f'DC={part}' for part in domain_name.split('.')])
    
    @staticmethod
    def _get_config_naming_context(domain_name: str) -> str:
        """
        Retrieve the configuration naming context.

        Args:
            domain_name: Domain name

        Returns:
            Configuration naming context
        """
        root_dse = LdapUtils.get_root_dse(domain_name)
        
        # Try different case variations
        for key in ['configurationNamingContext', 'ConfigurationNamingContext', 'configurationnamingcontext']:
            if key in root_dse and root_dse[key]:
                value = root_dse[key][0]
                if isinstance(value, bytes):
                    return value.decode('utf-8')
                return str(value)
        
        # Fallback: construct from domain name
        logger.warning(f"configurationNamingContext not found in RootDSE, constructing from domain name")
        dc_parts = ','.join([f'DC={part}' for part in domain_name.split('.')])
        return f'CN=Configuration,{dc_parts}'
    
    @staticmethod
    def _perform_ldap3_search(conn, search_base: str, ldap_filter: str, attributes: List[str]) -> List[Dict[str, Any]]:
        """
        Perform LDAP search using impacket library.
        
        Args:
            conn: impacket LDAP Connection object
            search_base: Search base DN
            ldap_filter: LDAP filter
            attributes: List of attributes to retrieve
            
        Returns:
            List of search results in python-ldap compatible format
        """
        try:
            from impacket.ldap import ldapasn1 as ldapasn1_impacket

            # Perform search with impacket
            search_results = conn.search(
                searchFilter=ldap_filter,
                attributes=attributes,
                searchBase=search_base
            )

            # Convert impacket ASN1 results to python-ldap compatible format
            results = []

            if search_results:
                for item in search_results:
                    if not isinstance(item, ldapasn1_impacket.SearchResultEntry):
                        continue
                    attrs = {}
                    for attribute in item['attributes']:
                        attr_name = str(attribute['type'])
                        attr_values = []
                        for val in attribute['vals']:
                            attr_values.append(val.asOctets())
                        attrs[attr_name] = attr_values

                    if attrs:
                        results.append(attrs)

            if not results:
                logger.warning(f"No results found with LDAP filter: {ldap_filter}")
                return []

            return results

        except Exception as ex:
            logger.error(f"Error during impacket LDAP search in {search_base}: {ex}")
            raise
    
    @staticmethod
    def _perform_ldap_search(domain_fqdn: str, search_base: str, ldap_filter: str, attributes: List[str]) -> List[Dict[str, Any]]:
        """
        Perform an LDAP search.

        Args:
            domain_fqdn: Domain FQDN
            search_base: Search base
            ldap_filter: LDAP filter
            attributes: List of attributes to retrieve

        Returns:
            List of search results

        Raises:
            Exception: If the search fails
        """
        try:
            conn_obj = LdapUtils._current_connection
            
            # Check if using ldap3 for PTH/PTT
            if conn_obj and hasattr(conn_obj, '_is_ldap3') and conn_obj._is_ldap3:
                return LdapUtils._perform_ldap3_search(conn_obj.conn, search_base, ldap_filter, attributes)
            
            if conn_obj and conn_obj.conn:
                conn = conn_obj.conn
                should_close = False
            else:
                domain_escaped = ldap.filter.escape_filter_chars(domain_fqdn)
                server_uri = f"ldap://{domain_escaped}"
                
                conn = ldap.initialize(server_uri)
                conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
                conn.set_option(ldap.OPT_REFERRALS, 0)
                conn.simple_bind_s("", "")
                should_close = True
            
            results = []
            page_size = 100
            
            page_control = ldap.controls.SimplePagedResultsControl(True, size=page_size, cookie='')
            
            while True:
                try:
                    msgid = conn.search_ext(
                        search_base,
                        ldap.SCOPE_SUBTREE,
                        ldap_filter,
                        attributes,
                        serverctrls=[page_control]
                    )
                    
                    result_type, result_data, result_msgid, result_controls = conn.result3(msgid)
                    
                    for dn, attrs in result_data:
                        if dn:
                            results.append(attrs)
                    
                    page_control = None
                    for control in result_controls:
                        if control.controlType == ldap.controls.SimplePagedResultsControl.controlType:
                            page_control = control
                            break
                    
                    if not page_control or not page_control.cookie:
                        break
                        
                except ldap.SIZELIMIT_EXCEEDED:
                    logger.warning("LDAP size limit exceeded")
                    break
                except Exception as ex:
                    logger.error(f"Error during LDAP search: {ex}")
                    break
            
            if should_close:
                conn.unbind()
            
            if not results:
                logger.warning(f"No results found with LDAP filter: {ldap_filter}")
                return []
            
            return results
            
        except Exception as ex:
            logger.error(f"Error during LDAP search in {search_base}: {ex}")
            raise
