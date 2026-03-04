#!/usr/bin/env python3
"""
Proton VPN Proxy Manager for Python requests library.

This module allows you to use Proton VPN proxies with the requests library.
It handles authentication, credential fetching, and automatic refresh.

Usage:
    from proton import ProtonProxyManager
    import requests
    
    # Initialize with your Proton credentials
    manager = ProtonProxyManager(
        uid="your-uid",
        access_token="your-access-token",
        refresh_token="your-refresh-token",  # Optional: enables auto token refresh
        proxy_host="server.protonvpn.com",  # Optional: specific server
        proxy_port=4443  # Optional: default is 4443
    )
    
    # Get a requests session configured with the proxy
    # Access token will automatically refresh if refresh_token is provided
    session = manager.get_session()
    response = session.get("https://api.ipify.org?format=json")
    print(response.json())
    
    # Or use with existing requests
    proxies = manager.get_proxies()
    response = requests.get("https://api.ipify.org?format=json", proxies=proxies)
    
    # Manually refresh access token if needed
    if manager.refresh_token:
        manager.refresh_access_token()
"""

import threading
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import requests
import json
import os


class ProtonProxyManager:
    """
    Manages Proton VPN proxy connections with automatic credential refresh.
    
    This class handles:
    - Fetching proxy credentials from Proton API
    - Automatic credential refresh before expiration
    - Automatic access token refresh using refresh token (if provided)
    - Thread-safe credential management
    - Integration with Python requests library
    """
    
    BASE_API_URL = "https://account.proton.me/api/"
    TOKEN_DURATION = 1200  # seconds (20 minutes)
    DEFAULT_PROXY_PORT = 4443
    DEFAULT_PROXY_SCHEME = "https"
    DEFAULT_CREDENTIALS_FILE = "proton_credentials.txt"
    CENTRALIZED_PROXY_CACHE_DURATION = 3600  # seconds (1 hour)
    ACCESS_TOKEN_REFRESH_BUFFER_SECONDS = 30  # refresh slightly early, not 5% early
    
    def __init__(
        self,
        uid: Optional[str] = None,
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
        proxy_host: Optional[str] = None,
        proxy_port: Optional[int] = None,
        token_duration: int = TOKEN_DURATION,
        credentials_file: Optional[str] = None,
    ):
        """
        Initialize the Proton Proxy Manager.
        
        Args:
            uid: Proton user ID (x-pm-uid). If not provided, will try to load from credentials_file
            access_token: Proton access token (Bearer token). If not provided, will try to load from credentials_file
            refresh_token: Optional refresh token for automatic token renewal. If not provided, will try to load from credentials_file
            proxy_host: Optional proxy server hostname (e.g., "server.protonvpn.com")
                       If not provided, you'll need to set it after connecting to a server
            proxy_port: Optional proxy server port (default: 4443)
            token_duration: Token duration in seconds (default: 1200)
            credentials_file: Path to credentials file (default: "proton_credentials.txt")
                             If provided, credentials will be loaded from and saved to this file
        """
        self.credentials_file = credentials_file or self.DEFAULT_CREDENTIALS_FILE
        access_token_expires_at: Optional[datetime] = None
        
        # Load any missing credentials from file.
        # This prevents accidentally nulling refreshToken when uid/access_token are
        # provided explicitly but refresh_token is omitted.
        if uid is None or access_token is None or refresh_token is None:
            file_creds = self._load_credentials_file()
            if file_creds:
                uid = uid or file_creds.get("uid")
                access_token = access_token or file_creds.get("accessToken")
                refresh_token = refresh_token or file_creds.get("refresh_token")
                access_token_expires_at = file_creds.get("access_token_expires_at")
        
        if not uid or not access_token:
            raise ValueError("uid and access_token must be provided either as parameters or in credentials_file")
        
        self.uid = uid
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port or self.DEFAULT_PROXY_PORT
        self.token_duration = token_duration
        
        self._credentials: Optional[Dict[str, Any]] = None
        self._credentials_expires_at: Optional[datetime] = None
        self._access_token_expires_at: Optional[datetime] = access_token_expires_at
        self._centralized_proxies_cache: Optional[List[Dict[str, Any]]] = None
        self._centralized_proxies_expires_at: Optional[datetime] = None
        # Re-entrant lock is required because credential flows can call token
        # validation while already inside a locked section.
        self._lock = threading.RLock()
        
        # Save initial credentials to file if credentials_file is set
        if self.credentials_file:
            self._save_credentials_file()
    
    def _load_credentials_file(self) -> Optional[Dict[str, Any]]:
        """
        Load credentials from file.
        
        Returns:
            Dictionary with uid, access_token, and optionally refresh_token, or None if file doesn't exist
        """
        if not self.credentials_file or not os.path.exists(self.credentials_file):
            return None
        
        try:
            with open(self.credentials_file, "r") as f:
                data = json.load(f)
                access_token_expires_at = None
                expires_at_raw = data.get("accessTokenExpiresAt")
                if isinstance(expires_at_raw, str) and expires_at_raw:
                    try:
                        # Stored in ISO 8601 format.
                        access_token_expires_at = datetime.fromisoformat(expires_at_raw)
                    except ValueError:
                        access_token_expires_at = None
                return {
                    "uid": data.get("uid"),
                    "accessToken": data.get("accessToken"),
                    "refresh_token": data.get("refreshToken"),
                    "access_token_expires_at": access_token_expires_at,
                }
        except (json.JSONDecodeError, IOError, KeyError):
            return None
    
    def _save_credentials_file(self, lock_held: bool = False) -> None:
        """
        Save current credentials to file.
        
        Args:
            lock_held: If True, assumes lock is already held and won't acquire it again
        """
        if not self.credentials_file:
            return
        
        try:
            # Only acquire lock if not already held
            if not lock_held:
                self._lock.acquire()
            
            try:
                data = {
                    "uid": self.uid,
                    "accessToken": self.access_token,
                    # Keep file schema stable: explicit null when refresh token is unavailable.
                    "refreshToken": self.refresh_token,
                    "accessTokenExpiresAt": (
                        self._access_token_expires_at.isoformat()
                        if self._access_token_expires_at is not None
                        else None
                    ),
                }
                
                # Write atomically using a temporary file
                temp_file = f"{self.credentials_file}.tmp"
                with open(temp_file, "w") as f:
                    json.dump(data, f, indent=2)
                
                # Replace original file
                os.replace(temp_file, self.credentials_file)
            finally:
                if not lock_held:
                    self._lock.release()
        except IOError:
            pass  # Silently fail if we can't write
        
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for API requests."""
        # Ensure access token is valid before making requests
        self._ensure_access_token()
        return {
            "x-pm-uid": self.uid,
            "x-pm-appversion": "browser-vpn@1.2.13",
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
    
    def _refresh_access_token(self) -> Dict[str, Any]:
        """
        Refresh the access token using the refresh token.
        
        Returns:
            Dictionary containing AccessToken, RefreshToken, ExpiresIn, etc.
            
        Raises:
            ValueError: If refresh_token is not available
            requests.RequestException: If the API request fails
        """
        if not self.refresh_token:
            raise ValueError("refresh_token is required for token refresh")
        
        url = f"{self.BASE_API_URL}auth/refresh"
        headers = {
            "x-pm-uid": self.uid,
            "x-pm-appversion": "browser-vpn@1.2.13",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        
        payload = {
            "UID": self.uid,
            "ResponseType": "token",
            "GrantType": "refresh_token",
            "RefreshToken": self.refresh_token,
            "RedirectURI": "https://protonvpn.com"
        }
        
        response = requests.post(url, headers=headers, json=payload, timeout=30, proxies={
            "http": "",
            "https": ""
        })
        response.raise_for_status()
        
        data = response.json()
        print(data)
        if not isinstance(data, dict):
            raise ValueError(f"Invalid response format: {data}")
        
        if data.get("Code") != 1000:
            error_msg = data.get("Error", "Unknown error")
            raise ValueError(f"API error: {error_msg}")
        
        if "AccessToken" not in data:
            raise ValueError("Missing AccessToken in response")
        
        return data
    
    def _ensure_access_token(self) -> None:
        """
        Ensure the access token is valid, refreshing if necessary.
        """
        if not self.refresh_token:
            return

        with self._lock:
            now = datetime.now()

            if (
                self._access_token_expires_at is not None
                and now < self._access_token_expires_at
            ):
                return

            # Refresh the access token.
            token_data = self._refresh_access_token()

            # Update access token, refresh token, and UID from refresh response.
            self.access_token = token_data["AccessToken"]
            if "RefreshToken" in token_data and token_data["RefreshToken"]:
                self.refresh_token = token_data["RefreshToken"]
            new_uid = token_data.get("UID") or token_data.get("Uid")
            if isinstance(new_uid, str) and new_uid:
                self.uid = new_uid

            # Honor ExpiresIn from payload and refresh just a few seconds early.
            expires_in = token_data.get("ExpiresIn", 86400)  # Default 24 hours
            try:
                expires_in = int(expires_in)
            except (TypeError, ValueError):
                expires_in = 86400

            refresh_buffer = self.ACCESS_TOKEN_REFRESH_BUFFER_SECONDS
            if expires_in <= refresh_buffer:
                refresh_buffer = 0

            self._access_token_expires_at = now + timedelta(
                seconds=max(expires_in - refresh_buffer, 0)
            )

            # Save updated credentials and expiry metadata.
            self._save_credentials_file(lock_held=True)
    
    def _fetch_credentials(self) -> Dict[str, Any]:
        """
        Fetch proxy credentials from Proton API.
        
        Returns:
            Dictionary containing Username, Password, Expire, and Code
            
        Raises:
            requests.RequestException: If the API request fails
            ValueError: If the response is invalid
        """
        url = f"{self.BASE_API_URL}vpn/v1/browser/token?Duration={self.token_duration}"
        headers = self._get_auth_headers()
        print(headers)
        
        response = requests.get(url, headers=headers, timeout=30, proxies={
            "http":"",
            "https":""
        })
        response.raise_for_status()
        
        data = response.json()
        
        if not isinstance(data, dict):
            raise ValueError(f"Invalid response format: {data}")
        
        if data.get("Code") != 1000:
            error_msg = data.get("Error", "Unknown error")
            raise ValueError(f"API error: {error_msg}")
        
        if "Username" not in data or "Password" not in data:
            raise ValueError("Missing Username or Password in response")
        
        return data
    
    def _ensure_credentials(self, force_refresh: bool = False) -> None:
        """
        Ensure valid credentials are available, refreshing if necessary.
        
        Args:
            force_refresh: Force refresh even if credentials are still valid
        """
        with self._lock:
            now = datetime.now()
            
            # Check if we need to refresh credentials
            if (
                force_refresh or
                self._credentials is None or
                self._credentials_expires_at is None or
                now >= self._credentials_expires_at
            ):
                # Fetch new credentials
                creds = self._fetch_credentials()
                
                # Calculate expiration time (with 10% margin for safety)
                expire_seconds = creds.get("Expire", self.token_duration)
                margin = expire_seconds * 0.1
                self._credentials_expires_at = now + timedelta(
                    seconds=expire_seconds - margin
                )
                
                self._credentials = creds
    
    def get_credentials(self, force_refresh: bool = False) -> Dict[str, str]:
        """
        Get current proxy credentials (username and password).
        
        Args:
            force_refresh: Force refresh even if credentials are still valid
            
        Returns:
            Dictionary with 'username' and 'password' keys
        """
        self._ensure_credentials(force_refresh)
        
        if self._credentials is None:
            raise RuntimeError("Failed to obtain credentials")
        
        return {
            "username": self._credentials["Username"],
            "password": self._credentials["Password"],
        }
    
    def _select_proxy_host_from_centralized(self) -> str:
        """
        Pick a proxy host from centralized Proton logical servers data.

        Returns:
            Proxy host/domain string.

        Raises:
            ValueError: If no usable host can be extracted.
        """
        logical_servers = self.get_proxies_centralized()
        for logical_server in logical_servers:
            if not isinstance(logical_server, dict):
                continue

            # Prefer a concrete server host if available.
            for server in logical_server.get("Servers", []):
                if not isinstance(server, dict):
                    continue
                for key in ("Domain", "EntryIP", "ExitIP", "Host", "Hostname"):
                    value = server.get(key)
                    if isinstance(value, str) and value:
                        return value

            # Fall back to logical-level host-like fields.
            for key in ("Domain", "Host", "Hostname", "Name"):
                value = logical_server.get(key)
                if isinstance(value, str) and value:
                    return value

        raise ValueError("No usable proxy host found in centralized proxy list")

    def get_proxy_url(self) -> str:
        """
        Get the proxy URL in format: https://username:password@host:port
        
        Returns:
            Proxy URL string
            
        Raises:
            ValueError: If no proxy host can be determined
        """
        proxy_host = self.proxy_host or self._select_proxy_host_from_centralized()
        
        creds = self.get_credentials()
        username = creds["username"]
        password = creds["password"]
        
        # URL encode username and password
        from urllib.parse import quote
        username_encoded = quote(username, safe="")
        password_encoded = quote(password, safe="")
        
        return (
            f"{self.DEFAULT_PROXY_SCHEME}://"
            f"{username_encoded}:{password_encoded}@"
            f"{proxy_host}:{self.proxy_port}"
        )
    
    def get_proxies(self) -> Dict[str, str]:
        """
        Get proxy dictionary for use with requests library.
        
        Returns:
            Dictionary with 'http' and 'https' keys pointing to proxy URLs
        """
        proxy_url = self.get_proxy_url()
        return {
            "http": proxy_url,
            "https": proxy_url,
        }
    
    def get_proxies_centralized(self, force_refresh: bool = False) -> List[Dict[str, Any]]:
        """
        Get centralized logical proxy servers from Proton API.
        Results are cached in memory for 1 hour to reduce API calls.
        
        Args:
            force_refresh: Ignore cache and fetch fresh data from the API.

        Returns:
            List of logical server dictionaries.
        """
        with self._lock:
            now = datetime.now()
            if (
                not force_refresh
                and self._centralized_proxies_cache is not None
                and self._centralized_proxies_expires_at is not None
                and now < self._centralized_proxies_expires_at
            ):
                return self._centralized_proxies_cache

        # Keep centralized API calls aligned with token refresh behavior.
        self._ensure_access_token()

        headers = {
            "accept": "*/*",
            "accept-language": "en-US,en;q=0.9",
            "authorization": f"Bearer {self.access_token}",
            "cache-control": "no-cache",
            "if-modified-since": "Thu, 01 Jan 1970 00:00:00 GMT",
            "pragma": "no-cache",
            "priority": "u=1, i",
            "sec-ch-ua": "\"Chromium\";v=\"145\", \"Not:A-Brand\";v=\"99\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"macOS\"",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "none",
            "sec-fetch-storage-access": "active",
            "x-pm-appversion": "browser-vpn@1.2.15",
            "x-pm-browser-type": "",
            "x-pm-country": "GB",
            "x-pm-max-tier": "2",
            "x-pm-netzone": "31.94.60.0",
            "x-pm-response-truncation-permitted": "true",
            "x-pm-single-group": "vpn-paid",
            "x-pm-uid": self.uid
        }
        
        response = requests.get("https://account.proton.me/api/vpn/v1/logicals", headers=headers)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise ValueError(f"Invalid response format: {data}")
        if data.get("Code") != 1000:
            error_msg = data.get("Error", "Unknown error")
            raise ValueError(f"API error: {error_msg}")
        if "LogicalServers" not in data:
            raise ValueError("Missing LogicalServers in response")
        
        logical_servers = data["LogicalServers"]
        if not isinstance(logical_servers, list):
            raise ValueError("Invalid LogicalServers format in response")

        with self._lock:
            self._centralized_proxies_cache = logical_servers
            self._centralized_proxies_expires_at = (
                datetime.now() + timedelta(seconds=self.CENTRALIZED_PROXY_CACHE_DURATION)
            )

        return logical_servers
    
    def get_session(self, **session_kwargs) -> requests.Session:
        """
        Get a requests.Session configured with Proton proxy.
        
        Args:
            **session_kwargs: Additional arguments to pass to requests.Session
            
        Returns:
            Configured requests.Session instance
        """
        session = requests.Session(**session_kwargs)
        session.proxies = self.get_proxies()
        return session
    
    def set_proxy_server(self, host: str, port: Optional[int] = None) -> None:
        """
        Set or update the proxy server host and port.
        
        Args:
            host: Proxy server hostname
            port: Proxy server port (optional, uses default if not provided)
        """
        with self._lock:
            self.proxy_host = host
            if port is not None:
                self.proxy_port = port
    
    def refresh_credentials(self) -> None:
        """Force refresh of proxy credentials."""
        self._ensure_credentials(force_refresh=True)
    
    def refresh_access_token(self) -> None:
        """
        Force refresh of the access token using the refresh token.
        
        Raises:
            ValueError: If refresh_token is not available
        """
        if not self.refresh_token:
            raise ValueError("refresh_token is required for token refresh")
        
        with self._lock:
            # Force refresh by clearing expiration
            self._access_token_expires_at = None
        
        self._ensure_access_token()
        # Credentials are saved automatically in _ensure_access_token
    
    def get_access_token_expiry(self) -> Optional[datetime]:
        """
        Get when the current access token expires.
        
        Returns:
            Datetime when access token expires, or None if not available
        """
        return self._access_token_expires_at
    
    def is_connected(self) -> bool:
        """
        Check if credentials are available and valid.
        
        Returns:
            True if credentials are available and not expired
        """
        with self._lock:
            if self._credentials is None or self._credentials_expires_at is None:
                return False
            return datetime.now() < self._credentials_expires_at
    
    def get_credentials_expiry(self) -> Optional[datetime]:
        """
        Get when the current credentials expire.
        
        Returns:
            Datetime when credentials expire, or None if not available
        """
        return self._credentials_expires_at


# Convenience function for quick usage
def create_proton_session(
    uid: Optional[str] = None,
    access_token: Optional[str] = None,
    refresh_token: Optional[str] = None,
    proxy_host: Optional[str] = None,
    proxy_port: Optional[int] = None,
    credentials_file: Optional[str] = None,
) -> requests.Session:
    """
    Create a requests session with Proton VPN proxy.
    
    Args:
        uid: Proton user ID (optional if credentials_file is provided)
        access_token: Proton access token (optional if credentials_file is provided)
        refresh_token: Optional refresh token for automatic token renewal
        proxy_host: Proxy server hostname
        proxy_port: Proxy server port
        credentials_file: Path to credentials file (default: "proton_credentials.txt")
        
    Returns:
        Configured requests.Session
    """
    manager = ProtonProxyManager(
        uid=uid,
        access_token=access_token,
        refresh_token=refresh_token,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        credentials_file=credentials_file
    )
    return manager.get_session()


if __name__ == "__main__":
    # Example usage
    import sys
    
    if len(sys.argv) < 1:
        print("Usage: python proton.py [uid] [access_token] [refresh_token] [proxy_host] [proxy_port] [credentials_file]")
        print("\nIf credentials_file is provided or default exists, uid/access_token are optional.")
        print("\nExample:")
        print("  python proton.py your-uid your-access-token refresh-token server.protonvpn.com 4443")
        print("  python proton.py  # Uses credentials from proton_credentials.txt if it exists")
        sys.exit(1)
    
    uid = sys.argv[1] if len(sys.argv) > 1 else None
    access_token = sys.argv[2] if len(sys.argv) > 2 else None
    refresh_token = sys.argv[3] if len(sys.argv) > 3 and not (sys.argv[3].isdigit() or '.' in sys.argv[3]) else None
    proxy_host = None
    proxy_port = None
    credentials_file = None
    
    # Parse remaining arguments
    arg_idx = 3 if refresh_token else 2
    if len(sys.argv) > arg_idx + 1:
        # Check if next arg is proxy_host (not a number)
        if not sys.argv[arg_idx + 1].isdigit():
            proxy_host = sys.argv[arg_idx + 1]
            if len(sys.argv) > arg_idx + 2:
                try:
                    proxy_port = int(sys.argv[arg_idx + 2])
                except ValueError:
                    credentials_file = sys.argv[arg_idx + 2]
        else:
            try:
                proxy_port = int(sys.argv[arg_idx + 1])
            except ValueError:
                pass
    
    if len(sys.argv) > arg_idx + 3:
        credentials_file = sys.argv[arg_idx + 3]
    
    try:
        manager = ProtonProxyManager(
            uid=uid,
            access_token=access_token,
            refresh_token=refresh_token,
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            credentials_file=credentials_file
        )
        
        if manager.refresh_token:
            print("Refresh token available - access token will auto-refresh when expired")
            if manager.get_access_token_expiry():
                print(f"Access token expires: {manager.get_access_token_expiry()}")
        
        if manager.credentials_file:
            print(f"Using credentials file: {manager.credentials_file}")
        
        print("Fetching proxy credentials...")
        creds = manager.get_credentials()
        print(f"✓ Credentials obtained (expires: {manager.get_credentials_expiry()})")
        
        if proxy_host:
            print(f"\nTesting connection through {proxy_host}:{manager.proxy_port}...")
            session = manager.get_session()
            response = session.get("https://api.ipify.org?format=json", timeout=10)
            print(f"✓ Success! Your IP: {response.json().get('ip', 'unknown')}")
        else:
            print("\nProxy host not provided. Set it using:")
            print("  manager.set_proxy_server('server.protonvpn.com', 4443)")
            print("\nThen use:")
            print("  session = manager.get_session()")
            print("  response = session.get('https://api.ipify.org?format=json')")
            
    except Exception as e:
        print(f"✗ Error: {e}", file=sys.stderr)
        sys.exit(1)

