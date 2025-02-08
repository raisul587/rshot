"""WPA3 handshake capture and SAE authentication module."""

import os
import time
import logging
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
from pathlib import Path
import subprocess
from scapy.all import (
    Dot11, RadioTap, Dot11Auth, Dot11AssoReq, Dot11AssoResp,
    Dot11Deauth, sendp, sniff, conf
)

@dataclass
class SAEConfig:
    """SAE authentication configuration."""
    password: str
    group_id: int = 19  # NIST P-256
    anti_clogging_token: Optional[bytes] = None
    timeout: float = 5.0
    retries: int = 3

@dataclass
class WPA3Credentials:
    """WPA3 network credentials."""
    ssid: str
    password: str
    pmk: Optional[bytes] = None
    ptk: Optional[bytes] = None
    gtk: Optional[bytes] = None

class WPA3Handler:
    """Handles WPA3 connections and authentication."""

    def __init__(self, interface: str):
        self.interface = interface
        self.credentials: Dict[str, WPA3Credentials] = {}
        self.sae_configs: Dict[str, SAEConfig] = {}
        
        # Configure Scapy
        conf.iface = interface
        
        # Setup logging
        self.logger = logging.getLogger('wpa3_handler')
        self.logger.setLevel(logging.INFO)
        
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def _check_wpa3_support(self) -> bool:
        """Check if the system and interface support WPA3."""
        try:
            # Check wpa_supplicant version
            result = subprocess.run(
                ['wpa_supplicant', '-v'],
                capture_output=True,
                text=True,
                check=True
            )
            if 'v2.9' not in result.stdout and 'v2.10' not in result.stdout:
                self.logger.warning(
                    'WPA3 requires wpa_supplicant v2.9 or later'
                )
                return False

            # Check if interface supports SAE
            result = subprocess.run(
                ['iw', 'phy', 'phy0', 'info'],
                capture_output=True,
                text=True,
                check=True
            )
            if 'SAE' not in result.stdout:
                self.logger.warning(
                    'Interface does not support SAE (WPA3)'
                )
                return False

            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f'Error checking WPA3 support: {e}')
            return False

    def _init_sae_handshake(self, bssid: str, config: SAEConfig) -> bool:
        """Initialize SAE handshake with an AP."""
        try:
            # Create SAE Commit frame
            commit_frame = (
                RadioTap() /
                Dot11(
                    type=0, subtype=11,  # Authentication
                    addr1=bssid,
                    addr2=self.interface,
                    addr3=bssid
                ) /
                Dot11Auth(
                    seqnum=1,
                    algo=3,  # SAE
                    status=0  # Success
                )
            )

            # Send frame and wait for response
            sendp(commit_frame, iface=self.interface, verbose=False)
            
            def handle_auth_response(pkt):
                if (
                    Dot11Auth in pkt and
                    pkt[Dot11].addr2 == bssid and
                    pkt[Dot11Auth].algo == 3
                ):
                    if pkt[Dot11Auth].status == 0:
                        return True
                    elif pkt[Dot11Auth].status == 76:  # Anti-clogging token needed
                        self.sae_configs[bssid].anti_clogging_token = (
                            pkt[Dot11Auth].payload.load
                        )
                    return True
                return False

            # Sniff for authentication response
            response = sniff(
                iface=self.interface,
                lfilter=handle_auth_response,
                timeout=config.timeout,
                count=1
            )

            if not response:
                self.logger.warning(f'No SAE response from {bssid}')
                return False

            return True

        except Exception as e:
            self.logger.error(f'Error in SAE handshake: {e}')
            return False

    def _complete_sae_handshake(self, bssid: str, config: SAEConfig) -> bool:
        """Complete SAE handshake and derive keys."""
        try:
            # Create SAE Confirm frame
            confirm_frame = (
                RadioTap() /
                Dot11(
                    type=0, subtype=11,
                    addr1=bssid,
                    addr2=self.interface,
                    addr3=bssid
                ) /
                Dot11Auth(
                    seqnum=2,
                    algo=3,
                    status=0
                )
            )

            # Send frame and wait for response
            sendp(confirm_frame, iface=self.interface, verbose=False)
            
            def handle_confirm_response(pkt):
                if (
                    Dot11Auth in pkt and
                    pkt[Dot11].addr2 == bssid and
                    pkt[Dot11Auth].algo == 3 and
                    pkt[Dot11Auth].seqnum == 2
                ):
                    return True
                return False

            # Sniff for confirmation response
            response = sniff(
                iface=self.interface,
                lfilter=handle_confirm_response,
                timeout=config.timeout,
                count=1
            )

            if not response:
                self.logger.warning(f'No SAE confirmation from {bssid}')
                return False

            return True

        except Exception as e:
            self.logger.error(f'Error completing SAE handshake: {e}')
            return False

    def _perform_wpa3_association(self, bssid: str, ssid: str) -> bool:
        """Perform WPA3 association after successful SAE handshake."""
        try:
            # Create Association Request frame
            assoc_req = (
                RadioTap() /
                Dot11(
                    type=0, subtype=0,
                    addr1=bssid,
                    addr2=self.interface,
                    addr3=bssid
                ) /
                Dot11AssoReq()
            )

            # Send frame and wait for response
            sendp(assoc_req, iface=self.interface, verbose=False)
            
            def handle_assoc_response(pkt):
                if (
                    Dot11AssoResp in pkt and
                    pkt[Dot11].addr2 == bssid
                ):
                    return pkt[Dot11AssoResp].status == 0
                return False

            # Sniff for association response
            response = sniff(
                iface=self.interface,
                lfilter=handle_assoc_response,
                timeout=5,
                count=1
            )

            if not response:
                self.logger.warning(f'Association failed with {bssid}')
                return False

            return True

        except Exception as e:
            self.logger.error(f'Error in WPA3 association: {e}')
            return False

    def connect_wpa3(self, bssid: str, ssid: str, password: str) -> bool:
        """Establish WPA3 connection with an AP."""
        if not self._check_wpa3_support():
            return False

        # Initialize SAE configuration
        self.sae_configs[bssid] = SAEConfig(password=password)
        
        # Attempt SAE handshake with retries
        for attempt in range(self.sae_configs[bssid].retries):
            self.logger.info(
                f'Attempting SAE handshake with {bssid} (attempt {attempt + 1})'
            )
            
            if not self._init_sae_handshake(bssid, self.sae_configs[bssid]):
                time.sleep(1)
                continue
                
            if not self._complete_sae_handshake(bssid, self.sae_configs[bssid]):
                time.sleep(1)
                continue
                
            if self._perform_wpa3_association(bssid, ssid):
                self.credentials[bssid] = WPA3Credentials(
                    ssid=ssid,
                    password=password
                )
                self.logger.info(f'Successfully connected to {ssid} ({bssid})')
                return True
                
            time.sleep(1)
        
        self.logger.error(f'Failed to establish WPA3 connection with {bssid}')
        return False

    def disconnect_wpa3(self, bssid: str) -> bool:
        """Disconnect from a WPA3 network."""
        try:
            # Send deauthentication frame
            deauth = (
                RadioTap() /
                Dot11(
                    type=0, subtype=12,
                    addr1=bssid,
                    addr2=self.interface,
                    addr3=bssid
                ) /
                Dot11Deauth(reason=3)  # Deauthenticated because leaving
            )
            
            sendp(deauth, iface=self.interface, verbose=False)
            
            # Clean up stored credentials
            if bssid in self.credentials:
                del self.credentials[bssid]
            if bssid in self.sae_configs:
                del self.sae_configs[bssid]
                
            return True
            
        except Exception as e:
            self.logger.error(f'Error disconnecting from {bssid}: {e}')
            return False

    def get_connection_status(self, bssid: str) -> Dict:
        """Get status of WPA3 connection."""
        if bssid not in self.credentials:
            return {'status': 'not_connected'}
            
        return {
            'status': 'connected',
            'ssid': self.credentials[bssid].ssid,
            'security': 'WPA3-SAE',
            'pmk_derived': self.credentials[bssid].pmk is not None,
            'ptk_derived': self.credentials[bssid].ptk is not None,
            'gtk_received': self.credentials[bssid].gtk is not None
        } 