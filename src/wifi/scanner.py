import os
import re
import csv
import codecs
import subprocess
import time

from src.utils import REPORTS_DIR
import src.wps.generator
import src.args

args = src.args.parseArgs()

class WiFiScanner:
    """Enhanced WiFi scanner with improved router detection."""

    def __init__(self, interface: str, vuln_list: str = None):
        self.INTERFACE = interface
        self.VULN_LIST = vuln_list
        self.MIN_SIGNAL_STRENGTH = -70  # Minimum recommended signal strength
        self.SCAN_RETRIES = 3  # Number of scan retries for better accuracy
        self.SCAN_DELAY = 2  # Delay between scans in seconds
        self.wps_generator = src.wps.generator.WPSpin()  # Initialize WPS generator for vendor detection
        self.last_scan_results = None  # Store last scan results
        
        reports_fname = REPORTS_DIR + 'stored.csv'
        self.STORED = self._loadStoredNetworks(reports_fname)

    def _loadStoredNetworks(self, reports_fname):
        """Load stored networks with better error handling."""
        try:
            with open(reports_fname, 'r', newline='', encoding='utf-8') as file:
                csv_reader = csv.reader(file, delimiter=';', quoting=csv.QUOTE_ALL)
                next(csv_reader)  # Skip header
                return [(row[1], row[2]) for row in csv_reader]  # BSSID, ESSID
        except FileNotFoundError:
            return []
        except Exception as e:
            print(f'[!] Warning: Error loading stored networks: {str(e)}')
            return []

    def _getCurrentSignalStrength(self, bssid: str) -> int:
        """Get current signal strength for a specific BSSID."""
        try:
            # Try to use cached results first
            if self.last_scan_results:
                for network in self.last_scan_results.values():
                    if network['BSSID'] == bssid:
                        return network['Level']

            # If not found in cache, do a new scan
            networks = self._iwScanner(skip_output=True)
            if networks:
                self.last_scan_results = networks  # Update cache
                for network in networks.values():
                    if network['BSSID'] == bssid:
                        return network['Level']
            
            return -100  # Return very weak signal if not found
        except Exception as e:
            print(f'[!] Warning: Error getting signal strength: {str(e)}')
            return -100

    def _getWPSVersion(self, bssid: str) -> str:
        """Get WPS version for a specific BSSID."""
        try:
            # Try to use cached results first
            if self.last_scan_results:
                for network in self.last_scan_results.values():
                    if network['BSSID'] == bssid:
                        return network['WPS version']

            # If not found in cache, do a new scan
            networks = self._iwScanner(skip_output=True)
            if networks:
                self.last_scan_results = networks  # Update cache
                for network in networks.values():
                    if network['BSSID'] == bssid:
                        return network['WPS version']
            
            return '1.0'  # Default to 1.0 if not found
        except Exception as e:
            print(f'[!] Warning: Error getting WPS version: {str(e)}')
            return '1.0'

    def _averageSignalStrength(self, networks, num_scans=3):
        """Calculate average signal strength over multiple scans."""
        signal_strengths = {}
        
        for _ in range(num_scans):
            current_networks = self._iwScanner(skip_output=True)
            if current_networks:
                self.last_scan_results = current_networks  # Update cache
                for net in current_networks.values():
                    bssid = net['BSSID']
                    if bssid not in signal_strengths:
                        signal_strengths[bssid] = []
                    signal_strengths[bssid].append(net['Level'])
            time.sleep(self.SCAN_DELAY)
        
        # Update networks with average signal strength
        for net in networks.values():
            bssid = net['BSSID']
            if bssid in signal_strengths and signal_strengths[bssid]:
                net['Level'] = sum(signal_strengths[bssid]) / len(signal_strengths[bssid])
                net['Signal Stability'] = max(signal_strengths[bssid]) - min(signal_strengths[bssid])

    def promptNetwork(self) -> str:
        """Enhanced network selection with signal strength analysis."""
        networks = self._iwScanner()

        if not networks:
            print('[-] No WPS networks found.')
            return

        # Calculate average signal strength
        self._averageSignalStrength(networks, self.SCAN_RETRIES)

        while True:
            try:
                network_no = input('Select target (press Enter to refresh): ')

                if network_no.lower() in {'r', '0', ''}:
                    if args.clear:
                        src.utils.clearScreen()
                    return self.promptNetwork()

                if int(network_no) in networks.keys():
                    selected_network = networks[int(network_no)]
                    
                    # Check signal strength
                    if selected_network['Level'] < self.MIN_SIGNAL_STRENGTH:
                        print(f'[!] Warning: Signal strength ({selected_network["Level"]} dBm) is weak')
                        print('[!] This may affect connection reliability')
                        if input('[?] Continue anyway? [y/N] ').lower() != 'y':
                            continue
                    
                    # Check WPS version compatibility
                    if selected_network['WPS version'] == '2.0':
                        print('[!] Note: WPS 2.0 detected - using enhanced security measures')
                    
                    return selected_network['BSSID']

                raise IndexError
            except IndexError:
                print('Invalid number')

    def _iwScanner(self, skip_output=False) -> dict[int, dict] | bool:
        """Enhanced iw scanner with better router detection."""

        def handleNetwork(_line, result, networks):
            networks.append({
                'Security type': 'Unknown',
                'WPS': False,
                'WPS version': '1.0',
                'WPS locked': False,
                'Model': '',
                'Model number': '',
                'Device name': '',
                'Manufacturer': '',  # Initialize manufacturer field
                'Signal Stability': 0,
                'Vendor': 'Unknown',
                'WPS state': '',
                'WPS warning': '',
                'WPS note': '',
                'Vendor Note': ''
            })
            bssid = result.group(1).upper()
            networks[-1]['BSSID'] = bssid
            # Add vendor detection
            networks[-1]['Vendor'] = self.wps_generator._detectVendor(bssid)

        def handleEssid(_line, result, networks):
            d = result.group(1)
            networks[-1]['ESSID'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

        def handleLevel(_line, result, networks):
            networks[-1]['Level'] = int(float(result.group(1)))

        def handleSecurityType(_line, result, networks):
            sec = networks[-1]['Security type']
            if result.group(1) == 'capability':
                if 'Privacy' in result.group(2):
                    sec = 'WEP'
                else:
                    sec = 'Open'
            elif sec == 'WEP':
                if result.group(1) == 'RSN':
                    sec = 'WPA2'
                elif result.group(1) == 'WPA':
                    sec = 'WPA'
            elif sec == 'WPA':
                if result.group(1) == 'RSN':
                    sec = 'WPA/WPA2'
            elif sec == 'WPA2':
                if result.group(1) == 'PSK SAE':
                    sec = 'WPA2/WPA3'
                elif result.group(1) == 'WPA':
                    sec = 'WPA/WPA2'
                elif result.group(1) == 'SAE':
                    sec = 'WPA3'
            elif sec == 'Open':
                if result.group(1) == 'RSN' or result.group(1) == 'WPA':
                    sec = 'WPA/WPA2'
            networks[-1]['Security type'] = sec

        def handleWps(_line, result, networks):
            is_wps_enabled = bool(result.group(1))
            networks[-1]['WPS'] = is_wps_enabled
            networks[-1]['WPS state'] = 'Configured' if is_wps_enabled else 'Not Configured'
            
            # Add signal strength warning
            if is_wps_enabled and networks[-1].get('Level', -100) < self.MIN_SIGNAL_STRENGTH:
                networks[-1]['WPS warning'] = 'Weak signal - may affect reliability'
            
            # Add vendor-specific notes
            vendor = networks[-1]['Vendor']
            if vendor != 'UNKNOWN':
                networks[-1]['Vendor Note'] = f'Detected {vendor} router - using optimized algorithms'

        def handleWpsVersion(_line, result, networks):
            wps_ver = networks[-1]['WPS version']
            wps_ver_filtered = result.group(1).replace('* Version2:', '')
            
            # Enhanced version detection
            if '2.0' in wps_ver_filtered:
                wps_ver = '2.0'
            elif '1.0h' in wps_ver_filtered:
                wps_ver = '1.0h'
            elif any(v in wps_ver_filtered for v in ['1.0', '1.1', '1.2']):
                wps_ver = wps_ver_filtered
            else:
                wps_ver = '1.0'  # Default to 1.0 if unknown
            
            networks[-1]['WPS version'] = wps_ver
            
            # Add compatibility warnings based on version
            if wps_ver == '2.0':
                networks[-1]['WPS note'] = 'WPS 2.0 - Enhanced security features'
            elif wps_ver == '1.0h':
                networks[-1]['WPS note'] = 'WPS 1.0h - Check for vendor-specific features'

        def handleWpsLocked(_line, result, networks):
            flag = int(result.group(1), 16)
            if flag:
                networks[-1]['WPS locked'] = True

        def handleManufacturer(_line, result, networks):
            """Handle manufacturer information."""
            if networks:  # Check if we have any networks
                networks[-1]['Manufacturer'] = result.group(1).strip()

        def handleDeviceName(_line, result, networks):
            """Handle device name information."""
            if networks:  # Check if we have any networks
                networks[-1]['Device name'] = codecs.decode(result.group(1), 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

        def handleModel(_line, result, networks):
            """Handle model information."""
            if networks:  # Check if we have any networks
                networks[-1]['Model'] = codecs.decode(result.group(1), 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

        def handleModelNumber(_line, result, networks):
            """Handle model number information."""
            if networks:  # Check if we have any networks
                networks[-1]['Model number'] = codecs.decode(result.group(1), 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

        networks = []
        matchers = {
            re.compile(r'BSS (\S+)( )?\(on \w+\)'): handleNetwork,
            re.compile(r'SSID: (.*)'): handleEssid,
            re.compile(r'signal: ([+-]?([0-9]*[.])?[0-9]+) dBm'): handleLevel,
            re.compile(r'(capability): (.+)'): handleSecurityType,
            re.compile(r'(RSN):\t [*] Version: (\d+)'): handleSecurityType,
            re.compile(r'(WPA):\t [*] Version: (\d+)'): handleSecurityType,
            re.compile(r'WPS:\t [*] Version: (([0-9]*[.])?[0-9]+)'): handleWps,
            re.compile(r' [*] Version2: (.+)'): handleWpsVersion,
            re.compile(r' [*] Authentication suites: (.+)'): handleSecurityType,
            re.compile(r' [*] AP setup locked: (0x[0-9]+)'): handleWpsLocked,
            re.compile(r' [*] Model: (.*)'): handleModel,
            re.compile(r' [*] Model Number: (.*)'): handleModelNumber,
            re.compile(r' [*] Device name: (.*)'): handleDeviceName,
            re.compile(r' [*] Manufacturer: (.*)'): handleManufacturer  # Fixed manufacturer handler
        }

        try:
            command = ['iw', 'dev', f'{self.INTERFACE}', 'scan']
            iw_scan_process = subprocess.run(command,
                encoding='utf-8', stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                check=True  # This will raise CalledProcessError if the command fails
            )

            lines = iw_scan_process.stdout.splitlines()

            for line in lines:
                if line.startswith('command failed:'):
                    print('[!] Error:', line)
                    return False

                line = line.strip('\t')

                for regexp, handler in matchers.items():
                    res = re.match(regexp, line)
                    if res:
                        try:
                            handler(line, res, networks)
                        except Exception as e:
                            print(f'[!] Warning: Error processing line "{line}": {str(e)}')
                            continue

        except subprocess.CalledProcessError as e:
            print(f'[!] Error running iw scan: {str(e)}')
            return False
        except Exception as e:
            print(f'[!] Unexpected error during scan: {str(e)}')
            return False

        # Filtering non-WPS networks
        networks = list(filter(lambda x: bool(x['WPS']), networks))

        if not networks:
            return False

        # Sorting by signal level
        networks.sort(key=lambda x: x['Level'], reverse=True)

        # Create network list
        network_list = {(i + 1): network for i, network in enumerate(networks)}
        
        # Update last scan results
        self.last_scan_results = network_list
        
        if not skip_output:
            self._displayNetworks(network_list)

        return network_list

    def _displayNetworks(self, network_list):
        """Display network list with proper formatting."""
        network_list_items = list(network_list.items())

        print('Network marks: {1} {0} {2} {0} {3} {0} {4} {0} {5}'.format(
            '|',
            self._colored('Vulnerable model', color='green'),
            self._colored('Vulnerable WPS ver.', color='dark_green'),
            self._colored('WPS locked', color='red'),
            self._colored('Already stored', color='yellow'),
            self._colored('Known vendor', color='blue')
        ))

        # Calculate column lengths
        columm_lengths = {
            '#': 4,
            'sec': self._entryMaxLength(network_list_items, 'Security type'),
            'bssid': 18,
            'essid': self._entryMaxLength(network_list_items, 'ESSID'),
            'name': self._entryMaxLength(network_list_items, 'Device name'),
            'model': self._entryMaxLength(network_list_items, 'Model')
        }

        # Print header
        row_format = '{:<{#}} {:<{bssid}} {:<{essid}} {:<{sec}} {:<{#}} {:<{#}} {:<{name}} {:<{model}}'
        print(row_format.format(
            '#', 'BSSID', 'ESSID', 'Sec.', 'PWR', 'Ver.', 'WSC name', 'WSC model',
            **columm_lengths
        ))

        # Print networks
        for n, network in network_list_items:
            self._displayNetwork(n, network, row_format, columm_lengths)

    @staticmethod
    def _colored(text: str, color: str) -> str:
        """Enhanced colored text with more status indicators"""
        colors = {
            'green': '\033[1m\033[92m',
            'dark_green': '\033[32m',
            'red': '\033[1m\033[91m',
            'yellow': '\033[1m\033[93m',
            'blue': '\033[1m\033[94m'
        }
        return f"{colors.get(color, '')}{text}\033[00m" if color in colors else text

    @staticmethod
    def _entryMaxLength(items, key, max_length=27) -> int:
        """Calculate maximum length for a column."""
        try:
            lengths = [len(str(entry[1].get(key, ''))) for entry in items]
            return min(max(lengths), max_length) + 1
        except Exception:
            return max_length

    def _displayNetwork(self, number, network, row_format, columm_lengths):
        """Display a single network entry."""
        try:
            number_str = f'{number})'
            essid = self._truncateStr(network.get('ESSID', ''), 25)
            device_name = self._truncateStr(network.get('Device name', ''), 27)
            model = f"{network.get('Model', '')} {network.get('Model number', '')}"

            line = row_format.format(
                number_str,
                network.get('BSSID', ''),
                essid,
                network.get('Security type', 'Unknown'),
                network.get('Level', 0),
                network.get('WPS version', '1.0'),
                device_name,
                model,
                **columm_lengths
            )

            # Determine line color
            if (network.get('BSSID', ''), network.get('ESSID', '')) in self.STORED:
                print(self._colored(line, 'yellow'))
            elif network.get('WPS version') == '1.0':
                print(self._colored(line, 'dark_green'))
            elif network.get('WPS locked'):
                print(self._colored(line, 'red'))
            elif self.VULN_LIST and (model in self.VULN_LIST or device_name in self.VULN_LIST):
                print(self._colored(line, 'green'))
            else:
                print(line)
        except Exception as e:
            print(f'[!] Error displaying network {number}: {str(e)}')

    def _truncateStr(self, s: str, length: int, postfix='…') -> str:
        """Truncate string with the specified length."""

        if len(s) > length:
            k = length - len(postfix)
            s = s[:k] + postfix
        return s
