import os
import re
import csv
import codecs
import subprocess
import time
import threading

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

        # Show prompt immediately
        print('\nSelect target (press Enter to refresh):')
        
        # Calculate signal strength in background
        def background_scan():
            self._averageSignalStrength(networks, self.SCAN_RETRIES)
            # Update display with new signal info
            if not args.clear:
                print('\n')  # Add some space
            self._displayNetworks(networks)

        # Start background scan in a separate thread
        scan_thread = threading.Thread(target=background_scan)
        scan_thread.daemon = True
        scan_thread.start()

        while True:
            try:
                network_no = input('> ')

                if network_no.lower() in {'r', '0', ''}:
                    if args.clear:
                        src.utils.clearScreen()
                    return self.promptNetwork()

                if int(network_no) in networks.keys():
                    selected_network = networks[int(network_no)]
                    
                    # Enhanced router compatibility checks
                    signal_ok = True
                    if selected_network['Level'] < self.MIN_SIGNAL_STRENGTH:
                        print(f'[!] Warning: Signal strength ({selected_network["Level"]} dBm) is weak')
                        print('[!] This may affect connection reliability')
                        signal_ok = input('[?] Continue anyway? [y/N] ').lower() == 'y'
                    
                    if not signal_ok:
                        continue
                    
                    # WPS version compatibility check
                    wps_ver = selected_network['WPS version']
                    if wps_ver == '2.0':
                        print('[!] Note: WPS 2.0 detected - using enhanced security measures')
                        # Adjust connection parameters for WPS 2.0
                        self._adjustWPS2Parameters(selected_network)
                    elif wps_ver == '1.0h':
                        print('[*] WPS 1.0h detected - optimizing for better compatibility')
                        self._adjustWPS1Parameters(selected_network)
                    
                    # Check for known vendor optimizations
                    vendor = selected_network.get('Vendor', 'Unknown')
                    if vendor != 'Unknown':
                        print(f'[*] Detected {vendor} router - applying vendor-specific optimizations')
                        self._applyVendorOptimizations(selected_network)
                    
                    return selected_network['BSSID']

                raise IndexError
            except IndexError:
                print('Invalid number')
            except ValueError:
                print('Please enter a number')

    def _adjustWPS2Parameters(self, network):
        """Adjust parameters for WPS 2.0 routers."""
        network['WPS_Timeout'] = 60  # Longer timeout for WPS 2.0
        network['WPS_Retries'] = 5   # More retries
        network['Delay_Between_Retries'] = 3  # Longer delay between retries
        network['Use_Extended_Auth'] = True   # Use extended authentication

    def _adjustWPS1Parameters(self, network):
        """Adjust parameters for WPS 1.0h routers."""
        network['WPS_Timeout'] = 30  # Standard timeout
        network['WPS_Retries'] = 3   # Standard retries
        network['Delay_Between_Retries'] = 2  # Standard delay
        network['Use_Extended_Auth'] = False  # Standard authentication

    def _applyVendorOptimizations(self, network):
        """Apply vendor-specific optimizations."""
        vendor = network.get('Vendor', 'Unknown').upper()
        
        vendor_optimizations = {
            'ASUS': {
                'Timeout': 45,
                'Retries': 4,
                'Auth_Method': 'mixed',
                'Extended_Compatibility': True
            },
            'TPLINK': {
                'Timeout': 35,
                'Retries': 3,
                'Auth_Method': 'standard',
                'Extended_Compatibility': False
            },
            'DLINK': {
                'Timeout': 40,
                'Retries': 4,
                'Auth_Method': 'legacy',
                'Extended_Compatibility': True
            },
            'NETGEAR': {
                'Timeout': 50,
                'Retries': 5,
                'Auth_Method': 'aggressive',
                'Extended_Compatibility': True
            }
        }
        
        if vendor in vendor_optimizations:
            opts = vendor_optimizations[vendor]
            network['WPS_Timeout'] = opts['Timeout']
            network['WPS_Retries'] = opts['Retries']
            network['Auth_Method'] = opts['Auth_Method']
            network['Extended_Compatibility'] = opts['Extended_Compatibility']
            
            # Additional vendor-specific tweaks
            if vendor == 'ASUS':
                network['Use_Special_Auth'] = True
            elif vendor == 'DLINK':
                network['Legacy_Support'] = True
            elif vendor == 'NETGEAR':
                network['Aggressive_Mode'] = True

    def _iwScanner(self, skip_output=False) -> dict[int, dict] | bool:
        """Enhanced iw scanner with better router detection."""
        try:
            command = ['iw', 'dev', f'{self.INTERFACE}', 'scan']
            
            # Add additional scan parameters for better detection
            command.extend(['--flush', '--type', 'trigger'])  # Force fresh scan
            
            iw_scan_process = subprocess.run(command,
                encoding='utf-8', stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                check=True  # This will raise CalledProcessError if the command fails
            )

            lines = iw_scan_process.stdout.splitlines()
            networks = []

            for line in lines:
                if line.startswith('command failed:'):
                    print('[!] Error:', line)
                    return False

                line = line.strip('\t')

                for regexp, handler in self.matchers.items():
                    res = re.match(regexp, line)
                    if res:
                        try:
                            handler(line, res, networks)
                        except Exception as e:
                            print(f'[!] Warning: Error processing line "{line}": {str(e)}')
                            continue

            # Enhanced filtering and validation
            networks = [net for net in networks if self._validateNetwork(net)]

            if not networks:
                return False

            # Improved sorting with multiple criteria
            networks.sort(key=lambda x: (
                x['Level'],           # Signal strength (primary)
                not x['WPS'],        # WPS enabled networks first
                x['WPS locked'],     # Unlocked networks first
                x.get('Security type', 'Unknown') != 'Open'  # Secured networks first
            ), reverse=True)

            # Create network list with enhanced information
            network_list = {(i + 1): self._enhanceNetworkInfo(network) 
                          for i, network in enumerate(networks)}
            
            self.last_scan_results = network_list
            
            if not skip_output:
                self._displayNetworks(network_list)

            return network_list

        except subprocess.CalledProcessError as e:
            print(f'[!] Error running iw scan: {str(e)}')
            return False
        except Exception as e:
            print(f'[!] Unexpected error during scan: {str(e)}')
            return False

    def _validateNetwork(self, network):
        """Validate network information and enhance compatibility."""
        # Must have basic required fields
        if not all(k in network for k in ['BSSID', 'ESSID', 'Level']):
            return False
            
        # Enhanced WPS detection
        if not network['WPS']:
            # Some routers don't properly advertise WPS
            # Check additional indicators
            if any(indicator in network.get('Device name', '').upper() 
                  for indicator in ['ROUTER', 'AP', 'WAP', 'WIFI']):
                network['WPS'] = True
                network['WPS_Note'] = 'WPS detected through device name'
            
        # Signal strength validation
        if network['Level'] < -85:  # Extremely weak signal
            network['Warning'] = 'Extremely weak signal - connection may fail'
            
        return True

    def _enhanceNetworkInfo(self, network):
        """Enhance network information with additional data."""
        # Add vendor information if available
        if 'Vendor' not in network or network['Vendor'] == 'Unknown':
            network['Vendor'] = self.wps_generator._detectVendor(network['BSSID'])
            
        # Enhanced security information
        if network.get('Security type') == 'WPA2':
            if 'PSK' in network.get('Authentication suites', ''):
                network['Security type'] = 'WPA2-PSK'
            elif 'SAE' in network.get('Authentication suites', ''):
                network['Security type'] = 'WPA3-Transition'
                
        # Add compatibility rating
        network['Compatibility_Rating'] = self._calculateCompatibility(network)
        
        return network

    def _calculateCompatibility(self, network):
        """Calculate compatibility rating for the network."""
        score = 100
        
        # Signal strength impact
        if network['Level'] < -75:
            score -= 30
        elif network['Level'] < -70:
            score -= 20
        elif network['Level'] < -65:
            score -= 10
            
        # WPS version impact
        if network['WPS version'] == '2.0':
            score -= 15  # WPS 2.0 is generally harder to work with
        elif network['WPS version'] == '1.0h':
            score -= 5   # 1.0h has some additional security
            
        # Vendor impact
        if network['Vendor'] != 'Unknown':
            if network['Vendor'] in ['ASUS', 'TPLINK', 'DLINK']:
                score += 10  # These vendors typically work well
                
        # Security type impact
        if network.get('Security type') == 'WPA3-Transition':
            score -= 20  # WPA3 can be problematic
            
        return max(0, min(100, score))  # Keep score between 0 and 100

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
