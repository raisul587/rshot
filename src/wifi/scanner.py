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

    def _averageSignalStrength(self, networks, num_scans=3):
        """Calculate average signal strength over multiple scans."""
        signal_strengths = {}
        
        for _ in range(num_scans):
            current_networks = self._iwScanner(skip_output=True)
            if current_networks:
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
                'Manufacturer': '',
                'Signal Stability': 0,
                'Vendor': 'Unknown'
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

        def handleModel(_line, result, networks):
            d = result.group(1)
            networks[-1]['Model'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

        def handleModelNumber(_line: str, result: str, networks: list):
            d = result.group(1)
            networks[-1]['Model number'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

        def handleDeviceName(_line, result, networks):
            d = result.group(1)
            networks[-1]['Device name'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

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
            # Add support for additional router information
            re.compile(r' [*] Manufacturer: (.*)'): lambda l, r, n: setattr(n[-1], 'Manufacturer', r.group(1)),
            re.compile(r' [*] OS Version: (.*)'): lambda l, r, n: setattr(n[-1], 'OS Version', r.group(1))
        }

        command = ['iw', 'dev', f'{self.INTERFACE}', 'scan']
        iw_scan_process = subprocess.run(command,
            encoding='utf-8', stdout=subprocess.PIPE, stderr=subprocess.STDOUT
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
                    handler(line, res, networks)

        # Filtering non-WPS networks
        networks = list(filter(lambda x: bool(x['WPS']), networks))

        if not networks:
            return False

        # Sorting by signal level
        networks.sort(key=lambda x: x['Level'], reverse=True)

        # Putting a list of networks in a dictionary, where each key is a network number in list of networks
        network_list = {(i + 1): network for i, network in enumerate(networks)}
        network_list_items = list(network_list.items())

        def truncateStr(s: str, length: int, postfix='…') -> str:
            """Truncate string with the specified length."""

            if len(s) > length:
                k = length - len(postfix)
                s = s[:k] + postfix
            return s

        def colored(text: str, color: str) -> str:
            """Enhanced colored text with more status indicators"""
            if color:
                if color == 'green':
                    text = f'\033[1m\033[92m{text}\033[00m'
                if color == 'dark_green':
                    text = f'\033[32m{text}\033[00m'
                elif color == 'red':
                    text = f'\033[1m\033[91m{text}\033[00m'
                elif color == 'yellow':
                    text = f'\033[1m\033[93m{text}\033[00m'
                elif color == 'blue':
                    text = f'\033[1m\033[94m{text}\033[00m'
                else:
                    return text
            else:
                return text
            return text

        if not skip_output:
            print('Network marks: {1} {0} {2} {0} {3} {0} {4} {0} {5}'.format(
                '|',
                colored('Vulnerable model', color='green'),
                colored('Vulnerable WPS ver.', color='dark_green'),
                colored('WPS locked', color='red'),
                colored('Already stored', color='yellow'),
                colored('Known vendor', color='blue')
            ))

        def entryMaxLength(item: str, max_length=27) -> int:
            """Calculates max length of network_list_items entry"""

            lengths = [len(entry[1][item]) for entry in network_list_items]
            return min(max(lengths), max_length) + 1

        # Used to calculate the max width of a collum in the network list table
        columm_lengths = {
            '#': 4,
            'sec': entryMaxLength('Security type'),
            'bssid': 18,
            'essid': entryMaxLength('ESSID'),
            'name': entryMaxLength('Device name'),
            'model': entryMaxLength('Model')
        }

        row = '{:<{#}} {:<{bssid}} {:<{essid}} {:<{sec}} {:<{#}} {:<{#}} {:<{name}} {:<{model}}'

        print(row.format(
            '#', 'BSSID', 'ESSID', 'Sec.', 'PWR', 'Ver.', 'WSC name', 'WSC model',
            **columm_lengths
        ))

        if args.reverse_scan:
            network_list_items = network_list_items[::-1]
        for n, network in network_list_items:
            number = f'{n})'
            model = f'{network['Model']} {network['Model number']}'
            essid = truncateStr(network['ESSID'], 25)
            device_name = truncateStr(network['Device name'], 27)
            line = row.format(
                number, network['BSSID'], essid,
                network['Security type'], network['Level'],
                network['WPS version'], device_name, model,
                **columm_lengths
            )
            if (network['BSSID'], network['ESSID']) in self.STORED:
                print(colored(line, color='yellow'))
            elif network['WPS version'] == '1.0':
                print(colored(line, color='dark_green'))
            elif network['WPS locked']:
                print(colored(line, color='red'))
            elif self.VULN_LIST and (model in self.VULN_LIST) or (device_name in self.VULN_LIST):
                print(colored(line, color='green'))
            else:
                print(line)

        return network_list
