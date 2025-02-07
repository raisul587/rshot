import os
import subprocess
import csv
import time
import json

from datetime import datetime
from shutil import which

import src.wifi.android
import src.utils

class WiFiCollector:
    """Enhanced WiFi data collector with improved storage capabilities."""

    def __init__(self):
        self._createDirectories()
        self.REPORTS_FILE = src.utils.REPORTS_DIR + 'stored.csv'
        self.PINS_FILE = src.utils.REPORTS_DIR + 'pins.json'
        self.DATA_VERSION = 2  # Version tracking for data format
        self.ANDROID_NETWORK = src.wifi.android.AndroidNetwork()

    def _createDirectories(self):
        """Ensure all necessary directories exist."""
        for directory in [src.utils.REPORTS_DIR, src.utils.PIXIEWPS_DIR]:
            if not os.path.exists(directory):
                os.makedirs(directory)

    def addNetwork(self, bssid: str, essid: str, wpa_psk: str):
        """Ads a network to systems network manager."""

        android_connect_cmd = ['cmd']
        android_connect_cmd.extend([
            '-w', 'wifi',
            'connect-network', f"{essid}",
            'wpa2', f"{wpa_psk}", 
            '-b', f"{bssid}"
        ])

        networkmanager_connect_cmd = ['nmcli']
        networkmanager_connect_cmd.extend([
            'connection', 'add', 
            'type', 'wifi', 
            'con-name', f"{essid}",
            'ssid', f"{essid}", 
            'wifi-sec.psk', f"{wpa_psk}",
            'wifi-sec.key-mgmt', 'wpa-psk'
        ])

        # Detect an android system
        if src.utils.isAndroid() is True:
            # The Wi-Fi scanner needs to be active in order to add network
            self.ANDROID_NETWORK.enableWifi(force_enable=True, whisper=True)
            subprocess.run(android_connect_cmd, check=True)

        # Detect NetworkManager
        elif which('nmcli'):
            subprocess.run(networkmanager_connect_cmd, check=True)

        print('[+] Access Point was saved to your network manager')

    def writeResult(self, bssid: str, essid: str, pin: str, psk: str, extra_info: dict = None):
        """Write network result with enhanced information."""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        
        # Prepare the data
        data = [timestamp, bssid, essid, pin, psk]
        headers = ['Timestamp', 'BSSID', 'ESSID', 'WPS PIN', 'WPA PSK']
        
        # Add extra information if provided
        if extra_info:
            for key, value in extra_info.items():
                headers.append(key)
                data.append(value)

        # Create file with headers if it doesn't exist
        if not os.path.exists(self.REPORTS_FILE):
            with open(self.REPORTS_FILE, 'w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file, delimiter=';', quoting=csv.QUOTE_ALL)
                writer.writerow(headers)

        # Append the data
        with open(self.REPORTS_FILE, 'a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file, delimiter=';', quoting=csv.QUOTE_ALL)
            writer.writerow(data)

    def writePin(self, bssid: str, pin: str, success_rate: float = None, vendor: str = None):
        """Store PIN with additional metadata."""
        bssid = bssid.upper()
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        
        # Load existing data
        pins_data = self._loadPinsData()
        
        # Update or add new entry
        if bssid not in pins_data:
            pins_data[bssid] = {'pins': []}
        
        pin_entry = {
            'pin': pin,
            'timestamp': timestamp,
            'success_rate': success_rate,
            'vendor': vendor
        }
        
        # Add new pin entry
        pins_data[bssid]['pins'].append(pin_entry)
        
        # Sort pins by success rate if available
        if success_rate is not None:
            pins_data[bssid]['pins'].sort(key=lambda x: x.get('success_rate', 0), reverse=True)
        
        # Save updated data
        self._savePinsData(pins_data)

    def _loadPinsData(self) -> dict:
        """Load PIN data with version checking."""
        try:
            with open(self.PINS_FILE, 'r', encoding='utf-8') as file:
                data = json.load(file)
                if data.get('version', 1) < self.DATA_VERSION:
                    # Handle data migration if needed
                    data = self._migratePinsData(data)
                return data.get('pins', {})
        except FileNotFoundError:
            return {}
        except json.JSONDecodeError:
            print('[!] Warning: PIN data file corrupted, creating new one')
            return {}

    def _savePinsData(self, pins_data: dict):
        """Save PIN data with version information."""
        data = {
            'version': self.DATA_VERSION,
            'pins': pins_data,
            'last_updated': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        with open(self.PINS_FILE, 'w', encoding='utf-8') as file:
            json.dump(data, file, indent=2)

    def _migratePinsData(self, old_data: dict) -> dict:
        """Migrate old data format to new version."""
        # Implement data migration logic here if needed
        return {
            'version': self.DATA_VERSION,
            'pins': old_data.get('pins', {}),
            'last_updated': time.strftime('%Y-%m-%d %H:%M:%S')
        }
