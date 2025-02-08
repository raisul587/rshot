import subprocess
import time

class AndroidNetwork:
    """Enhanced Android network management."""

    def __init__(self):
        self.WIFI_ENABLED = False
        self.ALWAYS_SCAN = False

    def enableWifi(self, force_enable: bool = False, whisper: bool = False):
        """Enable WiFi with better state tracking."""
        if not whisper:
            print('[*] Android: enabling Wi-Fi')
        
        try:
            subprocess.run(['cmd', 'wifi', 'enable'], check=True, capture_output=True)
            self.WIFI_ENABLED = True
            if not whisper:
                print('[+] WiFi enabled successfully')
            time.sleep(1)  # Give system time to process
        except Exception as e:
            if not whisper:
                print(f'[!] Error enabling WiFi: {str(e)}')

    def disableWifi(self, whisper: bool = False):
        """Disable WiFi with better state tracking."""
        if not whisper:
            print('[*] Android: disabling Wi-Fi')
        
        try:
            subprocess.run(['cmd', 'wifi', 'disable'], check=True, capture_output=True)
            self.WIFI_ENABLED = False
            if not whisper:
                print('[+] WiFi disabled successfully')
            time.sleep(1)  # Give system time to process
        except Exception as e:
            if not whisper:
                print(f'[!] Error disabling WiFi: {str(e)}')

    def storeAlwaysScanState(self):
        """Store WiFi scan state."""
        try:
            result = subprocess.run(['settings', 'get', 'global', 'wifi_scan_always_enabled'],
                                 check=True, capture_output=True, text=True)
            self.ALWAYS_SCAN = result.stdout.strip() == '1'
        except Exception:
            self.ALWAYS_SCAN = False

    def restoreAlwaysScanState(self):
        """Restore WiFi scan state."""
        if self.ALWAYS_SCAN:
            try:
                subprocess.run(['settings', 'put', 'global', 'wifi_scan_always_enabled', '1'],
                             check=True, capture_output=True)
            except Exception:
                pass
