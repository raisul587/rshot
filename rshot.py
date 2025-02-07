#!/usr/bin/env python3
import os
import sys
import signal
import time
import argparse
from pathlib import Path

import src.wifi.android
import src.wifi.scanner
import src.wps.connection
import src.wps.bruteforce
import src.utils

def signal_handler(signum, frame):
    """Handle interruption gracefully."""
    print('\n[!] Received interrupt signal')
    print('[*] Cleaning up...')
    if 'connection' in globals():
        connection._cleanup()
    sys.exit(1)

def parseArgs():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser()
    
    parser.add_argument('-i', '--interface',
        type=str, help='Name of the network interface to use')
    parser.add_argument('-b', '--bssid',
        type=str, help='BSSID of the target network')
    parser.add_argument('-p', '--pin',
        type=str, help='WPS PIN')
    parser.add_argument('-K', '--pixie-dust',
        action='store_true', help='Run Pixie Dust attack')
    parser.add_argument('-F', '--force',
        action='store_true', help='Run Pixiewps with --force option')
    parser.add_argument('-X', '--show-pixie-cmd',
        action='store_true', help='Always print Pixiewps command')
    parser.add_argument('--vuln-list',
        type=str, help='Use custom file with vulnerable devices list')
    parser.add_argument('--iface-down',
        action='store_true', help='Down network interface when the work is finished')
    parser.add_argument('--loop',
        action='store_true', help='Run in loop')
    parser.add_argument('--pbc',
        action='store_true', help='Run WPS push button connection')
    parser.add_argument('-v', '--verbose',
        action='store_true', help='Verbose output')
    parser.add_argument('--clear',
        action='store_true', help='Clear the screen before printing scan results')
    parser.add_argument('--check',
        action='store_true', help='Check if WPS is active on network')
    parser.add_argument('--store-pin-on-fail',
        action='store_true', help='Store calculated PIN if attack fails')
    parser.add_argument('--mtk-wifi',
        action='store_true', help='Enable MediaTek Wi-Fi interface device')
    
    return parser.parse_args()

def init_directories():
    """Initialize required directories."""
    pixiewps_dir = src.utils.PIXIEWPS_DIR
    sessions_dir = src.utils.SESSIONS_DIR
    
    for directory in [sessions_dir, pixiewps_dir]:
        if not os.path.exists(directory):
            os.makedirs(directory)

def init_mtk_wifi(enable: bool = True):
    """Initialize MediaTek WiFi interface."""
    wmtWifi_device = Path('/dev/wmtWifi')
    if not wmtWifi_device.is_char_device():
        src.utils.die('Unable to activate MediaTek Wi-Fi interface device (--mtk-wifi): '
            '/dev/wmtWifi does not exist or it is not a character device')
    wmtWifi_device.chmod(0o644)
    wmtWifi_device.write_text('1' if enable else '0', encoding='utf-8')
    return wmtWifi_device

def main(args):
    """Main program logic."""
    # Initialize scanner and collector
    wifi_scanner = src.wifi.scanner.WiFiScanner(args.interface, args.vuln_list)
    wifi_collector = src.wifi.collector.WiFiCollector()
    android_network = None
    
    if src.utils.isAndroid():
        android_network = src.wifi.android.AndroidNetwork()
        # Enable WiFi only once at the start
        android_network.enableWifi(force_enable=True)
    
    # Main loop
    max_retries = 3
    retry_count = 0
    
    while True:
        try:
            # Get target network
            if not args.bssid:
                args.bssid = wifi_scanner.promptNetwork()
                if not args.bssid:
                    retry_count += 1
                    if retry_count >= max_retries:
                        print('[!] Maximum retry attempts reached. Exiting...')
                        return 1
                    print(f'[*] Retrying scan... (Attempt {retry_count + 1}/{max_retries})')
                    time.sleep(2)  # Wait before retry
                    continue
            
            # Reset retry counter after successful scan
            retry_count = 0
            
            # Get current signal strength and WPS version
            signal_strength = wifi_scanner._getCurrentSignalStrength(args.bssid)
            wps_version = wifi_scanner._getWPSVersion(args.bssid)
            
            # Store network info for result collection
            network_info = {
                'signal_strength': signal_strength,
                'wps_version': wps_version,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            }
            
            # Initialize connection
            wps_connection = src.wps.connection.Initialize(
                args.interface,
                write_result=True,
                save_result=True,
                print_debug=args.verbose
            )
            
            # Run connection attempt
            res = wps_connection.singleConnection(
                args.bssid,
                args.pin,
                args.pixie_dust,
                args.show_pixie_cmd,
                args.force,
                args.pbc,
                args.store_pin_on_fail
            )
            
            # Handle result
            if res:
                print('[+] Session completed successfully')
                return 0
            
            if not args.loop:
                return 1
            
            args.bssid = None
            time.sleep(1)  # Small delay before next scan
            
        except KeyboardInterrupt:
            print('\n[!] Interrupted by user')
            return 1
        except Exception as e:
            print(f'[!] Error: {str(e)}')
            retry_count += 1
            if retry_count >= max_retries:
                print('[!] Maximum retry attempts reached. Exiting...')
                return 1
            print(f'[*] Retrying... (Attempt {retry_count + 1}/{max_retries})')
            time.sleep(2)
            continue

if __name__ == '__main__':
    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)

    # Python 3.8 is required
    if sys.hexversion < 0x030800F0:
        src.utils.die('The program requires Python 3.8 and above')

    # Running as root is required to use the interface
    if os.getuid() != 0:
        src.utils.die('Run it as root')

    # Parse arguments first
    args = parseArgs()

    # Initialize directories
    init_directories()

    # Handle MediaTek WiFi interface
    wmtWifi_device = None
    if args.mtk_wifi:
        wmtWifi_device = init_mtk_wifi(True)

    # Initialize interface
    if not src.utils.ifaceCtl(args.interface, action='up'):
        src.utils.die(f'Unable to up interface \'{args.interface}\'')

    try:
        exit_code = main(args)
        sys.exit(exit_code)
    except Exception as e:
        print(f'[!] Fatal error: {str(e)}')
        sys.exit(1)
    finally:
        # Cleanup
        if args.iface_down:
            src.utils.ifaceCtl(args.interface, action='down')
        if wmtWifi_device:
            wmtWifi_device.write_text('0', encoding='utf-8')
