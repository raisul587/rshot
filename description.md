# OneShot-Extended Project Documentation

This document provides a comprehensive overview of the OneShot-Extended project, its modules, and their functionalities.

## Project Structure

```
.
├── ose.py                 # Main entry point script
├── src/
│   ├── wifi/             # WiFi-related functionality
│   │   ├── scanner.py    # WiFi network scanning
│   │   ├── collector.py  # Data collection utilities
│   │   └── android.py    # Android-specific functionality
│   ├── wps/              # WPS attack implementations
│   │   ├── pixiewps.py   # Pixie Dust attack implementation
│   │   ├── generator.py  # PIN generation utilities
│   │   ├── connection.py # WPS connection handling
│   │   └── bruteforce.py # Bruteforce attack implementation
│   ├── utils.py          # Common utility functions
│   └── args.py           # Command-line argument parsing
```

## Module Descriptions

### Main Script (ose.py)
The main entry point of the application that orchestrates the entire workflow. Key functionalities include:
- Python version verification (requires 3.8+)
- Root privilege checking
- Interface management
- MediaTek WiFi interface support
- Main execution loop for scanning and attacking

### Arguments Module (src/args.py)
Handles command-line argument parsing with the following key options:
- `-i, --interface`: Specify network interface
- `-b, --bssid`: Target AP BSSID
- `-p, --pin`: Specify WPS PIN
- `-K, --pixie-dust`: Enable Pixie Dust attack
- `-B, --bruteforce`: Enable bruteforce attack
- `--pbc`: WPS push button connection
- Various other options for customization and control

### WiFi Package (src/wifi/)

#### scanner.py
Implements WiFi network scanning functionality:
- Network discovery
- Signal strength monitoring
- Vulnerable network identification

#### collector.py
Handles data collection from wireless networks:
- Network information gathering
- Data parsing and organization
- Statistics collection

#### android.py
Android-specific implementations:
- WiFi state management
- Android system integration
- Network configuration

### WPS Package (src/wps/)

#### pixiewps.py
Implements the Pixie Dust attack:
- E-Hash verification
- Key generation
- Attack execution

#### generator.py
PIN generation utilities:
- Algorithm implementations
- PIN validation
- Pattern generation

#### connection.py
WPS connection handling:
- Authentication
- Association
- Protocol state machine
- Connection management

#### bruteforce.py
Implements WPS bruteforce attacks:
- PIN sequence generation
- Rate limiting
- Success verification

### Utilities (src/utils.py)
Common utility functions used across the project:
- Interface control
- Screen management
- File operations
- System checks

## Key Features

1. Multiple Attack Methods:
   - Pixie Dust attack
   - WPS PIN bruteforce
   - Push Button Connection (PBC)

2. Network Management:
   - Automatic interface configuration
   - Network scanning
   - Connection handling

3. Platform Support:
   - Linux systems
   - Android device support
   - MediaTek WiFi interface support

4. User Interface:
   - Command-line interface
   - Progress monitoring
   - Verbose output options
   - Screen management

5. Data Management:
   - Session handling
   - Credential storage
   - Network configuration saving

## Usage Notes

1. Requires root privileges
2. Python 3.8 or higher required
3. Supports various wireless interfaces
4. Can run in loop mode for continuous operation
5. Provides options for credential storage and network management 