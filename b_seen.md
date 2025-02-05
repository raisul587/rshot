# OneShot-Extended: Behind the Scenes Analysis

This document provides a detailed analysis of how OneShot-Extended works behind the scenes, breaking down the functionality of each component.

## Core Components

### 1. Main Entry Point (`ose.py`)
- Main script that orchestrates the entire application
- Handles argument parsing and initializes core components
- Controls the main workflow of the WPS attack process

### 2. Argument Handling (`src/args.py`)
- Parses command-line arguments
- Configures program settings and attack parameters
- Validates user input and interface settings

### 3. Utility Functions (`src/utils.py`)
- Contains helper functions used throughout the application
- Handles system-specific operations (Android detection, interface control)
- Provides screen clearing and error handling utilities

## WiFi Components (`src/wifi/`)

### 1. Scanner (`wifi/scanner.py`)
- Class: `WiFiScanner`
- Handles network scanning and parsing results
- Maintains list of vulnerable networks
- Provides interactive network selection interface
- Stores previously found networks for quick reference

### 2. Collector (`wifi/collector.py`)
- Class: `WiFiCollector`
- Manages successful attack results
- Stores discovered network credentials
- Handles network configuration storage
- Writes results to files for later use

### 3. Android Support (`wifi/android.py`)
- Class: `AndroidNetwork`
- Manages Android-specific WiFi operations
- Controls WiFi state (enable/disable)
- Handles Android's "always scanning" feature

## WPS Attack Components (`src/wps/`)

### 1. Bruteforce Module (`wps/bruteforce.py`)
- Classes: `Initialize`, `BruteforceStatus`
- Implements WPS PIN bruteforce strategy
- Tracks attack progress and statistics
- Handles both first-half and second-half PIN attacks
- Manages timing and delay between attempts

### 2. Connection Handler (`wps/connection.py`)
- Classes: `Initialize`, `ConnectionStatus`
- Manages WPA supplicant connections
- Handles WPS authentication process
- Tracks connection states and messages
- Manages temporary files and sockets

### 3. PIN Generator (`wps/generator.py`)
- Class: `WPSpin`
- Implements PIN generation algorithms
- Provides smart PIN suggestions based on BSSID
- Handles PIN validation and checksum calculations

### 4. Pixie Dust Attack (`wps/pixiewps.py`)
- Implements Pixie Dust attack method
- Handles pixiewps tool integration
- Manages attack data and credentials

## Key Features

1. **Multi-Attack Strategy**
   - Supports both PIN bruteforce and Pixie Dust attacks
   - Implements smart PIN generation algorithms
   - Handles various WPS vulnerability types

2. **Platform Compatibility**
   - Works on both desktop Linux and Android systems
   - Adapts behavior based on platform detection
   - Handles platform-specific network management

3. **Result Management**
   - Stores successful attack results
   - Maintains database of vulnerable networks
   - Provides CSV and text-based result storage

4. **Progress Tracking**
   - Real-time attack progress monitoring
   - Statistical analysis of attempt times
   - Detailed status reporting

## Data Flow

1. Program starts with interface initialization
2. Scanner identifies potential target networks
3. Attack module attempts WPS exploitation
4. Results are collected and stored
5. Network credentials are saved for later use

## Error Handling

- Comprehensive error checking throughout the codebase
- Graceful handling of connection failures
- Clean termination of processes and resources
- Temporary file management and cleanup

This codebase is designed with modularity in mind, separating different concerns into logical components while maintaining efficient communication between modules.
