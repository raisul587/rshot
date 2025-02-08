"""WPS PIN generation module."""

from typing import List, Dict, Optional, Union, Tuple
from .router_config import RouterConfig, PinAlgorithm
from .pin_predictor import PinPredictor

class NetworkAddress:
    """Handles MAC addresses"""

    def __init__(self, mac):
        if isinstance(mac, int):
            self._INT_REPR = mac
            self._STR_REPR = self._int2mac(mac)
        elif isinstance(mac, str):
            self._STR_REPR = mac.replace('-', ':').replace('.', ':').upper()
            self._INT_REPR = self._mac2int(mac)

    @staticmethod
    def _mac2int(mac) -> int:
        """Converts MAC address to integer"""
        return int(mac.replace(':', ''), 16)

    @staticmethod
    def _int2mac(mac) -> str:
        """Converts integer to MAC address"""
        mac = hex(mac).split('x')[-1].upper()
        mac = mac.zfill(12)
        mac = ':'.join(mac[i: i + 2] for i in range(0, 12, 2))
        return mac

    @property
    def STRING(self):
        return self._STR_REPR

    @STRING.setter
    def STRING(self, value):
        self._STR_REPR = value
        self._INT_REPR = self._mac2int(value)

    @property
    def INTEGER(self):
        return self._INT_REPR

    @INTEGER.setter
    def INTEGER(self, value):
        self._INT_REPR = value
        self._STR_REPR = self._int2mac(value)

    def __int__(self):
        return self.INTEGER

    def __str__(self):
        return self.STRING

    def __iadd__(self, other):
        self.INTEGER += other
        return self

class WPSpin:
    """WPS pin generator."""

    def __init__(self):
        self.ALGO_MAC = 0
        self.ALGO_EMPTY = 1
        self.ALGO_STATIC = 2
        self.router_config = RouterConfig()
        self.pin_predictor = PinPredictor()

        # Legacy algorithms for backward compatibility
        self.LEGACY_ALGOS = {
            'pin24': {'name': '24-bit PIN', 'mode': self.ALGO_MAC, 'gen': self._pin24},
            'pin28': {'name': '28-bit PIN', 'mode': self.ALGO_MAC, 'gen': self._pin28},
            'pin32': {'name': '32-bit PIN', 'mode': self.ALGO_MAC, 'gen': self._pin32},
            'pinDLink': {'name': 'D-Link PIN', 'mode': self.ALGO_MAC, 'gen': self._pinDLink},
            'pinDLink1': {'name': 'D-Link PIN +1', 'mode': self.ALGO_MAC, 'gen': self._pinDLink1},
            'pinASUS': {'name': 'ASUS PIN', 'mode': self.ALGO_MAC, 'gen': self._pinASUS},
            'pinAirocon': {'name': 'Airocon Realtek', 'mode': self.ALGO_MAC, 'gen': self._pinAirocon}
        }

    def promptPin(self, bssid: str, model: Optional[str] = None) -> Optional[str]:
        """Prompts to select a WPS pin from a list of suggested pins."""
        pins = self._getSuggested(bssid, model)

        if len(pins) > 1:
            print(f'PINs generated for {bssid}:')
            print('{:<3} {:<10} {:<} {:<}'.format(
                '#', 'PIN', 'Confidence', 'Source'
            ))

            for i, pin in enumerate(pins):
                number = f'{i + 1})'
                confidence = f"{pin.get('confidence', 0)*100:.1f}%" if 'confidence' in pin else 'N/A'
                line = '{:<3} {:<10} {:<10} {:<}'.format(
                    number, pin['pin'], confidence, pin['name'])
                print(line)

            while True:
                pin_no = input('Select the PIN: ')
                try:
                    if int(pin_no) in range(1, len(pins) + 1):
                        pin = pins[int(pin_no) - 1]['pin']
                    else:
                        raise ValueError
                except ValueError:
                    print('Invalid number')
                else:
                    break

        elif len(pins) == 1:
            pin = pins[0]
            confidence = f"{pin.get('confidence', 0)*100:.1f}%" if 'confidence' in pin else 'N/A'
            print(f'[*] The only probable PIN is selected: {pin["name"]} (Confidence: {confidence})')
            pin = pin['pin']
        else:
            return None

        return pin

    def getLikely(self, bssid: str, model: Optional[str] = None) -> Optional[str]:
        """Returns a likely pin."""
        res = self._getSuggestedList(bssid, model)
        if res:
            return res[0]
        return None

    @staticmethod
    def checksum(pin: int) -> int:
        """Standard WPS checksum algorithm."""
        accum = 0
        while pin:
            accum += (3 * (pin % 10))
            pin = int(pin / 10)
            accum += (pin % 10)
            pin = int(pin / 10)
        return (10 - accum % 10) % 10

    def _generate_pin(self, mac: NetworkAddress, algorithm: PinAlgorithm) -> str:
        """Generate PIN using specified algorithm."""
        if algorithm.method == "static" and algorithm.pins:
            return algorithm.pins[0]  # Use first static PIN

        if not algorithm.formula:
            return ""

        # Get the last 6 digits of MAC
        mac_last_6 = mac.INTEGER & 0xFFFFFF

        # Apply the formula
        if algorithm.formula == "mac_last_6 + checksum":
            pin = mac_last_6 % 10000000
            return str(pin) + str(self.checksum(pin))

        elif algorithm.formula == "mac_last_6_reversed + checksum":
            # Reverse the last 6 digits
            mac_str = format(mac_last_6, '06x')
            reversed_mac = int(mac_str[::-1], 16)
            pin = reversed_mac % 10000000
            return str(pin) + str(self.checksum(pin))

        elif algorithm.formula == "nic_based + checksum":
            # Similar to D-Link algorithm
            nic = mac.INTEGER & 0xFFFFFF
            pin = ((nic & 0xF) << 4) + ((nic & 0xF) << 8) + \
                  ((nic & 0xF) << 12) + ((nic & 0xF) << 16) + \
                  ((nic & 0xF) << 20)
            pin %= 10000000
            if pin < 1000000:
                pin += ((pin % 9) * 1000000) + 1000000
            return str(pin) + str(self.checksum(pin))

        elif algorithm.formula == "serial_based + checksum":
            # Convert last 6 digits to decimal and use as PIN
            pin = int(format(mac_last_6, '06x')) % 10000000
            return str(pin) + str(self.checksum(pin))

        return ""

    def _getSuggested(self, bssid: str, model: Optional[str] = None) -> List[Dict[str, str]]:
        """Get all suggested WPS pin's for single MAC."""
        mac = NetworkAddress(bssid)
        
        # Get vendor from router config
        vendor = self.router_config.get_vendor_by_mac(bssid)
        vendor_name = vendor.name if vendor else None
        
        res = []
        
        # First try ML predictions if we have vendor information
        if vendor_name:
            ml_predictions = self.pin_predictor.predict_pins(bssid, vendor_name, model)
            for pin, confidence in ml_predictions:
                res.append({
                    'id': 'ml_prediction',
                    'name': f'ML Prediction - {vendor_name}',
                    'pin': pin,
                    'confidence': confidence
                })

        # Then try new algorithms from router config
        algorithms = self.router_config.get_pin_algorithms(bssid, model)
        for algo in algorithms:
            pin = self._generate_pin(mac, algo)
            if pin:
                res.append({
                    'id': algo.name,
                    'name': f"{algo.name} - {algo.description}",
                    'pin': pin.zfill(8)
                })

        # Finally try legacy algorithms for backward compatibility
        legacy_algos = self._suggest_legacy(bssid)
        for algo_id in legacy_algos:
            algo = self.LEGACY_ALGOS[algo_id]
            pin = self._generate_legacy(algo_id, bssid)
            res.append({
                'id': algo_id,
                'name': f"Legacy - {algo['name']}",
                'pin': pin
            })

        return res

    def _getSuggestedList(self, bssid: str, model: Optional[str] = None) -> List[str]:
        """Get all suggested WPS pin's for single MAC as list."""
        suggested = self._getSuggested(bssid, model)
        return [pin['pin'] for pin in suggested]

    def _suggest_legacy(self, bssid: str) -> List[str]:
        """Get legacy algorithm suggestions for a BSSID."""
        mac = bssid.replace(':', '').upper()
        algorithms = {
            'pin24': (
                '04BF6D', '0E5D4E', '107BEF', '14A9E3', '28285D', '32B2DC', 
                '381766', '404A03', '40B7F3', '44E9DD', '48EE0C', '5CE50C', 
                '62233D', '626BD3', '646CB2', '66B0B4', '0022F7', '788DF7', 
                '789682', '7C8BCA', '8C68C8', '8CAB8E', '8CE748', '8CF228', 
                '90C7D8', '98FFD0', '9C5D12', 'A0AB1B', 'A4C64F', 'AC9A96',
                'B07E70', 'B0B2DC', 'C4A81D', 'C82E47', 'CCB255', 'D86CE9',
                'DC7144', 'E86D52', 'E8CD2D', 'EC233D', 'EC4D47', 'F8C091',
                'D4BF7F4', '0C8063'  # Added your router's prefix
            ),
            'pin28': (
                '200BC7', '4846FB', 'D46AA8', 'F84ABF', '0014D1', '000D88',
                '001D7E', '002275', '08863B'
            ),
            'pin32': (
                '000726', 'D8FEE3', 'FC8B97', '144D67', '2008ED', '207355',
                '24336C', '28EE52', '4C09B4', '4CAC0A', '6045CB', '88E3AB',
                '9094E4', 'BC1401', 'C8D15E'
            ),
            'pinDLink': (
                '14D64D', '1C7EE5', '28107B', '84C9B2', 'A0AB1B', 'B8A386',
                'C0A0BB', 'CCB255', 'FC7516'
            ),
            'pinASUS': (
                '049226', '04D9F5', '08606E', '0862669', '107B44', '10BF48',
                '14DDA9', '1C872C', '2C56DC', '305A3A', '382C4A', '40167E',
                '50465D', '54A050', '6045CB', 'AC220B', 'BC9CC5', 'E03F49'
            ),
            'pinAirocon': (
                '0007262F', '000B2B4A', '000726B', '00168F'
            )
        }
        
        res = []
        for algo_id, masks in algorithms.items():
            if any(mac.startswith(mask) for mask in masks):
                res.append(algo_id)
        
        # If no specific algorithm matched, add some default algorithms
        if not res:
            res.extend(['pin24', 'pin32'])  # Try these common algorithms as fallback
            
        return res

    def _generate_legacy(self, algo: str, bssid: str) -> str:
        """Generate PIN using legacy algorithm."""
        mac = NetworkAddress(bssid)
        if algo not in self.LEGACY_ALGOS:
            raise ValueError('Invalid WPS pin algorithm')

        pin = self.LEGACY_ALGOS[algo]['gen'](mac)

        if self.LEGACY_ALGOS[algo]['mode'] == self.ALGO_EMPTY:
            return pin

        pin = pin % 10000000
        pin = str(pin) + str(self.checksum(pin))
        return pin.zfill(8)

    # Legacy PIN generation methods preserved for backward compatibility
    @staticmethod
    def _pin24(bssid: str):
        return bssid.INTEGER & 0xFFFFFF

    @staticmethod
    def _pin28(bssid: str):
        return bssid.INTEGER & 0xFFFFFFF

    @staticmethod
    def _pin32(bssid: str):
        return bssid.INTEGER % 0x100000000

    @staticmethod
    def _pinDLink(bssid: str):
        nic = bssid.INTEGER & 0xFFFFFF
        pin = ((nic & 0xF) << 4) + ((nic & 0xF) << 8) + \
              ((nic & 0xF) << 12) + ((nic & 0xF) << 16) + \
              ((nic & 0xF) << 20)
        pin %= int(10e6)
        if pin < int(10e5):
            pin += ((pin % 9) * int(10e5)) + int(10e5)
        return pin

    def _pinDLink1(self, bssid: str):
        bssid.INTEGER += 1
        return self._pinDLink(bssid)

    @staticmethod
    def _pinASUS(bssid: str):
        b = [int(i, 16) for i in bssid.STRING.split(':')]
        pin = ((b[5] + b[4]) % 10) + \
              (((b[4] + b[5]) % 10) * 10) + \
              (((b[3] + b[4]) % 10) * 100) + \
              (((b[2] + b[3]) % 10) * 1000) + \
              (((b[1] + b[2]) % 10) * 10000) + \
              (((b[0] + b[1]) % 10) * 100000)
        return pin

    @staticmethod
    def _pinAirocon(bssid: str):
        return bssid.INTEGER % 0x100000000

    def record_attempt(self, bssid: str, pin: str, success: bool):
        """Record a PIN attempt for machine learning."""
        vendor = self.router_config.get_vendor_by_mac(bssid)
        vendor_name = vendor.name if vendor else None
        self.pin_predictor.record_attempt(bssid, pin, success, vendor=vendor_name)

    def get_vendor_statistics(self, vendor: str) -> Optional[Dict]:
        """Get statistics for a vendor."""
        return self.pin_predictor.get_vendor_statistics(vendor)

    def get_model_statistics(self, model: str) -> Optional[Dict]:
        """Get statistics for a specific model."""
        return self.pin_predictor.get_model_statistics(model)
