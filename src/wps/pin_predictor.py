"""Machine learning based WPS PIN prediction module."""

import os
import json
import numpy as np
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
from datetime import datetime
from collections import Counter

@dataclass
class PinAttempt:
    """Represents a single PIN attempt."""
    bssid: str
    pin: str
    success: bool
    timestamp: float
    model: Optional[str] = None
    vendor: Optional[str] = None

@dataclass
class VendorPattern:
    """Represents PIN patterns for a vendor."""
    common_prefixes: List[str]
    common_suffixes: List[str]
    digit_frequencies: List[Dict[int, float]]
    success_rate: float

class PinPredictor:
    """Machine learning based PIN predictor."""

    def __init__(self):
        self.data_dir = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'data'
        )
        os.makedirs(self.data_dir, exist_ok=True)
        
        self.history_file = os.path.join(self.data_dir, 'pin_history.json')
        self.patterns_file = os.path.join(self.data_dir, 'pin_patterns.json')
        
        self.attempts: List[PinAttempt] = []
        self.vendor_patterns: Dict[str, VendorPattern] = {}
        
        self._load_history()
        self._load_patterns()

    def _load_history(self):
        """Load PIN attempt history."""
        try:
            with open(self.history_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.attempts = [
                    PinAttempt(
                        bssid=item['bssid'],
                        pin=item['pin'],
                        success=item['success'],
                        timestamp=item['timestamp'],
                        model=item.get('model'),
                        vendor=item.get('vendor')
                    )
                    for item in data
                ]
        except FileNotFoundError:
            self.attempts = []

    def _save_history(self):
        """Save PIN attempt history."""
        data = [
            {
                'bssid': attempt.bssid,
                'pin': attempt.pin,
                'success': attempt.success,
                'timestamp': attempt.timestamp,
                'model': attempt.model,
                'vendor': attempt.vendor
            }
            for attempt in self.attempts
        ]
        with open(self.history_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

    def _load_patterns(self):
        """Load vendor PIN patterns."""
        try:
            with open(self.patterns_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.vendor_patterns = {
                    vendor: VendorPattern(
                        common_prefixes=pattern['common_prefixes'],
                        common_suffixes=pattern['common_suffixes'],
                        digit_frequencies=pattern['digit_frequencies'],
                        success_rate=pattern['success_rate']
                    )
                    for vendor, pattern in data.items()
                }
        except FileNotFoundError:
            self.vendor_patterns = {}

    def _save_patterns(self):
        """Save vendor PIN patterns."""
        data = {
            vendor: {
                'common_prefixes': pattern.common_prefixes,
                'common_suffixes': pattern.common_suffixes,
                'digit_frequencies': pattern.digit_frequencies,
                'success_rate': pattern.success_rate
            }
            for vendor, pattern in self.vendor_patterns.items()
        }
        with open(self.patterns_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

    def record_attempt(self, bssid: str, pin: str, success: bool,
                      model: Optional[str] = None, vendor: Optional[str] = None):
        """Record a PIN attempt."""
        attempt = PinAttempt(
            bssid=bssid,
            pin=pin,
            success=success,
            timestamp=datetime.now().timestamp(),
            model=model,
            vendor=vendor
        )
        self.attempts.append(attempt)
        self._save_history()
        self._update_patterns(attempt)

    def _update_patterns(self, attempt: PinAttempt):
        """Update vendor patterns with new attempt data."""
        if not attempt.vendor:
            return

        if attempt.vendor not in self.vendor_patterns:
            self.vendor_patterns[attempt.vendor] = VendorPattern(
                common_prefixes=[],
                common_suffixes=[],
                digit_frequencies=[{} for _ in range(8)],
                success_rate=0.0
            )

        pattern = self.vendor_patterns[attempt.vendor]

        # Update prefix/suffix frequencies
        prefix = attempt.pin[:4]
        suffix = attempt.pin[4:]
        
        if attempt.success:
            if prefix not in pattern.common_prefixes:
                pattern.common_prefixes.append(prefix)
            if suffix not in pattern.common_suffixes:
                pattern.common_suffixes.append(suffix)

        # Update digit frequencies
        vendor_attempts = [a for a in self.attempts if a.vendor == attempt.vendor]
        total_attempts = len(vendor_attempts)
        successful_attempts = len([a for a in vendor_attempts if a.success])
        
        pattern.success_rate = successful_attempts / total_attempts if total_attempts > 0 else 0.0

        # Calculate digit frequencies
        for pos in range(8):
            freq = Counter(a.pin[pos] for a in vendor_attempts)
            total = sum(freq.values())
            pattern.digit_frequencies[pos] = {
                int(digit): count/total
                for digit, count in freq.items()
            }

        self._save_patterns()

    def predict_pins(self, bssid: str, vendor: Optional[str] = None,
                    model: Optional[str] = None, top_n: int = 5) -> List[Tuple[str, float]]:
        """Predict most likely PINs for a device."""
        if not vendor or vendor not in self.vendor_patterns:
            return []

        pattern = self.vendor_patterns[vendor]
        
        # If we have successful PINs for this vendor, prioritize their patterns
        if pattern.common_prefixes and pattern.common_suffixes:
            pins = []
            for prefix in pattern.common_prefixes:
                for suffix in pattern.common_suffixes:
                    pin = prefix + suffix
                    # Calculate probability based on digit frequencies
                    prob = 1.0
                    for pos, digit in enumerate(pin):
                        prob *= pattern.digit_frequencies[pos].get(int(digit), 0.01)
                    pins.append((pin, prob * pattern.success_rate))
            
            # Sort by probability and return top N
            pins.sort(key=lambda x: x[1], reverse=True)
            return pins[:top_n]

        # If no successful patterns, generate PINs based on digit frequencies
        pins = []
        for _ in range(top_n * 2):  # Generate more than needed and take top N
            pin = ''
            prob = 1.0
            for pos in range(8):
                if not pattern.digit_frequencies[pos]:
                    # If no frequency data, use uniform distribution
                    digit = np.random.randint(0, 10)
                    prob *= 0.1
                else:
                    # Sample digit based on frequencies
                    digits, freqs = zip(*pattern.digit_frequencies[pos].items())
                    digit = int(np.random.choice(digits, p=freqs))
                    prob *= pattern.digit_frequencies[pos][digit]
                pin += str(digit)
            pins.append((pin, prob * pattern.success_rate))

        pins.sort(key=lambda x: x[1], reverse=True)
        return pins[:top_n]

    def get_vendor_statistics(self, vendor: str) -> Optional[Dict]:
        """Get statistics for a vendor."""
        if vendor not in self.vendor_patterns:
            return None

        pattern = self.vendor_patterns[vendor]
        vendor_attempts = [a for a in self.attempts if a.vendor == vendor]
        
        return {
            'total_attempts': len(vendor_attempts),
            'successful_attempts': len([a for a in vendor_attempts if a.success]),
            'success_rate': pattern.success_rate,
            'common_prefixes': pattern.common_prefixes,
            'common_suffixes': pattern.common_suffixes,
            'most_common_digits': [
                {str(k): v for k, v in sorted(freq.items(), key=lambda x: x[1], reverse=True)[:3]}
                for freq in pattern.digit_frequencies
            ]
        }

    def get_model_statistics(self, model: str) -> Optional[Dict]:
        """Get statistics for a specific model."""
        model_attempts = [a for a in self.attempts if a.model == model]
        if not model_attempts:
            return None

        successful = [a for a in model_attempts if a.success]
        return {
            'total_attempts': len(model_attempts),
            'successful_attempts': len(successful),
            'success_rate': len(successful) / len(model_attempts),
            'successful_pins': [a.pin for a in successful],
            'last_successful_attempt': max(successful, key=lambda x: x.timestamp).timestamp if successful else None
        }

    def clear_history(self):
        """Clear PIN attempt history."""
        self.attempts = []
        self.vendor_patterns = {}
        self._save_history()
        self._save_patterns() 