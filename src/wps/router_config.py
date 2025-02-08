"""Router configuration and PIN generation module."""

import os
import yaml
from typing import Dict, List, Optional, Union
from dataclasses import dataclass
from pathlib import Path

@dataclass
class PinAlgorithm:
    """PIN generation algorithm configuration."""
    name: str
    description: str
    method: str
    formula: Optional[str] = None
    models: Optional[List[str]] = None
    pins: Optional[List[str]] = None

@dataclass
class VendorTiming:
    """Vendor-specific timing configuration."""
    initial_delay: float
    retry_delay: float
    max_retries: int

@dataclass
class VendorConfig:
    """Vendor configuration."""
    name: str
    models: Dict[str, List[str]]
    mac_prefixes: List[str]
    pin_algorithms: List[PinAlgorithm]
    timing: VendorTiming

class RouterConfig:
    """Router configuration manager."""

    def __init__(self):
        self.config_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'config',
            'router_config.yaml'
        )
        self.config = self._load_config()
        self.default_timing = self._parse_default_timing()
        self.vendors = self._parse_vendors()

    def _load_config(self) -> dict:
        """Load configuration from YAML file."""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            print(f"[!] Configuration file not found: {self.config_path}")
            return {}
        except yaml.YAMLError as e:
            print(f"[!] Error parsing configuration: {e}")
            return {}

    def _parse_default_timing(self) -> VendorTiming:
        """Parse default timing configuration."""
        timing = self.config.get('default_timing', {})
        return VendorTiming(
            initial_delay=timing.get('initial_delay', 0.5),
            retry_delay=timing.get('retry_delay', 1.0),
            max_retries=timing.get('max_retries', 3)
        )

    def _parse_vendors(self) -> Dict[str, VendorConfig]:
        """Parse vendor configurations."""
        vendors = {}
        for vendor_id, vendor_data in self.config.get('vendors', {}).items():
            try:
                timing_data = vendor_data.get('timing', {})
                timing = VendorTiming(
                    initial_delay=timing_data.get('initial_delay', self.default_timing.initial_delay),
                    retry_delay=timing_data.get('retry_delay', self.default_timing.retry_delay),
                    max_retries=timing_data.get('max_retries', self.default_timing.max_retries)
                )

                algorithms = []
                for algo_data in vendor_data.get('pin_algorithms', []):
                    algorithms.append(PinAlgorithm(
                        name=algo_data['name'],
                        description=algo_data['description'],
                        method=algo_data['method'],
                        formula=algo_data.get('formula'),
                        models=algo_data.get('models'),
                        pins=algo_data.get('pins')
                    ))

                vendors[vendor_id] = VendorConfig(
                    name=vendor_data['name'],
                    models=vendor_data.get('models', {}),
                    mac_prefixes=vendor_data.get('mac_prefixes', []),
                    pin_algorithms=algorithms,
                    timing=timing
                )
            except KeyError as e:
                print(f"[!] Error parsing vendor {vendor_id}: {e}")
                continue

        return vendors

    def get_vendor_by_mac(self, mac: str) -> Optional[VendorConfig]:
        """Get vendor configuration by MAC address."""
        mac = mac.replace(':', '').upper()
        for vendor in self.vendors.values():
            for prefix in vendor.mac_prefixes:
                if mac.startswith(prefix):
                    return vendor
        return None

    def get_pin_algorithms(self, mac: str, model: Optional[str] = None) -> List[PinAlgorithm]:
        """Get PIN algorithms for a specific MAC address and model."""
        vendor = self.get_vendor_by_mac(mac)
        if not vendor:
            return []

        if not model:
            return vendor.pin_algorithms

        matching_algos = []
        for algo in vendor.pin_algorithms:
            if not algo.models or model in algo.models:
                matching_algos.append(algo)

        return matching_algos

    def get_timing(self, mac: str) -> VendorTiming:
        """Get timing configuration for a specific MAC address."""
        vendor = self.get_vendor_by_mac(mac)
        return vendor.timing if vendor else self.default_timing

    def is_supported_model(self, model: str) -> bool:
        """Check if a model is supported."""
        for vendor in self.vendors.values():
            for model_list in vendor.models.values():
                if model in model_list:
                    return True
            if isinstance(vendor.models, list) and model in vendor.models:
                return True
        return False

    def get_supported_models(self) -> List[str]:
        """Get a list of all supported models."""
        models = []
        for vendor in self.vendors.values():
            if isinstance(vendor.models, dict):
                for model_list in vendor.models.values():
                    models.extend(model_list)
            elif isinstance(vendor.models, list):
                models.extend(vendor.models)
        return sorted(models)

    def get_mac_prefixes(self) -> Dict[str, List[str]]:
        """Get all MAC prefixes grouped by vendor."""
        return {
            vendor_id: vendor.mac_prefixes
            for vendor_id, vendor in self.vendors.items()
        }

    def get_vendor_names(self) -> List[str]:
        """Get a list of supported vendor names."""
        return [vendor.name for vendor in self.vendors.values()]

    def get_pin_methods(self) -> Dict[str, List[Dict[str, str]]]:
        """Get available PIN generation methods."""
        return self.config.get('pin_methods', {})

    def get_wps_versions(self) -> List[Dict[str, Union[str, bool]]]:
        """Get WPS version information."""
        return self.config.get('wps_versions', []) 