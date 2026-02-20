import frida
from dataclasses import dataclass
from typing import List
from pathlib import Path

@dataclass
class Device:
    id: str
    name: str
    type: str

class MobileInstrumentor:
    """Frida-based runtime instrumentation"""

    def list_devices(self) -> List[Device]:
        """List available Frida devices"""
        devices = []

        for dev in frida.enumerate_devices():
            devices.append(Device(
                id=dev.id,
                name=dev.name,
                type=dev.type
            ))

        return devices

    def get_device(self, device_type: str = 'usb'):
        """Get device by type"""
        if device_type == 'usb':
            return frida.get_usb_device()
        elif device_type == 'local':
            return frida.get_local_device()
        else:
            return frida.get_device(device_type)

    def attach(self, device, app_name: str):
        """Attach to running app"""
        try:
            session = device.attach(app_name)
            return session
        except Exception as e:
            print(f"[!] Failed to attach to {app_name}: {e}")
            return None

    def load_script(self, script_path: Path) -> str:
        """Load Frida script from file"""
        with open(script_path, 'r') as f:
            return f.read()
