#!/usr/bin/env python3

import os
import time
import json
import subprocess
from datetime import datetime

# Whitelist of trusted USB devices (VID:PID)
TRUSTED_DEVICES = {
    "0951:1642": "Kingston DT101 G2",
    "0483:5740": "ST-Link V2",
    "8087:0029": "Intel Wireless Device"
}

# Blacklist of known malicious devices (VID:PID)
MALICIOUS_DEVICES = {
    "1234:5678": "Known BadUSB",
    "abcd:ef01": "Suspicious HID Device"
}

def get_usb_devices():
    """Fetch connected USB devices using lsusb and sysfs."""
    devices = {}

    # Run lsusb command to get device list
    try:
        lsusb_output = subprocess.check_output("lsusb", shell=True, text=True).strip().split("\n")
    except subprocess.CalledProcessError:
        return {}

    for line in lsusb_output:
        parts = line.split()
        bus = parts[1]
        device = parts[3][:-1]  # Remove trailing colon
        vid_pid = f"{parts[5]}:{parts[6]}"
        device_path = f"/dev/bus/usb/{bus}/{device}"

        # Fetch manufacturer and product details from sysfs
        sysfs_path = f"/sys/bus/usb/devices/{bus}-{device}"
        manufacturer = read_sysfs(sysfs_path, "manufacturer")
        product = read_sysfs(sysfs_path, "product")

        devices[device_path] = {
            "vid_pid": vid_pid,
            "manufacturer": manufacturer or "Unknown",
            "product": product or "Unknown",
            "trusted": vid_pid in TRUSTED_DEVICES,
            "malicious": vid_pid in MALICIOUS_DEVICES
        }

    return devices

def read_sysfs(path, filename):
    """Read USB information from sysfs."""
    try:
        with open(os.path.join(path, filename)) as f:
            return f.read().strip()
    except FileNotFoundError:
        return None

def monitor_usb():
    """Continuously monitor USB devices and detect new connections."""
    print("USB Security Monitor Started")
    print("Monitoring for malicious USB devices...\n")

    known_devices = get_usb_devices()

    while True:
        current_devices = get_usb_devices()

        # Detect new devices
        for dev_path, dev_info in current_devices.items():
            if dev_path not in known_devices:
                print(f"\n🔌 New USB device detected at {dev_path}")
                print(json.dumps(dev_info, indent=2))

                # Trust check
                if dev_info["trusted"]:
                    print(f"✅ Trusted device: {TRUSTED_DEVICES[dev_info['vid_pid']]}")
                elif dev_info["malicious"]:
                    print(f"🚨 WARNING: Malicious device detected - {MALICIOUS_DEVICES[dev_info['vid_pid']]}")
                    log_security_alert(dev_info, "Known malicious USB device detected")
                else:
                    print("⚠ Unknown device detected!")
                    log_security_alert(dev_info, "Untrusted USB device connected")

        # Detect removed devices
        for dev_path in list(known_devices.keys()):
            if dev_path not in current_devices:
                print(f"\n❌ USB device removed: {dev_path}")
                del known_devices[dev_path]

        known_devices = current_devices
        time.sleep(2)  # Polling interval

def log_security_alert(device_info, reason):
    """Log security alerts with timestamp."""
    alert = {
        "timestamp": datetime.now().isoformat(),
        "device": device_info,
        "reason": reason
    }
    print("\n🚨 SECURITY ALERT 🚨")
    print(json.dumps(alert, indent=2))

if __name__ == "__main__":
    try:
        monitor_usb()
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
