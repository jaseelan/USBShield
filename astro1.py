#!/usr/bin/env python3

import os
import sys
import time
import json
import psutil
from datetime import datetime

# Trusted and malicious USB device lists
TRUSTED_DEVICES = {
    "0x0483:0x5740": "ST-Link V2",
    "0x8087:0x0029": "Intel Wireless Device",
    "0x0951:0x1666": "Kingston Flash Drive"
}

MALICIOUS_SIGNATURES = {
    "0x1234:0x5678": "Known BadUSB Device",
    "0xabcd:0xef01": "Suspicious HID Device"
}

# File types to analyze for security risks
EXECUTABLE_EXTENSIONS = {".exe", ".sh", ".bat", ".dll", ".py", ".vbs"}

class USBSecurityMonitor:
    def __init__(self):
        self.connected_devices = {}

    def get_mounted_usb_drives(self):
        """Detects mounted USB drives and retrieves details."""
        usb_drives = []
        partitions = psutil.disk_partitions()
        for partition in partitions:
            if "usb" in partition.opts or "/media" in partition.mountpoint:
                usb_drives.append(partition.mountpoint)
        return usb_drives

    def get_usb_storage_details(self, mount_point):
        """Retrieve USB storage details (total size, used space, free space)."""
        try:
            usage = psutil.disk_usage(mount_point)
            return {
                "total_size": f"{usage.total / (1024**3):.2f} GB",
                "used_size": f"{usage.used / (1024**3):.2f} GB",
                "free_size": f"{usage.free / (1024**3):.2f} GB"
            }
        except Exception as e:
            return {"error": f"Failed to retrieve storage info: {e}"}

    def count_files_and_executables(self, path):
        """Counts total files, directories, and executable files on the USB."""
        total_files = 0
        total_dirs = 0
        exec_files = []

        for root, dirs, files in os.walk(path):
            total_dirs += len(dirs)
            total_files += len(files)
            for file in files:
                if any(file.lower().endswith(ext) for ext in EXECUTABLE_EXTENSIONS):
                    exec_files.append(os.path.join(root, file))

        return {
            "total_files": total_files,
            "total_directories": total_dirs,
            "executable_files": exec_files
        }

    def scan_connected_devices(self):
        """Scans for connected USB devices (Linux only)."""
        detected_devices = {}
        try:
            if sys.platform.startswith('linux'):
                usb_path = "/sys/bus/usb/devices"
                if os.path.exists(usb_path):
                    for device in os.listdir(usb_path):
                        device_path = os.path.join(usb_path, device)
                        if os.path.exists(os.path.join(device_path, "idVendor")):
                            try:
                                with open(os.path.join(device_path, "idVendor")) as f:
                                    vendor_id = f.read().strip()
                                with open(os.path.join(device_path, "idProduct")) as f:
                                    product_id = f.read().strip()
                                
                                vid_pid = f"0x{vendor_id}:0x{product_id}"
                                manufacturer = self.read_usb_attribute(device_path, "manufacturer")
                                product = self.read_usb_attribute(device_path, "product")

                                detected_devices[device_path] = {
                                    "vid_pid": vid_pid,
                                    "manufacturer": manufacturer,
                                    "product": product
                                }
                            except (IOError, OSError) as e:
                                print(f"Error reading USB device info: {e}")
                                continue
        except Exception as e:
            print(f"USB scanning error: {e}")

        return detected_devices

    def read_usb_attribute(self, device_path, attribute):
        """Reads an attribute of a USB device (e.g., manufacturer, product)."""
        try:
            with open(os.path.join(device_path, attribute)) as f:
                return f.read().strip()
        except:
            return "Unknown"

    def check_device_trustworthiness(self, vid_pid):
        """Checks if the USB device is trusted or malicious."""
        if vid_pid in TRUSTED_DEVICES:
            return True, f"Trusted device: {TRUSTED_DEVICES[vid_pid]}"
        if vid_pid in MALICIOUS_SIGNATURES:
            return False, f"⚠️ WARNING: Malicious device detected - {MALICIOUS_SIGNATURES[vid_pid]}"
        return False, "Unknown device detected"

    def monitor(self):
        """Continuously monitors USB devices and gathers details."""
        print("USB Security Monitor Started\nMonitoring for USB devices...\n")
        try:
            while True:
                current_devices = self.scan_connected_devices()
                usb_drives = self.get_mounted_usb_drives()

                for dev_path, dev_info in current_devices.items():
                    if dev_path not in self.connected_devices:
                        print(f"\n🔌 New USB device detected at {dev_path}")
                        print(f"Device info: {json.dumps(dev_info, indent=2)}")

                        # Trust check
                        trust_status, trust_msg = self.check_device_trustworthiness(dev_info["vid_pid"])
                        print(f"🔍 Trust check: {trust_msg}")

                        # Storage and file details if USB is mounted
                        for drive in usb_drives:
                            print(f"\n📁 USB Mounted at: {drive}")

                            storage_info = self.get_usb_storage_details(drive)
                            file_info = self.count_files_and_executables(drive)

                            print(f"💾 Storage Details: {json.dumps(storage_info, indent=2)}")
                            print(f"📄 Total Files: {file_info['total_files']}, Folders: {file_info['total_directories']}")
                            if file_info['executable_files']:
                                print(f"⚠️ Executable Files Found ({len(file_info['executable_files'])}):")
                                for exe in file_info['executable_files']:
                                    print(f"  - {exe}")

                        # Alert if device is untrusted
                        if not trust_status:
                            alert = {
                                "timestamp": datetime.now().isoformat(),
                                "device": dev_info,
                                "reason": "Untrusted or suspicious device detected"
                            }
                            print("\n⚠️ SECURITY ALERT ⚠️")
                            print(json.dumps(alert, indent=2))

                # Update connected devices list
                self.connected_devices = current_devices

                # Wait before next scan
                time.sleep(2)

        except KeyboardInterrupt:
            print("\nMonitoring stopped by user.")

if __name__ == "__main__":
    monitor = USBSecurityMonitor()
    monitor.monitor()
