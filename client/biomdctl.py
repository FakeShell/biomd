#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>

import dbus
import dbus.mainloop.glib
from gi.repository import GLib
import threading
import sys
import time
import argparse

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

class BiometricAPI:
    def __init__(self, bus, service_name, object_path, interface_name):
        self.bus = bus
        self.service_name = service_name
        self.object_path = object_path
        self.interface_name = interface_name

        try:
            self.proxy_object = bus.get_object(service_name, object_path)
            self.interface = dbus.Interface(self.proxy_object, interface_name)
            self.properties = dbus.Interface(self.proxy_object, 'org.freedesktop.DBus.Properties')
        except dbus.exceptions.DBusException as e:
            print(f"Error connecting to {interface_name}: {e}")
            raise

    def get_property(self, name):
        try:
            return self.properties.Get(self.interface_name, name)
        except dbus.exceptions.DBusException as e:
            print(f"Error getting property {name}: {e}")
            return None

    def register_signal(self, signal_name, callback):
        """Register a callback for a D-Bus signal"""
        self.bus.add_signal_receiver(
            callback,
            dbus_interface=self.interface_name,
            signal_name=signal_name
        )

class FingerprintAPI(BiometricAPI):
    def __init__(self, bus):
        super().__init__(
            bus,
            'io.FuriOS.Biomd',
            '/org/FuriOS/Biomd/Fingerprint',
            'io.FuriOS.Biomd.Fingerprint'
        )

        self.register_signals()

        self.states = {
            0: "IDLE",
            1: "ENROLLING",
            2: "IDENTIFYING"
        }

        self.errors = {
            0: "NONE",
            1: "HW_UNAVAILABLE",
            2: "UNABLE_TO_PROCESS",
            3: "TIMEOUT",
            4: "NO_SPACE",
            5: "CANCELED",
            6: "REMOVE",
            7: "LOCKOUT",
            8: "GENERAL"
        }

        self.acquisitions = {
            0: "NONE",
            1: "GOOD",
            2: "PARTIAL",
            3: "INSUFFICIENT",
            4: "IMAGER_DIRTY",
            5: "TOO_SLOW",
            6: "TOO_FAST",
            7: "VENDOR"
        }

    def register_signals(self):
        signals = {
            'StateChanged': self.on_state_changed,
            'EnrollmentProgressChanged': self.on_enrollment_progress_changed,
            'EnrolledFingersChanged': self.on_enrolled_fingers_changed,
            'ErrorInfoChanged': self.on_error_info_changed,
            'AcquisitionInfoChanged': self.on_acquisition_info_changed,
            'Identified': self.on_identified
        }

        for signal_name, callback in signals.items():
            self.register_signal(signal_name, callback)

    def on_state_changed(self, state):
        state_name = self.states.get(state, f"UNKNOWN ({state})")
        print(f"State changed: {state_name}")

    def on_enrollment_progress_changed(self, progress):
        print(f"Enrollment progress: {progress}%")

    def on_enrolled_fingers_changed(self, fingers):
        print(f"Enrolled fingers changed: {', '.join(fingers)}")

    def on_error_info_changed(self, error):
        error_name = self.errors.get(error, f"UNKNOWN ({error})")
        print(f"Error: {error_name}")

    def on_acquisition_info_changed(self, info):
        acquisition_name = self.acquisitions.get(info, f"UNKNOWN ({info})")
        print(f"Acquisition: {acquisition_name}")

    def on_identified(self, finger_name):
        print(f"Identified finger: {finger_name}")

    def enroll(self, finger_name):
        try:
            return self.interface.Enroll(finger_name)
        except dbus.exceptions.DBusException as e:
            print(f"Enrollment error: {e}")
            return False

    def stop_enroll(self):
        try:
            return self.interface.StopEnroll()
        except dbus.exceptions.DBusException as e:
            print(f"Stop enrollment error: {e}")
            return False

    def identify(self):
        try:
            return self.interface.Identify()
        except dbus.exceptions.DBusException as e:
            print(f"Identification error: {e}")
            return False

    def stop_identify(self):
        try:
            return self.interface.StopIdentify()
        except dbus.exceptions.DBusException as e:
            print(f"Stop identification error: {e}")
            return False

    def remove_finger(self, finger_name):
        try:
            return self.interface.RemoveFinger(finger_name)
        except dbus.exceptions.DBusException as e:
            print(f"Remove finger error: {e}")
            return False

    def rename_finger(self, old_name, new_name):
        try:
            return self.interface.RenameFinger(old_name, new_name)
        except dbus.exceptions.DBusException as e:
            print(f"Rename finger error: {e}")
            return False

    def print_properties(self):
        try:
            state = self.get_property('State')
            progress = self.get_property('EnrollmentProgress')
            fingers = self.get_property('EnrolledFingers')
            error = self.get_property('ErrorInfo')
            acquisition = self.get_property('AcquisitionInfo')
            hw_available = self.get_property('HardwareAvailable')

            print("\n=== Fingerprint Properties ===")
            print(f"Hardware Available: {hw_available}")
            print(f"State: {self.states.get(state, f'UNKNOWN ({state})')}")
            print(f"Enrollment Progress: {progress}%")
            print(f"Enrolled Fingers: {', '.join(fingers) if fingers else 'None'}")
            print(f"Error: {self.errors.get(error, f'UNKNOWN ({error})')}")
            print(f"Acquisition: {self.acquisitions.get(acquisition, f'UNKNOWN ({acquisition})')}")
            print("============================\n")
        except Exception as e:
            print(f"Error printing properties: {e}")

    def list_valid_finger_names(self):
        try:
            names = self.get_property('ValidFingerNames')
            print("\n=== Valid Finger Names ===")
            for name in names:
                print(f" - {name}")
            print("========================\n")
            return names
        except Exception as e:
            print(f"Error listing valid finger names: {e}")
            return []

    def list_enrolled_fingers(self):
        try:
            fingers = self.get_property('EnrolledFingers')
            print("\n=== Enrolled Fingers ===")
            if not fingers:
                print("No fingers enrolled")
            else:
                for i, finger in enumerate(fingers):
                    print(f"{i+1}. {finger}")
            print("======================\n")
            return fingers
        except Exception as e:
            print(f"Error listing enrolled fingers: {e}")
            return []

class ManagerAPI(BiometricAPI):
    def __init__(self, bus):
        super().__init__(
            bus,
            'io.FuriOS.Biomd',
            '/org/FuriOS/Biomd',
            'io.FuriOS.Biomd'
        )

    def get_supported_modules(self):
        """Get list of supported biometric modules"""
        try:
            modules = self.interface.GetSupportedModules()
            print("\n=== Supported Biometric Modules ===")
            if not modules:
                print("No biometric modules available")
            else:
                for i, module in enumerate(modules):
                    print(f"{i+1}. {module}")
            print("==================================\n")
            return modules
        except dbus.exceptions.DBusException as e:
            print(f"Error getting supported modules: {e}")
            return []

    def ping(self):
        """Ping the biometric service"""
        try:
            result = self.interface.Ping()
            print(f"Ping result: {'Success' if result else 'Failed'}")
            return result
        except dbus.exceptions.DBusException as e:
            print(f"Ping error: {e}")
            return False

class BiometricClient:
    def __init__(self):
        self.bus = dbus.SystemBus()
        self.mainloop = GLib.MainLoop()

        try:
            self.fingerprint = FingerprintAPI(self.bus)
            print("Fingerprint API connected")
        except Exception as e:
            self.fingerprint = None
            print(f"Fingerprint API not available: {e}")

        try:
            self.manager = ManagerAPI(self.bus)
            print("Manager API connected")
        except Exception as e:
            self.manager = None
            print(f"Manager API not available: {e}")

        self.mainloop_thread = threading.Thread(target=self.mainloop.run)
        self.mainloop_thread.daemon = True
        self.mainloop_thread.start()

    def run_interactive(self):
        try:
            if self.fingerprint:
                self.fingerprint.print_properties()

            while True:
                choice = self.print_menu()
                self.handle_menu_choice(choice)
        except KeyboardInterrupt:
            print("\nExiting...")
        finally:
            self.mainloop.quit()

    def print_menu(self):
        print("\n=== Biometric Actions ===")

        if self.fingerprint:
            print("-- Fingerprint --")
            print("1. Start enrollment")
            print("2. Cancel enrollment")
            print("3. Start identification")
            print("4. Cancel identification")
            print("5. View fingerprint properties")
            print("6. List enrolled fingers")
            print("7. Remove finger")
            print("8. Rename finger")
            print("9. List valid finger names")

        if self.manager:
            print("-- Manager --")
            print("10. List supported modules")
            print("11. Ping service")

        print("0. Exit")
        print("===========================")
        return input("Select option: ")

    def handle_menu_choice(self, choice):
        if choice == '1':
            if self.fingerprint:
                self.handle_enroll()
            else:
                print("Fingerprint API not available")
        elif choice == '2':
            if self.fingerprint:
                success = self.fingerprint.stop_enroll()
                print(f"Enrollment {'canceled' if success else 'cancel failed'}")
            else:
                print("Fingerprint API not available")
        elif choice == '3':
            if self.fingerprint:
                success = self.fingerprint.identify()
                print(f"Identification {'started' if success else 'failed'}")
                print("Place your finger on the sensor...")
            else:
                print("Fingerprint API not available")
        elif choice == '4':
            if self.fingerprint:
                success = self.fingerprint.stop_identify()
                print(f"Identification {'canceled' if success else 'cancel failed'}")
            else:
                print("Fingerprint API not available")
        elif choice == '5':
            if self.fingerprint:
                self.fingerprint.print_properties()
            else:
                print("Fingerprint API not available")
        elif choice == '6':
            if self.fingerprint:
                self.fingerprint.list_enrolled_fingers()
            else:
                print("Fingerprint API not available")
        elif choice == '7':
            if self.fingerprint:
                self.handle_remove_finger()
            else:
                print("Fingerprint API not available")
        elif choice == '8':
            if self.fingerprint:
                self.handle_rename_finger()
            else:
                print("Fingerprint API not available")
        elif choice == '9':
            if self.fingerprint:
                self.fingerprint.list_valid_finger_names()
            else:
                print("Fingerprint API not available")
        elif choice == '10':
            if self.manager:
                self.manager.get_supported_modules()
            else:
                print("Manager API not available")
        elif choice == '11':
            if self.manager:
                self.manager.ping()
            else:
                print("Manager API not available")
        elif choice == '0':
            print("Exiting...")
            sys.exit(0)
        else:
            print("Invalid option")

    def handle_enroll(self):
        valid_names = self.fingerprint.list_valid_finger_names()

        name = input("Enter finger name (or empty to show valid names): ")
        if name.strip() == "":
            if valid_names:
                for i, valid_name in enumerate(valid_names):
                    print(f"{i+1}. {valid_name}")
                selection = input("Select finger name (number): ")
                try:
                    idx = int(selection) - 1
                    if 0 <= idx < len(valid_names):
                        name = valid_names[idx]
                    else:
                        print("Invalid selection")
                        return
                except ValueError:
                    print("Invalid input")
                    return
            else:
                print("No valid finger names available")
                return

        success = self.fingerprint.enroll(name)
        print(f"Enrollment {'started' if success else 'failed'}")
        if success:
            print("Place your finger on the sensor...")

    def handle_remove_finger(self):
        """Handle finger removal interaction"""
        fingers = self.fingerprint.list_enrolled_fingers()
        if not fingers:
            return

        selection = input("Enter number to remove (or name): ")
        try:
            idx = int(selection) - 1
            if 0 <= idx < len(fingers):
                finger_name = fingers[idx]
            else:
                print("Invalid selection")
                return
        except ValueError:
            finger_name = selection

        success = self.fingerprint.remove_finger(finger_name)
        print(f"Finger {'removed' if success else 'removal failed'}")

    def handle_rename_finger(self):
        fingers = self.fingerprint.list_enrolled_fingers()
        if not fingers:
            return

        selection = input("Enter number to rename (or name): ")
        try:
            idx = int(selection) - 1
            if 0 <= idx < len(fingers):
                old_name = fingers[idx]
            else:
                print("Invalid selection")
                return
        except ValueError:
            old_name = selection

        valid_names = self.fingerprint.list_valid_finger_names()

        print("Enter new name (or number from valid names): ")
        new_name = input("> ")

        try:
            idx = int(new_name) - 1
            if 0 <= idx < len(valid_names):
                new_name = valid_names[idx]
            else:
                print("Invalid selection")
                return
        except ValueError:
            pass

        success = self.fingerprint.rename_finger(old_name, new_name)
        print(f"Finger {'renamed' if success else 'rename failed'}")

def main():
    parser = argparse.ArgumentParser(description="FuriOS Biometric Service Client")
    args = parser.parse_args()

    client = BiometricClient()
    client.run_interactive()

if __name__ == "__main__":
    main()
