#!/usr/bin/env python3
#
# Copyright (C) 2025 Red Hat, Inc.  All rights reserved.
#
# Author: Jules <jules@google.com> (Google AI Agent)
#
# This software licensed under GPL-2.0+
#

import unittest
import os
import sys

# Attempt to import the compiled C extension.
# This assumes that when the test is run, either:
# 1. The _nozzle.so is in the same directory (e.g., copied by Makefile)
# 2. PYTHONPATH is set to find it in the build directory (e.g., ../../build/libnozzle/bindings/python or similar)
# 3. The module is installed.
try:
    import _nozzle
except ImportError as e:
    # A common location for the built .so file if running tests from `libnozzle/bindings/python/tests`
    # and the build dir is parallel to srcdir, e.g. `_build/libnozzle/bindings/python/`
    # This is a guess; a more robust solution involves build system support (e.g. via PYTHONPATH)
    build_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', '_build', 'libnozzle', 'bindings', 'python'))
    if os.path.exists(os.path.join(build_dir, '_nozzle.so')): # Check typical automake build dir
        sys.path.insert(0, build_dir)
    else: # Try another common pattern for non-out-of-tree builds or specific setups
        build_dir_alt = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        if os.path.exists(os.path.join(build_dir_alt, '_nozzle.so')):
             sys.path.insert(0, build_dir_alt)

    try:
        import _nozzle
    except ImportError:
        print(f"Failed to import _nozzle. Original error: {e}")
        print(f"Attempted to add build directories to sys.path: {build_dir}, {build_dir_alt}")
        print(f"Current sys.path: {sys.path}")
        # To help diagnose, list contents of attempted build directories
        if os.path.exists(build_dir):
            print(f"Contents of {build_dir}: {os.listdir(build_dir)}")
        if os.path.exists(build_dir_alt):
            print(f"Contents of {build_dir_alt}: {os.listdir(build_dir_alt)}")
        raise

# Define a unique prefix for test interface names to avoid clashes
# and make it easy to clean up if tests fail midway.
TEST_IFACE_PREFIX = "nozpytst"
UPDOWN_PATH_SCRIPTS = "/tmp/knet_nozzle_test_scripts" # Dummy path, ensure it exists or is not needed by basic open/close

class TestNozzle(unittest.TestCase):

    def setUp(self):
        # For nozzle_open, updownpath is required. Create a dummy structure if it doesn't exist.
        # This is a simplification. Real tests might need more elaborate setup for updown scripts.
        os.makedirs(os.path.join(UPDOWN_PATH_SCRIPTS, "up.d"), exist_ok=True)
        os.makedirs(os.path.join(UPDOWN_PATH_SCRIPTS, "down.d"), exist_ok=True)
        # In a real CI environment, we might need to clean up interfaces
        # that were not closed due to previous test failures.
        # For now, we assume a clean state or manual cleanup.
        pass

    def tearDown(self):
        # pass # Individual tests will close their handles.
        # Clean up any interfaces that might have been left open by tests.
        # This is a bit complex as it requires listing system interfaces.
        # For now, we'll rely on tests to clean up after themselves.
        # Example of how one might attempt to clean up:
        # for i in range(5): # Try a few interface numbers
        #     try:
        #         # This is pseudo-code; actual cleanup needs to interact with the system
        #         # or use nozzle_get_handle_by_name if available and then close.
        #         iface_name_to_check = f"{TEST_IFACE_PREFIX}{i}"
        #         # handle = _nozzle.get_handle_by_name(iface_name_to_check) # If we had this
        #         # if handle: _nozzle.close(handle)
        #     except Exception:
        #         pass
        pass


    def test_01_open_and_close_interface(self):
        """Test opening and closing a nozzle interface with a specific name."""
        dev_name_req = TEST_IFACE_PREFIX + "0"
        try:
            handle, actual_dev_name = _nozzle.open(dev_name_req, UPDOWN_PATH_SCRIPTS)
            self.assertIsNotNone(handle, "Nozzle handle should not be None")
            self.assertTrue(actual_dev_name.startswith(TEST_IFACE_PREFIX), f"Actual device name {actual_dev_name} does not start with {TEST_IFACE_PREFIX}")
            self.assertEqual(actual_dev_name, dev_name_req, "Actual device name should match requested if specific name is given")

            # Test get_name
            name_from_handle = _nozzle.get_name(handle)
            self.assertEqual(name_from_handle, actual_dev_name, "Name from handle should match actual device name")

            # Test get_fd
            fd = _nozzle.get_fd(handle)
            self.assertIsInstance(fd, int, "File descriptor should be an integer")
            self.assertGreaterEqual(fd, 0, "File descriptor should be non-negative")

        finally:
            if 'handle' in locals() and handle:
                _nozzle.close(handle)

        # After closing, operations on the handle should ideally fail.
        # PyCapsule does not automatically invalidate, so the C code would need to handle this,
        # or we accept that behavior is undefined after close for a stale handle.
        # For example, trying to get_name on a closed handle:
        # with self.assertRaises(Exception): # Expect some error
        #    _nozzle.get_name(handle)


    def test_02_open_interface_system_assigned_name(self):
        """Test opening a nozzle interface allowing system to assign name."""
        try:
            handle, actual_dev_name = _nozzle.open("", UPDOWN_PATH_SCRIPTS) # Empty string for system-assigned
            self.assertIsNotNone(handle, "Nozzle handle should not be None for system-assigned name")
            # System-assigned names usually start with 'tap' on Linux, or could be 'noz' if kernel/udev rules are set.
            # For this library, it's often 'tapX' or similar if not forced.
            # Given it's nozzle, it might try to create 'nozzleX' or 'nozX'
            self.assertTrue(len(actual_dev_name) > 0, "Actual device name should not be empty for system-assigned")
            # We cannot predict the exact name, but we can check its properties via other calls.

            name_from_handle = _nozzle.get_name(handle)
            self.assertEqual(name_from_handle, actual_dev_name, "Name from handle should match actual device name (system-assigned)")

            fd = _nozzle.get_fd(handle)
            self.assertIsInstance(fd, int, "File descriptor should be an integer (system-assigned)")
            self.assertGreaterEqual(fd, 0, "File descriptor should be non-negative (system-assigned)")

        finally:
            if 'handle' in locals() and handle:
                _nozzle.close(handle)

    def test_03_open_non_existent_updownpath(self):
        """Test opening with a non-existent updownpath. Should still open device."""
        # nozzle_open itself doesn't fail if updownpath is invalid,
        # errors occur when nozzle_run_updown is called.
        dev_name_req = TEST_IFACE_PREFIX + "1"
        non_existent_path = "/tmp/nonexistent_path_for_nozzle_test"
        try:
            handle, actual_dev_name = _nozzle.open(dev_name_req, non_existent_path)
            self.assertIsNotNone(handle, "Nozzle handle should not be None even with non-existent updownpath")
            self.assertEqual(actual_dev_name, dev_name_req)
        finally:
            if 'handle' in locals() and handle:
                _nozzle.close(handle)

    # Potential future tests:
    # - Error conditions for open (e.g., invalid devname format if enforced, permission issues)
    # - Error conditions for close (e.g., invalid handle)
    # - Thread safety if applicable
    # - Multiple open/close operations

if __name__ == '__main__':
    # This allows running the test script directly.
    # For 'make check', the Makefile will typically invoke it.
    unittest.main()
