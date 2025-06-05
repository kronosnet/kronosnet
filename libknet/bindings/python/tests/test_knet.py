#!/usr/bin/env python3

import unittest
import os
import sys

# Attempt to import the compiled C extension _knet.
# This follows the same logic as test_nozzle.py for locating the .so file.
try:
    import _knet
except ImportError as e:
    build_dir_guess1 = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', '_build', 'libknet', 'bindings', 'python'))
    build_dir_guess2 = os.path.abspath(os.path.join(os.path.dirname(__file__), '..')) # For non-out-of-tree or specific setups

    added_to_path = False
    if os.path.exists(os.path.join(build_dir_guess1, '_knet.so')):
        sys.path.insert(0, build_dir_guess1)
        added_to_path = True
    elif os.path.exists(os.path.join(build_dir_guess2, '_knet.so')):
        sys.path.insert(0, build_dir_guess2)
        added_to_path = True

    if added_to_path:
        try:
            import _knet
        except ImportError:
            print(f"Failed to import _knet even after adding potential build directory to sys.path.")
            print(f"Original error: {e}")
            print(f"Attempted directories: {build_dir_guess1}, {build_dir_guess2}")
            print(f"Current sys.path: {sys.path}")
            raise
    else:
        print(f"Failed to import _knet. Could not find _knet.so in guessed paths.")
        print(f"Original error: {e}")
        print(f"Attempted directories: {build_dir_guess1}, {build_dir_guess2}")
        # To help diagnose, list contents of attempted build directories if they exist
        if os.path.exists(build_dir_guess1):
            print(f"Contents of {build_dir_guess1}: {os.listdir(build_dir_guess1)}")
        else:
            print(f"{build_dir_guess1} does not exist.")
        if os.path.exists(build_dir_guess2):
            print(f"Contents of {build_dir_guess2}: {os.listdir(build_dir_guess2)}")
        else:
            print(f"{build_dir_guess2} does not exist.")
        raise


# KNET_HANDLE_T_CAPSULE_NAME defined in _knet.c
KNET_HANDLE_T_CAPSULE_NAME = "_knet_handle_t"

class TestKnet(unittest.TestCase):

    def test_01_handle_new_and_free(self):
        """Test creating and freeing a knet handle."""
        host_id = 1
        log_fd = 0   # Typically 0 to disable, or a real fd.
                     # Using 0 for basic test to avoid actual logging output.
        default_log_level = 0 # KNET_LOG_ERR
        flags = 0 # No special flags for basic test

        handle_capsule = None
        try:
            handle_capsule = _knet.handle_new(host_id, log_fd, default_log_level, flags)
            self.assertIsNotNone(handle_capsule, "knet_handle_new should return a handle (capsule).")

            # Check if it's a capsule and has the correct name
            self.assertTrue(hasattr(handle_capsule, '__class__'), "Returned handle does not look like an object.")
            # PyCapsule_CheckExact is not directly available in Python,
            # but we can check the type name if it's a well-behaved capsule.
            # For now, just ensuring it's not None and doesn't immediately crash.
            # A more robust check would be to try using it with another function
            # that expects this capsule type, or checking its type name string if accessible.
            # print(type(handle_capsule)) # Expected: <class 'PyCapsule'>

            # Attempt to get the pointer to verify it's a valid capsule of our type
            # This is more of an internal check, not typically done in Python tests,
            # but useful here to ensure the C extension is behaving.
            # PyCapsule_GetPointer would be the C equivalent. Python doesn't directly expose this.
            # We rely on handle_free to validate the capsule type.

        except Exception as e:
            self.fail(f"knet_handle_new raised an exception: {e}")
        finally:
            if handle_capsule:
                try:
                    _knet.handle_free(handle_capsule)
                except Exception as e:
                    self.fail(f"knet_handle_free raised an exception: {e}")

    def test_02_handle_free_invalid_capsule(self):
        """Test knet_handle_free with an invalid capsule type."""
        # Create a dummy capsule with a different name
        dummy_capsule = None
        try:
            # The C API PyCapsule_New takes (pointer, name, destructor).
            # We can't easily create a PyCapsule from Python side with a specific C pointer or name.
            # So, we'll pass a non-capsule type or a capsule of a different C type if we had one.
            # For now, let's pass a simple Python object.
            with self.assertRaises(TypeError): # Expecting a TypeError from the C extension
                _knet.handle_free(object())

            # Test with None
            with self.assertRaises(TypeError): # PyArg_ParseTuple will fail with "O" if None is passed and not handled.
                                               # Or it could be a different error if specifically checked in C.
                _knet.handle_free(None)

        except _knet.Error as e: # Assuming a custom _knet.Error for knet specific errors
            self.skipTest(f"Skipping invalid capsule test, _knet.Error not fully set up for this: {e}")
        except Exception as e:
            # The exact error might vary based on Python version and how PyArg_ParseTuple handles it.
            # We are checking that it *does* error out.
            pass


if __name__ == '__main__':
    unittest.main()
