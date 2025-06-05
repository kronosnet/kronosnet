/*
 * Copyright (C) 2025 Red Hat, Inc.  All rights reserved.
 *
 * Author: Jules <jules@google.com> (Google AI Agent)
 *
 * This software licensed under GPL-2.0+
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "libknet.h"

// Capsule name for knet_handle_t
#define KNET_HANDLE_T_CAPSULE_NAME "_knet_handle_t"

// Wrapper for knet_handle_new
static PyObject *
py_knet_handle_new(PyObject *self, PyObject *args)
{
    unsigned short host_id; // knet_node_id_t is uint16_t
    int log_fd;
    unsigned char default_log_level; // uint8_t
    unsigned long long flags; // uint64_t
    knet_handle_t handle;

    if (!PyArg_ParseTuple(args, "HibK", &host_id, &log_fd, &default_log_level, &flags)) {
        return NULL;
    }

    handle = knet_handle_new((knet_node_id_t)host_id, log_fd, (uint8_t)default_log_level, (uint64_t)flags);

    if (handle == NULL) {
        PyErr_SetFromErrno(PyExc_OSError); // Or a custom KnetException
        return NULL;
    }

    PyObject *capsule = PyCapsule_New(handle, KNET_HANDLE_T_CAPSULE_NAME, NULL); // No custom destructor for now
    if (capsule == NULL) {
        knet_handle_free(handle); // Clean up if capsule creation fails
        return NULL;
    }
    return capsule;
}

// Wrapper for knet_handle_free
static PyObject *
py_knet_handle_free(PyObject *self, PyObject *args)
{
    PyObject *capsule;
    knet_handle_t handle;

    if (!PyArg_ParseTuple(args, "O", &capsule)) {
        return NULL;
    }

    if (!PyCapsule_CheckExact(capsule)) {
        PyErr_SetString(PyExc_TypeError, "Argument must be a knet handle capsule.");
        return NULL;
    }

    handle = (knet_handle_t)PyCapsule_GetPointer(capsule, KNET_HANDLE_T_CAPSULE_NAME);
    if (handle == NULL) {
        // PyCapsule_GetPointer already set an error (e.g., wrong capsule name)
        return NULL;
    }

    if (knet_handle_free(handle) == -1) {
        PyErr_SetFromErrno(PyExc_OSError); // Or a custom KnetException
        return NULL;
    }

    // It's good practice to invalidate the capsule after freeing the underlying resource,
    // though Python doesn't enforce it. One way is to set its pointer to NULL.
    // PyCapsule_SetPointer(capsule, NULL); // Requires a non-NULL name if destructor is NULL.
    // Or, more simply, just rely on the user not to use a freed handle.
    // If a destructor was provided to PyCapsule_New, it would be called when the capsule is GC'd.
    // Since we don't have one, make sure the user calls free explicitly.

    Py_RETURN_NONE;
}

// Method definitions
static PyMethodDef KnetMethods[] = {
    {"handle_new", py_knet_handle_new, METH_VARARGS, "Create a new knet handle. Args: (host_id, log_fd, default_log_level, flags)"},
    {"handle_free", py_knet_handle_free, METH_VARARGS, "Free a knet handle. Args: (handle_capsule)"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

// Module definition
static struct PyModuleDef knetmodule = {
    PyModuleDef_HEAD_INIT,
    "_knet",   /* name of module */
    "Python bindings for libknet", /* module documentation, may be NULL */
    -1,       /* size of per-interpreter state of the module,
                 or -1 if the module keeps state in global variables. */
    KnetMethods
};

// Module initialization function
PyMODINIT_FUNC
PyInit__knet(void)
{
    PyObject *m;

    m = PyModule_Create(&knetmodule);
    if (m == NULL)
        return NULL;

    // Optional: Add custom exceptions like KnetError = PyErr_NewException("_knet.Error", NULL, NULL);
    // Py_XINCREF(KnetError);
    // if (PyModule_AddObject(m, "Error", KnetError) < 0) { ... }

    return m;
}
