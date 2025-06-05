/*
 * Copyright (C) 2025 Red Hat, Inc.  All rights reserved.
 *
 * Author: Jules <jules@google.com> (Google AI Agent)
 *
 * This software licensed under GPL-2.0+
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "libnozzle.h"
#include <net/if.h> // For IFNAMSIZ

// Capsule name for nozzle_t
#define NOZZLE_T_CAPSULE_NAME "_nozzle_t"

// Wrapper for nozzle_open
static PyObject *
py_nozzle_open(PyObject *self, PyObject *args)
{
    const char *devname_in;
    const char *updownpath;
    char devname_out[IFNAMSIZ];
    nozzle_t handle;

    if (!PyArg_ParseTuple(args, "ss", &devname_in, &updownpath)) {
        return NULL;
    }

    // Initialize devname_out, copy devname_in if it's not empty
    memset(devname_out, 0, IFNAMSIZ);
    if (strlen(devname_in) > 0) {
        strncpy(devname_out, devname_in, IFNAMSIZ - 1);
    }

    handle = nozzle_open(devname_out, IFNAMSIZ, updownpath);

    if (handle == NULL) {
        PyErr_SetFromErrno(PyExc_OSError); // Or a custom exception
        return NULL;
    }

    // Return a tuple: (capsule_containing_handle, actual_devname_string)
    PyObject *capsule = PyCapsule_New(handle, NOZZLE_T_CAPSULE_NAME, NULL);
    if (capsule == NULL) {
        // If capsule creation fails, we should close the handle we just opened
        nozzle_close(handle);
        return NULL;
    }
    return Py_BuildValue("Ns", capsule, devname_out);
}

// Wrapper for nozzle_close
static PyObject *
py_nozzle_close(PyObject *self, PyObject *args)
{
    PyObject *capsule;
    nozzle_t handle;

    if (!PyArg_ParseTuple(args, "O", &capsule)) {
        return NULL;
    }

    handle = (nozzle_t)PyCapsule_GetPointer(capsule, NOZZLE_T_CAPSULE_NAME);
    if (handle == NULL) {
        return NULL; // PyCapsule_GetPointer already set an error
    }

    if (nozzle_close(handle) == -1) {
        PyErr_SetFromErrno(PyExc_OSError); // Or a custom exception
        return NULL;
    }

    Py_RETURN_NONE;
}

// Wrapper for nozzle_get_name_by_handle
static PyObject *
py_nozzle_get_name_by_handle(PyObject *self, PyObject *args)
{
    PyObject *capsule;
    nozzle_t handle;
    const char *name;

    if (!PyArg_ParseTuple(args, "O", &capsule)) {
        return NULL;
    }

    handle = (nozzle_t)PyCapsule_GetPointer(capsule, NOZZLE_T_CAPSULE_NAME);
    if (handle == NULL) {
        return NULL;
    }

    name = nozzle_get_name_by_handle(handle);
    if (name == NULL) {
        // nozzle_get_name_by_handle sets errno on error, but might also return NULL if handle is invalid
        // without necessarily setting errno (though docs say it does).
        // For safety, set a generic error if name is NULL.
        PyErr_SetString(PyExc_ValueError, "Failed to get name for nozzle handle or handle invalid");
        return NULL;
    }

    return PyUnicode_FromString(name);
}

// Wrapper for nozzle_get_fd
static PyObject *
py_nozzle_get_fd(PyObject *self, PyObject *args)
{
    PyObject *capsule;
    nozzle_t handle;
    int fd;

    if (!PyArg_ParseTuple(args, "O", &capsule)) {
        return NULL;
    }

    handle = (nozzle_t)PyCapsule_GetPointer(capsule, NOZZLE_T_CAPSULE_NAME);
    if (handle == NULL) {
        return NULL;
    }

    fd = nozzle_get_fd(handle);
    if (fd == -1) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }
    return PyLong_FromLong(fd);
}


// Method definitions
static PyMethodDef NozzleMethods[] = {
    {"open", py_nozzle_open, METH_VARARGS, "Open a nozzle (tap) interface. Args: (devname_requested, updownpath_script_dir). Returns (handle, actual_devname)"},
    {"close", py_nozzle_close, METH_VARARGS, "Close a nozzle interface. Args: (handle)"},
    {"get_name", py_nozzle_get_name_by_handle, METH_VARARGS, "Get interface name from handle. Args: (handle)"},
    {"get_fd", py_nozzle_get_fd, METH_VARARGS, "Get file descriptor from handle. Args: (handle)"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

// Module definition
static struct PyModuleDef nozzlemodule = {
    PyModuleDef_HEAD_INIT,
    "_nozzle",   /* name of module */
    "Python bindings for libnozzle", /* module documentation, may be NULL */
    -1,       /* size of per-interpreter state of the module,
                 or -1 if the module keeps state in global variables. */
    NozzleMethods
};

// Module initialization function
PyMODINIT_FUNC
PyInit__nozzle(void)
{
    PyObject *m;

    m = PyModule_Create(&nozzlemodule);
    if (m == NULL)
        return NULL;

    // Optional: Add custom exceptions or constants here
    // e.g., PyModule_AddStringConstant(m, "NOZZLE_CONSTANT", "value");

    return m;
}
