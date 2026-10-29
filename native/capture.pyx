# cython: language_level=3, boundscheck=False, wraparound=False
from libc.stdint cimport uint8_t
from libc.string cimport memcpy

cdef extern from "dxcap.h" nogil:
    enum: DXCAP_ERROR, DXCAP_LOST, DXCAP_TIMEOUT, DXCAP_FRAME, DXCAP_POINTER
    ctypedef struct dxcap
    dxcap *dxcap_open(int *width, int *height, char *err, int errlen)
    int dxcap_grab(dxcap *c, int timeout_ms, const uint8_t **data, int *pitch, int *px, int *py, int *pvisible)
    void dxcap_done(dxcap *c)
    void dxcap_close(dxcap *c)

ERROR, LOST, TIMEOUT, FRAME, POINTER = DXCAP_ERROR, DXCAP_LOST, DXCAP_TIMEOUT, DXCAP_FRAME, DXCAP_POINTER


cdef class Capturer:
    """DXGI desktop duplication of the primary monitor (BGRA)."""
    cdef dxcap *c
    cdef readonly int width, height
    cdef readonly int pointer_x, pointer_y, pointer_visible

    def __cinit__(self):
        cdef char err[256]
        self.c = dxcap_open(&self.width, &self.height, err, sizeof(err))
        if self.c == NULL:
            raise OSError(err.decode())

    def __dealloc__(self):
        if self.c != NULL:
            dxcap_close(self.c)

    def grab(self, int timeout_ms, uint8_t[::1] out, int out_pitch):
        """Wait for an update; on FRAME copy the image into `out` (rows of out_pitch bytes).

        Returns TIMEOUT, FRAME, POINTER or LOST (caller must reopen). Runs without the GIL.
        """
        cdef const uint8_t *src
        cdef uint8_t *dst = &out[0]
        cdef int pitch, y, r, row = self.width * 4
        if out_pitch < row or <Py_ssize_t>out.shape[0] < <Py_ssize_t>out_pitch * self.height:
            raise ValueError("output buffer too small")
        with nogil:
            r = dxcap_grab(self.c, timeout_ms, &src, &pitch, &self.pointer_x, &self.pointer_y, &self.pointer_visible)
            if r == DXCAP_FRAME:
                if pitch == out_pitch:
                    memcpy(dst, src, <size_t>pitch * self.height)
                else:
                    for y in range(self.height):
                        memcpy(dst + <size_t>y * out_pitch, src + <size_t>y * pitch, row)
                dxcap_done(self.c)
        if r == DXCAP_ERROR:
            raise OSError("AcquireNextFrame failed")
        return r
