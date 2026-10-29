# cython: language_level=3
"""Mouse/keyboard injection via SendInput. Coordinates are physical desktop pixels."""

cdef extern from "winput.h" nogil:
    void wi_init()
    void wi_refresh()
    void wi_move(int x, int y)
    void wi_button(int button, int down)
    void wi_wheel(int dx, int dy)
    void wi_key(int scancode, int down)
    void wi_text(const unsigned short *s, int n)


def init():
    """Per-monitor DPI awareness + 1 ms timer resolution. Call once at startup."""
    wi_init()


def refresh():
    """Re-read the virtual desktop bounds (after a resolution change)."""
    wi_refresh()


def move(int x, int y):
    wi_move(x, y)


def button(int b, bint down):
    wi_button(b, down)


def wheel(int dx, int dy):
    wi_wheel(dx, dy)


def key(int scancode, bint down):
    wi_key(scancode, down)


def text(str s):
    cdef bytes u = s.encode("utf-16-le")
    wi_text(<const unsigned short *><const char *>u, len(u) // 2)
