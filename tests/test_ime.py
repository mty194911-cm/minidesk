"""Phone text must not depend on the PC's IME: with Microsoft Pinyin in Chinese mode, scancodes are composed
by the IME while Unicode injection passes through untouched. Run from minidesk/: python tests/test_ime.py"""
import ctypes
import os
import sys
import tkinter as tk

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import winput  # noqa: E402

u, imm = ctypes.windll.user32, ctypes.windll.imm32
imm.ImmGetDefaultIMEWnd.restype = ctypes.c_void_p
u.SendMessageW.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_size_t, ctypes.c_ssize_t]
WM_IME_CONTROL, IMC_SETCONVERSIONMODE, IMC_SETOPENSTATUS = 0x283, 0x002, 0x006
CHINESE_MODE = 1025  # IME_CMODE_NATIVE | IME_CMODE_SYMBOL


def tap(sc):
    winput.key(sc, True)
    winput.key(sc, False)


def chinese_mode():
    w = imm.ImmGetDefaultIMEWnd(u.GetForegroundWindow())
    u.SendMessageW(w, WM_IME_CONTROL, IMC_SETOPENSTATUS, 1)
    u.SendMessageW(w, WM_IME_CONTROL, IMC_SETCONVERSIONMODE, CHINESE_MODE)


STEPS = [  # (action, expected entry text afterwards)
    (chinese_mode, ""),
    (lambda: (tap(0x31), tap(0x17), tap(0x39)), "你"),  # n i space -> composed by the PC IME
    (lambda: winput.text("abc 你好"), "你abc 你好"),      # Unicode bypasses it
    (lambda: tap(0x0E), "你abc 你"),                      # Backspace passes through
    (lambda: winput.text("Hi!"), "你abc 你Hi!"),
]


def main():
    winput.init()
    r = tk.Tk()
    r.geometry("420x80+200+200")
    r.attributes("-topmost", True)
    e = tk.Entry(r, font=("Microsoft YaHei", 14))
    e.pack(fill="x", padx=10, pady=20)
    results = []

    def run(i=0):
        if i:
            results.append((STEPS[i - 1][1], e.get()))
        if i == len(STEPS):
            return r.destroy()
        STEPS[i][0]()
        r.after(400, run, i + 1)

    def start(tries=0):  # inject only once this window really is in the foreground
        r.lift()
        r.focus_force()
        e.focus_set()
        if u.GetForegroundWindow() != int(r.wm_frame(), 16) and tries < 20:
            return r.after(100, start, tries + 1)
        r.after(400, run)

    r.after(300, start)
    r.mainloop()
    for want, got in results:
        print(f"{'OK ' if want == got else 'FAIL'} expected {want!r:16} got {got!r}")
    assert all(w == g for w, g in results)
    print("ALL OK")


if __name__ == "__main__":
    main()
