#pragma once
#undef WINVER
#undef _WIN32_WINNT
#define WINVER 0x0A00
#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mmsystem.h>

static int vx, vy, vw = 2, vh = 2;

static void wi_refresh(void) {
    vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
    vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
    vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
}

static void wi_init(void) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);  // physical pixels everywhere
    timeBeginPeriod(1);                                                         // 1 ms sleep granularity
    wi_refresh();
}

static void wi_send_mouse(DWORD flags, LONG dx, LONG dy, DWORD data) {
    INPUT in = {0};
    in.type = INPUT_MOUSE;
    in.mi.dx = dx;
    in.mi.dy = dy;
    in.mi.mouseData = data;
    in.mi.dwFlags = flags;
    SendInput(1, &in, sizeof(in));
}

/* x, y: desktop pixels */
static void wi_move(int x, int y) {
    wi_send_mouse(MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
                  MulDiv(x - vx, 65535, vw - 1), MulDiv(y - vy, 65535, vh - 1), 0);
}

/* button: 0 left, 1 right, 2 middle */
static void wi_button(int button, int down) {
    static const DWORD flags[3][2] = {
        {MOUSEEVENTF_LEFTUP, MOUSEEVENTF_LEFTDOWN},
        {MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_RIGHTDOWN},
        {MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MIDDLEDOWN},
    };
    if (button >= 0 && button < 3) wi_send_mouse(flags[button][down != 0], 0, 0, 0);
}

/* 120 = one notch; positive dy scrolls up, positive dx scrolls right */
static void wi_wheel(int dx, int dy) {
    if (dy) wi_send_mouse(MOUSEEVENTF_WHEEL, 0, 0, (DWORD)dy);
    if (dx) wi_send_mouse(MOUSEEVENTF_HWHEEL, 0, 0, (DWORD)dx);
}

/* scancode: set-1 code, 0xE0xx for extended keys */
static void wi_key(int scancode, int down) {
    INPUT in = {0};
    in.type = INPUT_KEYBOARD;
    in.ki.wScan = (WORD)(scancode & 0xFF);
    in.ki.dwFlags = KEYEVENTF_SCANCODE | ((scancode & 0xFF00) == 0xE000 ? KEYEVENTF_EXTENDEDKEY : 0) |
                    (down ? 0 : KEYEVENTF_KEYUP);
    SendInput(1, &in, sizeof(in));
}

/* Types UTF-16 text regardless of keyboard layout or IME. */
static void wi_text(const unsigned short *s, int n) {
    INPUT in[64];
    while (n > 0) {
        int k = n < 32 ? n : 32;
        for (int i = 0; i < k; i++) {
            INPUT *d = &in[2 * i];
            ZeroMemory(d, 2 * sizeof(INPUT));
            d[0].type = d[1].type = INPUT_KEYBOARD;
            d[0].ki.wScan = d[1].ki.wScan = s[i];
            d[0].ki.dwFlags = KEYEVENTF_UNICODE;
            d[1].ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
        }
        SendInput(2 * k, in, sizeof(INPUT));
        s += k;
        n -= k;
    }
}
