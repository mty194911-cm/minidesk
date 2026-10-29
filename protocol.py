"""Message types. Every message is one encrypted WebSocket frame: [u8 type][payload], little-endian.
Mirrored in relay/web/app.js.
"""
# host -> client
VIDEO = 0x01     # u8 keyframe, u32 seq, H.264 Annex-B access unit
SCREEN = 0x02    # u16 width, u16 height (sent before the first keyframe of each encoder)
CURSOR = 0x03    # i16 x, i16 y, u8 visible
LAN = 0x04       # UTF-8 JSON list of wss:// URLs reaching this host directly on its LAN
PONG = 0x41      # echo of PING payload
BYE = 0x7F       # u16 code: 4001 disconnected from the PC, 4002 replaced by another session

# client -> host
MOVE = 0x10      # u16 x, u16 y (screen pixels)
BUTTON = 0x11    # u8 button (0 left, 1 right, 2 middle), u8 down
WHEEL = 0x12     # i16 dx, i16 dy (120 = one notch)
KEY = 0x20       # u16 set-1 scancode (0xE0xx = extended), u8 down
TEXT = 0x21      # UTF-8 text, typed as Unicode
ACK = 0x30       # u32 seq of a received VIDEO message (end-to-end flow control)
KEYFRAME = 0x31  # request an IDR frame
CONFIG = 0x32    # u32 kbps, u8 fps (first message after the handshake starts the stream)
PING = 0x40      # opaque payload, echoed as PONG
NOTE = 0x50      # UTF-8 diagnostics from the client (e.g. why the last connection ended), logged
