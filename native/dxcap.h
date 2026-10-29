#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dxcap dxcap;

enum { DXCAP_ERROR = -2, DXCAP_LOST = -1, DXCAP_TIMEOUT = 0, DXCAP_FRAME = 1, DXCAP_POINTER = 2 };

/* Duplicate the primary monitor. Returns NULL and fills err on failure. */
dxcap *dxcap_open(int *width, int *height, char *err, int errlen);

/* Wait up to timeout_ms for a desktop update.
 * DXCAP_FRAME:   data and pitch point at the mapped BGRA image until dxcap_done().
 * DXCAP_POINTER: only the mouse moved.
 * Pointer fields (hot spot, desktop pixels) are updated whenever the mouse moved. */
int dxcap_grab(dxcap *c, int timeout_ms, const uint8_t **data, int *pitch, int *px, int *py, int *pvisible);
void dxcap_done(dxcap *c);
void dxcap_close(dxcap *c);

#ifdef __cplusplus
}
#endif
