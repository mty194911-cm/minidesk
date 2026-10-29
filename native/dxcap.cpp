#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <stdio.h>
#include "dxcap.h"

struct dxcap {
    ID3D11Device *dev;
    ID3D11DeviceContext *ctx;
    IDXGIOutputDuplication *dup;
    ID3D11Texture2D *staging;
};

template <class T> static void release(T *&p) {
    if (p) { p->Release(); p = nullptr; }
}

void dxcap_close(dxcap *c) {
    if (!c) return;
    release(c->staging);
    release(c->dup);
    release(c->ctx);
    release(c->dev);
    delete c;
}

static dxcap *fail(dxcap *c, char *err, int errlen, const char *what, HRESULT hr) {
    snprintf(err, errlen, "%s failed (hr=0x%08lx)", what, (unsigned long)hr);
    dxcap_close(c);
    return nullptr;
}

dxcap *dxcap_open(int *width, int *height, char *err, int errlen) {
    dxcap *c = new dxcap();
    IDXGIFactory1 *factory = nullptr;
    HRESULT hr = CreateDXGIFactory1(__uuidof(IDXGIFactory1), (void **)&factory);
    if (FAILED(hr)) return fail(c, err, errlen, "CreateDXGIFactory1", hr);

    // The primary monitor is the attached output whose desktop origin is (0,0).
    // Duplication must run on the adapter that owns it (matters on hybrid-GPU laptops).
    IDXGIAdapter1 *adapter = nullptr;
    IDXGIOutput *output = nullptr;
    for (UINT i = 0; !output && factory->EnumAdapters1(i, &adapter) != DXGI_ERROR_NOT_FOUND; i++) {
        IDXGIOutput *o;
        for (UINT j = 0; adapter->EnumOutputs(j, &o) != DXGI_ERROR_NOT_FOUND; j++) {
            DXGI_OUTPUT_DESC d;
            o->GetDesc(&d);
            if (d.AttachedToDesktop && d.DesktopCoordinates.left == 0 && d.DesktopCoordinates.top == 0) {
                output = o;
                break;
            }
            o->Release();
        }
        if (!output) release(adapter);
    }
    factory->Release();
    if (!output) {
        snprintf(err, errlen, "primary monitor not found");
        dxcap_close(c);
        return nullptr;
    }

    static const D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_1, D3D_FEATURE_LEVEL_10_0};
    hr = D3D11CreateDevice(adapter, D3D_DRIVER_TYPE_UNKNOWN, nullptr, 0, levels, 3, D3D11_SDK_VERSION,
                           &c->dev, nullptr, &c->ctx);
    adapter->Release();
    if (FAILED(hr)) {
        output->Release();
        return fail(c, err, errlen, "D3D11CreateDevice", hr);
    }

    IDXGIOutput1 *output1 = nullptr;
    hr = output->QueryInterface(__uuidof(IDXGIOutput1), (void **)&output1);
    output->Release();
    if (FAILED(hr)) return fail(c, err, errlen, "QueryInterface(IDXGIOutput1)", hr);
    hr = output1->DuplicateOutput(c->dev, &c->dup);
    output1->Release();
    if (FAILED(hr)) return fail(c, err, errlen, "DuplicateOutput", hr);

    DXGI_OUTDUPL_DESC dd;
    c->dup->GetDesc(&dd);
    D3D11_TEXTURE2D_DESC td = {};
    td.Width = dd.ModeDesc.Width;
    td.Height = dd.ModeDesc.Height;
    td.MipLevels = td.ArraySize = 1;
    td.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    td.SampleDesc.Count = 1;
    td.Usage = D3D11_USAGE_STAGING;
    td.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    hr = c->dev->CreateTexture2D(&td, nullptr, &c->staging);
    if (FAILED(hr)) return fail(c, err, errlen, "CreateTexture2D", hr);

    *width = (int)td.Width;
    *height = (int)td.Height;
    return c;
}

int dxcap_grab(dxcap *c, int timeout_ms, const uint8_t **data, int *pitch, int *px, int *py, int *pvisible) {
    DXGI_OUTDUPL_FRAME_INFO fi;
    IDXGIResource *res = nullptr;
    HRESULT hr = c->dup->AcquireNextFrame(timeout_ms, &fi, &res);
    if (hr == DXGI_ERROR_WAIT_TIMEOUT) return DXCAP_TIMEOUT;
    if (hr == DXGI_ERROR_ACCESS_LOST) return DXCAP_LOST;
    if (FAILED(hr)) return DXCAP_ERROR;

    int r = DXCAP_TIMEOUT;
    if (fi.LastMouseUpdateTime.QuadPart) {
        POINT pt;  // DXGI reports the shape's corner; GetCursorPos gives the hot spot
        GetCursorPos(&pt);
        *px = pt.x;
        *py = pt.y;
        *pvisible = fi.PointerPosition.Visible;
        r = DXCAP_POINTER;
    }
    if (fi.LastPresentTime.QuadPart) {  // zero means only the pointer changed
        ID3D11Texture2D *tex;
        if (SUCCEEDED(res->QueryInterface(__uuidof(ID3D11Texture2D), (void **)&tex))) {
            c->ctx->CopyResource(c->staging, tex);
            tex->Release();
            D3D11_MAPPED_SUBRESOURCE m;
            if (SUCCEEDED(c->ctx->Map(c->staging, 0, D3D11_MAP_READ, 0, &m))) {
                *data = (const uint8_t *)m.pData;
                *pitch = (int)m.RowPitch;
                r = DXCAP_FRAME;
            }
        }
    }
    res->Release();
    c->dup->ReleaseFrame();
    return r;
}

void dxcap_done(dxcap *c) {
    c->ctx->Unmap(c->staging, 0);
}
