#include <windows.h>
#include "fsplugin.h"
#include <iostream>

static int WINAPI Progress(int, LPCWSTR, LPCWSTR, int) { return 0; }
static void WINAPI Log(int, int, LPCWSTR) {}
static BOOL WINAPI Request(int, int, LPCWSTR, LPCWSTR, LPWSTR, int) { return FALSE; }

int wmain(int argc, wchar_t** argv) {
    if (argc != 2) return 2;
    HMODULE module = LoadLibraryW(argv[1]);
    if (!module) { std::cout << "LoadLibrary failed: " << GetLastError() << '\n'; return 1; }
    const auto init = reinterpret_cast<decltype(&FsInitW)>(GetProcAddress(module, "FsInitW"));
    const auto get = reinterpret_cast<decltype(&FsGetFileW)>(GetProcAddress(module, "FsGetFileW"));
    const auto status = reinterpret_cast<decltype(&FsStatusInfo)>(GetProcAddress(module, "FsStatusInfo"));
    bool ok = init && get && status && init(42, Progress, Log, Request) == 0;
    if (ok) {
        for (int i = 0; i < 100; ++i) {
            status("\\synthetic", FS_STATUS_START, FS_STATUS_OP_GET_MULTI);
            status("\\synthetic", FS_STATUS_END, FS_STATUS_OP_GET_MULTI);
        }
        ok = get(nullptr, nullptr, 0, nullptr) == FS_FILE_NOTFOUND;
    }
    wchar_t text[64]{};
    ok = ok && FindResourceW(module, MAKEINTRESOURCEW(118), MAKEINTRESOURCEW(5)) &&
         LoadStringW(module, 12107, text, 64) > 0;
    FreeLibrary(module);
    std::cout << (ok ? "PASS" : "FAIL") << " plugin load, initialization, batch callbacks, exports, resources, unload\n";
    return ok ? 0 : 1;
}
