#pragma once
#include <windows.h>
#include <filesystem>
#include <string>

struct IsolatedAppData {
    std::wstring original;
    std::filesystem::path path;
    IsolatedAppData() {
        std::wstring buffer(32768, L'\0');
        const DWORD n = GetEnvironmentVariableW(L"APPDATA", buffer.data(), static_cast<DWORD>(buffer.size()));
        if (n && n < buffer.size()) original.assign(buffer.data(), n);
        path = std::filesystem::temp_directory_path() /
            (L"sftp-tests-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
        std::filesystem::create_directories(path);
        if (!SetEnvironmentVariableW(L"APPDATA", path.c_str())) throw std::runtime_error("APPDATA isolation failed");
    }
    ~IsolatedAppData() {
        SetEnvironmentVariableW(L"APPDATA", original.empty() ? nullptr : original.c_str());
        std::error_code error;
        std::filesystem::remove_all(path, error);
    }
};
