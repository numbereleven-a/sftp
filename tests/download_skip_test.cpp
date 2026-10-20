// Compile the production translation unit so the test cannot drift from it.
#include "../src/core/DownloadErrors.cpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>

HINSTANCE hinst = nullptr;
int PluginNumber = 0;
tLogProc LogProc = nullptr;
tLogProcW LogProcW = nullptr;
const char* LngGetString(UINT) noexcept { return nullptr; }

int main() {
    const auto dir = std::filesystem::temp_directory_path() /
        (L"sftp-skip-test-" + std::to_wstring(GetCurrentProcessId()));
    std::filesystem::create_directory(dir);
    int failures = 0;
    auto check = [&](bool ok, const char* name) {
        std::cout << (ok ? "PASS " : "FAIL ") << name << '\n';
        failures += !ok;
    };
    const auto file = dir / "partial.txt";
    std::ofstream(file) << "partial";
    check(HandleBatchDownloadError(L"/synthetic", file.c_str(), false, false) == FS_FILE_READERROR,
          "single-file errors are not reported as success");
    BeginDownloadErrorBatch();
    g_skipAllDownloadErrors = true; // Simulate the dialog's Skip all selection.
    check(HandleBatchDownloadError(L"/synthetic", file.c_str(), true, false) == FS_FILE_READERROR &&
          std::filesystem::exists(file), "move error retains the local file and error status");
    check(HandleBatchDownloadError(L"/synthetic", file.c_str(), false, true) == FS_FILE_READERROR &&
          std::filesystem::exists(file), "resume error retains existing partial data");
    check(HandleBatchDownloadError(L"/synthetic", file.c_str(), false, false) == FS_FILE_OK &&
          !std::filesystem::exists(file), "skip removes the incomplete local file");
    const auto absent = dir / "missing-parent" / "file.txt";
    check(HandleBatchDownloadError(L"/synthetic", absent.c_str(), false, false) == FS_FILE_OK,
          "skip succeeds when the destination parent does not exist");
    std::ofstream(file) << "partial";
    HANDLE locked = CreateFileW(file.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    check(locked != INVALID_HANDLE_VALUE &&
          HandleBatchDownloadError(L"/synthetic", file.c_str(), false, false) == FS_FILE_OK &&
          std::filesystem::exists(file), "locked partial file does not interrupt Skip all");
    CloseHandle(locked);
    std::filesystem::remove(file);
    std::ofstream(file) << "existing";
    check(HandleBatchDownloadError(L"/synthetic", file.c_str(), false, false,
                                  FS_FILE_WRITEERROR, false) == FS_FILE_OK &&
          std::filesystem::file_size(file) == 8,
          "write error is skipped without removing a pre-existing destination");
    check(HandleBatchDownloadError(L"/synthetic", file.c_str(), true, false,
                                  FS_FILE_WRITEERROR) == FS_FILE_WRITEERROR &&
          std::filesystem::exists(file), "move retains write error and local data");
    check(HandleBatchDownloadError(L"/synthetic", file.c_str(), false, true,
                                  FS_FILE_WRITEERROR) == FS_FILE_WRITEERROR &&
          std::filesystem::exists(file), "resume retains write error and local data");
    check(HandleBatchDownloadError(L"/synthetic", file.c_str(), false, false,
                                  FS_FILE_WRITEERROR) == FS_FILE_OK &&
          !std::filesystem::exists(file), "write error removes an owned partial file and continues");
    BeginDownloadErrorBatch();
    EndDownloadErrorBatch();
    check(g_skipAllDownloadErrors, "nested batch does not reset the outer choice");
    bool isolated = false;
    std::thread worker([&] { isolated = !g_skipAllDownloadErrors && g_downloadErrorBatchDepth == 0; });
    worker.join();
    check(isolated, "independent threads do not inherit Skip all");
    EndDownloadErrorBatch();
    BeginDownloadErrorBatch();
    check(!g_skipAllDownloadErrors, "next batch asks again");
    EndDownloadErrorBatch();
    check(HandleBatchDownloadError(L"/synthetic", file.c_str(), false, false,
                                  FS_FILE_WRITEERROR) == FS_FILE_WRITEERROR,
          "single-file write errors retain their original result");
    std::filesystem::remove(dir);
    return failures ? 1 : 0;
}
