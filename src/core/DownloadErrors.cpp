#include "PluginEntryPoints.h"
#include "res/resource.h"

namespace {

thread_local unsigned g_downloadErrorBatchDepth = 0;
thread_local bool g_skipAllDownloadErrors = false;

enum class DownloadErrorChoice {
    Skip,
    SkipAll,
    Cancel
};

std::wstring LoadDownloadDialogText(UINT id, const wchar_t* fallback)
{
    if (const char* translated = LngGetString(id)) {
        const int needed = MultiByteToWideChar(CP_UTF8, 0, translated, -1, nullptr, 0);
        if (needed > 1) {
            std::wstring result(static_cast<size_t>(needed), L'\0');
            MultiByteToWideChar(CP_UTF8, 0, translated, -1, result.data(), needed);
            result.pop_back();
            return result;
        }
    }

    std::array<wchar_t, 512> buffer{};
    const int length = LoadStringW(hinst, id, buffer.data(), static_cast<int>(buffer.size()));
    return length > 0 ? std::wstring(buffer.data(), static_cast<size_t>(length))
                      : std::wstring(fallback ? fallback : L"");
}

INT_PTR CALLBACK DownloadErrorDialogProc(HWND dialog, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message) {
        case WM_INITDIALOG: {
            const auto* remoteName = reinterpret_cast<const wchar_t*>(lParam);
            SetWindowTextW(dialog, LoadDownloadDialogText(IDS_DOWNLOAD_ERROR_TITLE, L"Download error").c_str());
            SetDlgItemTextW(dialog, IDC_DOWNLOAD_ERROR_TEXT,
                            LoadDownloadDialogText(IDS_DOWNLOAD_ERROR_TEXT,
                                                   L"The file could not be downloaded:").c_str());
            SetDlgItemTextW(dialog, IDC_DOWNLOAD_ERROR_PATH, remoteName ? remoteName : L"");
            SetDlgItemTextW(dialog, IDC_DOWNLOAD_SKIP,
                            LoadDownloadDialogText(IDS_DOWNLOAD_SKIP, L"Skip").c_str());
            SetDlgItemTextW(dialog, IDC_DOWNLOAD_SKIP_ALL,
                            LoadDownloadDialogText(IDS_DOWNLOAD_SKIP_ALL, L"Skip all").c_str());
            SetDlgItemTextW(dialog, IDCANCEL,
                            LoadDownloadDialogText(IDS_CANCEL, L"Cancel").c_str());
            return TRUE;
        }
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDC_DOWNLOAD_SKIP:
                case IDC_DOWNLOAD_SKIP_ALL:
                case IDCANCEL:
                    EndDialog(dialog, LOWORD(wParam));
                    return TRUE;
            }
            break;
        case WM_CLOSE:
            EndDialog(dialog, IDCANCEL);
            return TRUE;
    }
    return FALSE;
}

DownloadErrorChoice AskDownloadErrorChoice(LPCWSTR remoteName)
{
    HWND parent = GetActiveWindow();
    if (parent)
        parent = GetAncestor(parent, GA_ROOTOWNER);
    if (!parent)
        parent = FindWindowA("TTOTAL_CMD", nullptr);

    const INT_PTR result = DialogBoxParamW(hinst, MAKEINTRESOURCEW(IDD_DOWNLOAD_ERROR), parent,
                                           DownloadErrorDialogProc,
                                           reinterpret_cast<LPARAM>(remoteName));
    if (result == IDC_DOWNLOAD_SKIP_ALL)
        return DownloadErrorChoice::SkipAll;
    if (result == IDC_DOWNLOAD_SKIP)
        return DownloadErrorChoice::Skip;
    return DownloadErrorChoice::Cancel;
}

bool RemoveSkippedLocalFile(LPCWSTR localName) noexcept
{
    if (!localName || !localName[0])
        return true;
    if (DeleteFileW(localName))
        return true;
    const DWORD error = GetLastError();
    return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}

} // namespace

int HandleBatchDownloadError(LPCWSTR remoteName, LPCWSTR localName,
                            bool move, bool requestedResume, int error, bool removePartial)
{
    // WFX has no "skip" result. A copy can continue with a logged omission,
    // but reporting success for a move could make TC remove the source.
    // Keep normal error handling for moves and existing resumed data.
    if (move || requestedResume || g_downloadErrorBatchDepth == 0)
        return error;

    DownloadErrorChoice choice = DownloadErrorChoice::Skip;
    if (!g_skipAllDownloadErrors) {
        choice = AskDownloadErrorChoice(remoteName);
        if (choice == DownloadErrorChoice::Cancel)
            return FS_FILE_USERABORT;
        if (choice == DownloadErrorChoice::SkipAll)
            g_skipAllDownloadErrors = true;
    }

    // A locked or read-only partial file must not break Skip all. Leave it in
    // place and report that cleanup failed rather than claiming it was removed.
    const bool cleanupFailed = removePartial && !RemoveSkippedLocalFile(localName);

    std::wstring message = LoadDownloadDialogText(IDS_LOG_DOWNLOAD_SKIPPED,
                                                   L"Skipped after a download error:");
    message += L" ";
    if (remoteName)
        message += remoteName;
    if (cleanupFailed)
        message += L" (could not remove the incomplete local file)";
    if (LogProcW)
        LogProcW(PluginNumber, MSGTYPE_IMPORTANTERROR, message.c_str());
    else if (LogProc) {
        std::array<char, wdirtypemax * 3> messageA{};
        WideCharToMultiByte(CP_ACP, 0, message.c_str(), -1, messageA.data(),
                            static_cast<int>(messageA.size()), nullptr, nullptr);
        LogProc(PluginNumber, MSGTYPE_IMPORTANTERROR, messageA.data());
    }
    return FS_FILE_OK;
}

void BeginDownloadErrorBatch() noexcept
{
    if (g_downloadErrorBatchDepth++ == 0)
        g_skipAllDownloadErrors = false;
}

void EndDownloadErrorBatch() noexcept
{
    if (g_downloadErrorBatchDepth == 0)
        return;
    if (--g_downloadErrorBatchDepth == 0)
        g_skipAllDownloadErrors = false;
}
