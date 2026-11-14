#include "global.h"
#include "SftpInternal.h"
#include "Libssh2Backend.h"
#include "PluginEntryPointsInternal.h"
#include "ScpTransfer.h"
#include "PhpAgentClient.h"
#include "IsolatedAppData.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
// Includes the production import boundary so portable sources can be tested
// without consulting the user's installed SSH clients or registry sessions.
#include "../src/core/SessionImport.cpp"

namespace {
int failures = 0;
std::string response = "synthetic-pass";
void check(bool ok, const char* label) {
    std::cout << (ok ? "PASS " : "FAIL ") << label << std::endl;
    if (!ok) ++failures;
}
int WINAPI progress(int, LPCSTR, LPCSTR, int) { return 0; }
void WINAPI logMessage(int, int, LPCSTR) {}
BOOL WINAPI request(int, int type, LPCSTR, LPCSTR, LPSTR result, int length) {
    if (type == RT_Password && result) { strlcpy(result, response.c_str(), length); return TRUE; }
    return FALSE;
}
std::string readFile(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(file), {}};
}
void writeFile(const std::filesystem::path& path, const std::string& bytes) {
    std::ofstream file(path, std::ios::binary); file.write(bytes.data(), bytes.size());
}
tConnectSettings* connectTo(int port, const char* name, bool shell) {
    auto cs = std::make_unique<tConnectSettings>();
    cs->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(static_cast<u_short>(port));
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(cs->sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr))) throw std::runtime_error("connect failed");
    Libssh2Backend backend;
    cs->session = backend.createSession(nullptr, nullptr, nullptr, cs.get());
    cs->session->setBlocking(1);
    if (cs->session->startup(static_cast<int>(cs->sock))) throw std::runtime_error("handshake failed");
    if (cs->session->userauthPassword("synthetic", 9, "synthetic-pass", 14, nullptr)) throw std::runtime_error("auth failed");
    cs->session->setBlocking(0);
    SetBlockingSocket(cs->sock, false);
    cs->scponly = shell; cs->scpfordata = shell;
    cs->utf8names = 1; cs->unixlinebreaks = 0; cs->filemod = 0644; cs->dirmod = 0755;
    cs->server = "127.0.0.1"; cs->customport = static_cast<unsigned short>(port);
    cs->user = "synthetic"; cs->DisplayName = name;
    if (!shell) {
        const auto start = GetTickCount64();
        while (!(cs->sftpsession = cs->session->sftpInit())) {
            if (cs->session->lastErrno() != LIBSSH2_ERROR_EAGAIN || GetTickCount64() - start > 10000)
                throw std::runtime_error("SFTP init failed");
            WaitForSshIo(cs.get());
        }
    }
    if (!SetServerIdForName(name, cs.get())) throw std::runtime_error("registration failed");
    return cs.release();
}
void authPrompts() {
    tConnectSettings cs{};
    void* context = &cs;
    LIBSSH2_USERAUTH_KBDINT_RESPONSE result{};
    LIBSSH2_USERAUTH_KBDINT_PROMPT prompt{};
    std::string text = "Verification code:";
    prompt.text = reinterpret_cast<unsigned char*>(text.data()); prompt.length = static_cast<unsigned>(text.size());
    response = "synthetic-code";
    kbd_callback(nullptr, 0, nullptr, 0, 1, &prompt, &result, &context);
    check(cs.password.empty() && result.text && response == result.text, "OTP answer is sent but not retained as a password");
    free(result.text);
    for (const char* label : {"Passcode:", "OTP password:", "One-time password:"}) {
        text = label; prompt.text = reinterpret_cast<unsigned char*>(text.data()); prompt.length = static_cast<unsigned>(text.size());
        kbd_callback(nullptr, 0, nullptr, 0, 1, &prompt, &result, &context);
        check(cs.password.empty(), label);
        free(result.text);
    }
    text = "Password:"; prompt.text = reinterpret_cast<unsigned char*>(text.data()); prompt.length = static_cast<unsigned>(text.size());
    response = "synthetic-pass";
    kbd_callback(nullptr, 0, nullptr, 0, 1, &prompt, &result, &context);
    check(cs.password == response, "password answer remains available for reconnect");
    free(result.text);
}
void imports(const std::filesystem::path& root) {
    const auto input = (root / "portable.ini").string();
    const auto output = (root / "imported.ini").string();
    PortableSessionDescriptor descriptor{SessionSource::putty, input, "synthetic", "synthetic"};
    for (int mode = 0; mode != 3; ++mode) {
        writeFile(input, "[synthetic]\r\nHostName=example.invalid\r\nProxyMethod=" + std::to_string(mode == 1 ? 3 : 0) +
            "\r\nTunnel=" + std::to_string(mode == 2 ? 1 : 0) + "\r\n");
        WritePrivateProfileStringA(nullptr, nullptr, nullptr, input.c_str());
        bool unsupported = false;
        const bool ok = ImportPortableSessionToIni(descriptor, output.c_str(), unsupported, nullptr);
        check(mode == 0 ? ok && !unsupported : !ok && unsupported,
              mode == 0 ? "direct portable session imports" : mode == 1 ? "proxy import refuses a direct connection" : "tunnel import refuses a direct connection");
    }
}
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 3 && argc != 4) return 2;
    IsolatedAppData isolated;
    const std::filesystem::path root(argv[2]);
    FsInit(42, progress, logMessage, request);
    libssh2_init(0);
    authPrompts(); imports(root);
    auto* cs = connectTo(_wtoi(argv[1]), "synthetic", false);
    auto* other = connectTo(_wtoi(argv[1]), "other", false);
    const auto local = root / "local.bin", download = root / "download.bin";
    const std::string bytes = "alpha\r\nbeta\n";
    writeFile(local, bytes);
    check(SftpUploadFileW(cs, local.c_str(), L"/source.bin", false, false) == SFTP_OK, "SFTP upload completes");
    check(SftpDownloadFileW(cs, L"/source.bin", download.c_str(), true, bytes.size(), nullptr, false) == SFTP_OK && readFile(download) == bytes,
          "SFTP download preserves complete bytes");
    check(SftpChmodW(cs, L"\\source.bin", L"0750"), "Alt+A sets permissions through SFTP without a shell");
    LIBSSH2_SFTP_ATTRIBUTES attrs{};
    WaitForOperation([&] { return cs->sftpsession->stat("/source.bin", &attrs); }, 10000, cs);
    check((attrs.permissions & 07777) == 0750, "server received requested permissions");
    RemoteInfoStruct info{}; info.Size64 = bytes.size();
    check(FsRenMovFileW(L"\\synthetic\\source.bin", L"\\synthetic\\copy.bin", false, false, &info) == FS_FILE_OK &&
          SftpFileExistsW(cs, L"/source.bin") == 1, "same-session F5 copies and preserves the source");
    check(FsRenMovFileW(L"\\synthetic\\source.bin", L"\\other\\remote-copy.bin", false, false, &info) == FS_FILE_OK,
          "cross-session F5 relays a file");
    check(FsRenMovFileW(L"\\synthetic\\source.bin", L"\\other\\remote-copy.bin", true, false, &info) == FS_FILE_EXISTS &&
          SftpFileExistsW(cs, L"/source.bin") == 1, "cross-session move asks before overwrite and preserves the source");
    check(FsRenMovFileW(L"\\synthetic\\source.bin", L"\\other\\denied.bin", false, false, &info) == FS_FILE_WRITEERROR,
          "permission error is not treated as a missing destination");
    check(FsRenMovFileW(L"\\synthetic\\source.bin", L"\\other\\source.bin", true, true, &info) == FS_FILE_WRITEERROR,
          "two sessions cannot move a file onto itself");
    check(FsPutFileW(local.c_str(), L"\\synthetic\\move.bin", FS_COPYFLAGS_MOVE) == FS_FILE_OK && !std::filesystem::exists(local),
          "F6 upload removes the local source after completion");
    check(FsGetFileW(L"\\synthetic\\move.bin", const_cast<wchar_t*>(local.c_str()), FS_COPYFLAGS_MOVE, &info) == FS_FILE_OK &&
          readFile(local) == bytes && SftpFileExistsW(cs, L"/move.bin") == 0, "F6 download removes the remote source after completion");
    writeFile(download, bytes.substr(0, 3));
    check(FsGetFileW(L"\\synthetic\\source.bin", const_cast<wchar_t*>(download.c_str()), FS_COPYFLAGS_MOVE | FS_COPYFLAGS_RESUME, &info) == FS_FILE_OK &&
          readFile(download) == bytes && SftpFileExistsW(cs, L"/source.bin") == 1, "resumed move preserves the source");
    writeFile(local, "a");
    check(SftpUploadFileW(cs, local.c_str(), L"/source.bin", true, false) == SFTP_WRITEFAILED,
          "resume refuses a larger destination");
    cs->unixlinebreaks = 1;
    Global_TransferMode = 'A';
    check(SftpUploadFileW(cs, local.c_str(), L"/source.bin", true, false) == SFTP_WRITEFAILED,
          "text-mode resume refuses to truncate the destination");
    cs->unixlinebreaks = 0;
    Global_TransferMode = 'I';
    check(SftpDownloadFileW(cs, L"/short.bin", download.c_str(), true, 100, nullptr, false) != SFTP_OK,
          "truncated download is not successful");
    info.Size64 = 100;
    check(FsGetFileW(L"\\synthetic\\short.bin", const_cast<wchar_t*>(download.c_str()), FS_COPYFLAGS_OVERWRITE, &info) == FS_FILE_READERROR,
          "automatic resume stops when a retry adds no data");
    writeFile(local, bytes);
    HANDLE lock = CreateFileW(local.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    OVERLAPPED region{};
    const bool locked = LockFileEx(lock, LOCKFILE_EXCLUSIVE_LOCK, 0, 100, 0, &region) != 0;
    check(locked && FsPutFileW(local.c_str(), L"\\synthetic\\locked.bin", FS_COPYFLAGS_MOVE) == FS_FILE_READERROR && std::filesystem::exists(local),
          "local read failure preserves the F6 source");
    UnlockFileEx(lock, 0, 100, 0, &region); CloseHandle(lock);
    cs->scpfordata = true;
    check(SftpUploadFileW(cs, local.c_str(), L"/scp.bin", false, false) == SFTP_OK, "native SCP upload retries channel startup and receives completion");
    check(SftpDownloadFileW(cs, L"/scp.bin", download.c_str(), true, bytes.size(), nullptr, false) == SFTP_OK && readFile(download) == bytes,
          "native SCP download completes its handshake");
    check(SftpUploadFileW(cs, local.c_str(), L"/scp-fail.bin", false, false) == SFTP_WRITEFAILED, "SCP receiver disk error is reported");
    auto* shell = connectTo(_wtoi(argv[1]), "shell", true);
    const auto shellRoot = root / "shell";
    std::filesystem::create_directories(shellRoot / "nonempty");
    writeFile(shellRoot / "nonempty" / "keep.bin", bytes);
    check(SftpDeleteFileW(shell, (shellRoot / "nonempty").c_str(), true) == SFTP_FAILED &&
          std::filesystem::exists(shellRoot / "nonempty" / "keep.bin"), "shell rmdir preserves skipped files");
    std::filesystem::create_directory(shellRoot / "empty");
    check(SftpDeleteFileW(shell, (shellRoot / "empty").c_str(), true) == SFTP_OK && !std::filesystem::exists(shellRoot / "empty"),
          "shell rmdir reports actual success for an empty directory");
    check(SftpDeleteFileW(shell, L"/", true) == SFTP_FAILED && SftpDeleteFileW(shell, L"/a/..", true) == SFTP_FAILED,
          "shell deletion rejects root and dot paths");
    check(SftpCreateDirectoryW(shell, (shellRoot / "created").c_str()) == SFTP_OK && std::filesystem::is_directory(shellRoot / "created"),
          "shell mkdir uses the requested absolute path");
    check(SftpCreateDirectoryW(shell, (shellRoot / "missing" / "created").c_str()) == SFTP_FAILED,
          "shell mkdir reports a refused operation");
    const auto shellScp = shellRoot / "scp space.bin";
    check(SftpUploadFileW(shell, local.c_str(), shellScp.c_str(), false, false) == SFTP_OK && readFile(shellScp) == bytes,
          "shell SCP upload preserves a quoted absolute path");
    check(SftpDownloadFileW(shell, shellScp.c_str(), download.c_str(), true, bytes.size(), nullptr, false) == SFTP_OK && readFile(download) == bytes,
          "shell SCP download reads the header without an extra acknowledgement");
    writeFile(download, bytes.substr(0, 3));
    check(SftpDownloadFileW(shell, shellScp.c_str(), download.c_str(), true, bytes.size(), nullptr, true) == SFTP_OK && readFile(download) == bytes,
          "raw shell download resumes without losing bytes");
    writeFile(shellScp, bytes.substr(0, 3));
    check(SftpUploadFileW(shell, local.c_str(), shellScp.c_str(), true, false) == SFTP_OK && readFile(shellScp) == bytes,
          "raw shell upload resumes and checks completion");
    shell->shell_transfer_force = true; shell->shell_transfer_dd = true;
    const auto special = shellRoot / "space '; special.bin";
    check(SftpUploadFileW(shell, local.c_str(), special.c_str(), false, false) == SFTP_OK && readFile(special) == bytes,
          "shell base64 upload quotes names and verifies completion");
    check(SftpDownloadFileW(shell, special.c_str(), download.c_str(), true, bytes.size(), nullptr, false) == SFTP_OK && readFile(download) == bytes,
          "shell base64 download preserves complete bytes");
    check(SftpRenameMoveFileW(shell, special.c_str(), (shellRoot / "renamed.bin").c_str(), true, false, false) == SFTP_OK &&
          !std::filesystem::exists(special) && readFile(shellRoot / "renamed.bin") == bytes, "shell rename uses Unix paths and checks exit status");
    check(SftpUploadFileW(shell, local.c_str(), (shellRoot / "missing" / "failure.bin").c_str(), false, false) != SFTP_OK,
          "shell upload failure is not reported as success");
    if (argc == 4) {
        auto* php = new tConnectSettings{};
        php->transfermode = static_cast<int>(sftp::TransferMode::php_agent);
        php->server = "http://127.0.0.1:" + std::to_string(_wtoi(argv[3])) + "/sftp.php";
        php->password = "synthetic-pass";
        php->DisplayName = "php";
        SetServerIdForName("php", php);
        check(PhpAgentProbe(php) == SFTP_OK, "production PHP agent negotiation succeeds");
        check(SftpUploadFileW(php, local.c_str(), L"/source.bin", false, false) == SFTP_OK, "signed PHP upload succeeds");
        check(SftpFileExistsW(php, L"/source.bin") == 1 && SftpFileExistsW(php, L"/missing.bin") == 0,
              "PHP destination probe distinguishes existing and missing files");
        info.Size64 = bytes.size();
        check(FsRenMovFileW(L"\\php\\source.bin", L"\\php\\copy.bin", false, false, &info) == FS_FILE_OK &&
              SftpFileExistsW(php, L"/source.bin") == 1, "PHP same-session copy preserves the source");
        php->password = "wrong-synthetic-pass";
        check(SftpFileExistsW(php, L"/missing.bin") == -1, "PHP authentication failure is not treated as a missing file");
        SetServerIdForName("php", nullptr);
    }
    SetServerIdForName("shell", nullptr);
    SetServerIdForName("other", nullptr);
    SetServerIdForName("synthetic", nullptr);
    libssh2_exit();
    std::cout << "SSH integration: " << failures << " failures\n";
    return failures ? 1 : 0;
}
