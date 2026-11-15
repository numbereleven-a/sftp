#include "global.h"
#include "SftpInternal.h"
#include "Libssh2Backend.h"
#include "PluginEntryPoints.h"
#include <filesystem>
#include <fstream>
#include <iostream>

static int WINAPI progress(int, LPCSTR, LPCSTR, int) { return 0; }
static void WINAPI logMessage(int, int, LPCSTR) {}
static BOOL WINAPI request(int, int, LPCSTR, LPCSTR, LPSTR, int) { return FALSE; }

int wmain(int argc, wchar_t** argv)
{
    if (argc != 3) return 2;
    FsInit(42, progress, logMessage, request);
    libssh2_init(0);
    tConnectSettings cs{};
    cs.sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(static_cast<u_short>(_wtoi(argv[1])));
    if (connect(cs.sock, reinterpret_cast<sockaddr*>(&address), sizeof(address))) return 2;
    Libssh2Backend backend;
    cs.session = backend.createSession(nullptr, nullptr, nullptr, &cs);
    cs.session->setBlocking(1);
    if (cs.session->startup(static_cast<int>(cs.sock)) ||
        cs.session->userauthPassword("synthetic", 9, "synthetic-pass", 14, nullptr)) return 2;
    cs.session->setBlocking(0);
    SetBlockingSocket(cs.sock, false);
    cs.scponly = cs.scpfordata = cs.shell_transfer_force = cs.shell_transfer_dd = true;
    cs.utf8names = 1;
    cs.filemod = 0644;
    std::filesystem::path root(argv[2]);
    const auto source = root / "source.bin", target = root / "upload.bin";
    std::string expected(96 * 1024 + 7, '\0');
    for (size_t i = 0; i < expected.size(); ++i) expected[i] = static_cast<char>(i * 73);
    { std::ofstream output(source, std::ios::binary); output.write(expected.data(), expected.size()); }
    const ULONGLONG start = GetTickCount64();
    const int rc = SftpUploadFileW(&cs, source.c_str(), target.c_str(), false, false);
    const ULONGLONG elapsed = GetTickCount64() - start;
    std::ifstream input(target, std::ios::binary);
    const std::string actual{std::istreambuf_iterator<char>(input), {}};
    const bool ok = rc == SFTP_OK && actual == expected;
    std::cout << (ok ? "PASS" : "FAIL") << " shell upload: " << expected.size() << " bytes, " << elapsed << " ms\n";
    SftpCloseConnection(&cs);
    libssh2_exit();
    return ok ? 0 : 1;
}
