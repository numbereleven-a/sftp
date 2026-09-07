// Exercise production LAN2 transfers over loopback with real Windows files.
// Inject an already-connected socket; pairing is outside this transfer test.
#include "global.h"
#include <memory>
#include <vector>
#include <string>
#include <sstream>
#include <fstream>
#include "LanPair.h"
#define private public
#include "LanPairSession.h"
#undef private
#include "../src/core/LanPairSession.cpp"
#include <filesystem>
#include <iostream>

extern "C" BOOL AcquireTrustedInstallerToken() { return FALSE; }
extern "C" BOOL ReleaseTrustedInstallerToken() { return TRUE; }
// These dependencies are not used by the injected transfer-only session.
namespace lanpair::DpapiSecretStore {
bool saveSecret(const std::string&, const std::string&, PairError*) { std::abort(); }
bool loadSecret(const std::string&, std::string*, PairError*) { std::abort(); }
bool deleteSecret(const std::string&, PairError*) { std::abort(); }
}
namespace sftp {
DllExceptionBarrier::~DllExceptionBarrier() noexcept = default;
void DllExceptionBarrier::capture() noexcept { std::abort(); }
}

int main(int argc, char** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    const std::string mode = argc > 1 ? argv[1] : "resume";
    const bool upload = mode.starts_with("upload-");
    const bool fresh = mode == "fresh";
    const std::string initial = mode == "empty" || fresh ? "" : mode == "complete" ? "ABCDEF" : "ABC";
    const std::string remainder = std::string("ABCDEF").substr(initial.size());
    lanpair_internal::WsaScope wsa;
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) || listen(listener, 1)) return 2;
    int length = sizeof(address);
    getsockname(listener, reinterpret_cast<sockaddr*>(&address), &length);
    SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (::connect(client, reinterpret_cast<sockaddr*>(&address), length)) return 2;
    SOCKET peer = accept(listener, nullptr, nullptr);
    closesocket(listener);
    setSocketTimeout(client, 3000);
    setSocketTimeout(peer, 3000);
    auto impl = std::make_unique<LanPairSession::Impl>();
    impl->sock_ = client;
    impl->connected_ = true;
    LanPairSession session(std::move(impl));
    const auto file = std::filesystem::temp_directory_path() /
        (L"sftp-lan-transfer-" + std::to_wstring(GetCurrentProcessId()) + L".txt");
    std::ofstream(file, std::ios::binary) << initial;
    bool requestOk = false;
    std::thread server([&] {
        std::string request;
        recvLine(peer, &request);
        if (upload) {
            sendLine(peer, "OK");
            std::vector<uint8_t> bytes(initial.size());
            requestOk = recvAll(peer, bytes.data(), bytes.size()) &&
                std::string(bytes.begin(), bytes.end()) == initial;
            if (mode != "upload-closed")
                sendLine(peer, mode == "upload-ok" ? "DONE" : mode == "upload-spaces" ? "   " : "");
        } else {
            requestOk = request.ends_with(" " + std::to_string(initial.size()));
            sendLine(peer, "OK " + std::to_string(remainder.size()));
            sendAll(peer, reinterpret_cast<const uint8_t*>(remainder.data()), remainder.size());
        }
        shutdown(peer, SD_SEND);
        closesocket(peer);
    });
    int result = -1;
    bool ok;
    if (upload) {
        const bool sent = session.putFile(file.c_str(), "/synthetic", true, false, &result);
        ok = mode == "upload-ok" ? sent && result == FS_FILE_OK :
             !sent && result == FS_FILE_WRITEERROR && !session.isConnected();
    } else {
        const bool received = session.getFile("/synthetic", file.c_str(), 6, nullptr, true, !fresh, &result);
        std::ifstream input(file, std::ios::binary);
        std::string contents((std::istreambuf_iterator<char>(input)), {});
        ok = received && result == FS_FILE_OK && contents == "ABCDEF";
        std::cout << "Expected size 6, actual size " << contents.size() << '\n';
    }
    server.join();
    ok = ok && requestOk;
    std::filesystem::remove(file);
    std::cout << (ok ? "PASS " : "FAIL ") << mode << std::endl;
    return ok ? 0 : 1;
}
