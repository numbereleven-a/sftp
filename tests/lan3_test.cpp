#include "global.h"
#include "LanPair.h"
#include "LanPairSession.h"
#include "LanPairInternal.h"
#include "LanPairAuth.h"
#include "ProfileSettings.h"
#include "SftpClient.h"
#include "IsolatedAppData.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <chrono>
#include <thread>

// These synthetic profiles do not contain passwords.
void DecryptString(LPCTSTR, LPTSTR, UINT) { std::abort(); }
static int failures = 0;
static void check(bool result, const char* message) {
    std::cout << (result ? "PASS " : "FAIL ") << message << '\n';
    if (!result) ++failures;
}

int main() {
    std::cout << std::unitbuf;
    IsolatedAppData isolated;
    lanpair_internal::WsaScope wsa;
    const auto profileFile = isolated.path / "profiles.ini";
    for (int role = 0; role <= 2; ++role) {
        const std::string name = "role" + std::to_string(role);
        WritePrivateProfileStringW(std::wstring(name.begin(), name.end()).c_str(), L"server", L"synthetic", profileFile.c_str());
        const std::wstring value = std::to_wstring(role);
        WritePrivateProfileStringW(std::wstring(name.begin(), name.end()).c_str(), L"lanpairrole", value.c_str(), profileFile.c_str());
        tConnectSettings settings{};
        const std::string fileName = profileFile.string();
        check(LoadServerSettings(name.c_str(), &settings, fileName.c_str()) && settings.lan_pair_role == role,
              "saved LAN role preserved");
    }
    auto root = isolated.path / "shared";
    std::filesystem::create_directories(root);
    { std::ofstream file(root / "hello.txt", std::ios::binary); file << "ABCDEF"; }
    const auto utf8Root = root.u8string();
    const std::string share(reinterpret_cast<const char*>(utf8Root.data()), utf8Root.size());
    LanFileServer server;
    lanpair::PairError error;
    check(!server.start(45986, &error), "donor rejected missing password/share");
    server.setPassword("synthetic-pair-password");
    server.setAllowedRoots({share});
    if (!server.start(45986, &error)) { check(false, "server started"); return 1; }
    auto session = LanPairSession::connect("127.0.0.1", 45986, "synthetic-client", "", "wrong", &error);
    check(!session, "wrong password rejected");
    session = LanPairSession::connect("127.0.0.1", 45986, "synthetic-client", "", "synthetic-pair-password", &error);
    check(session != nullptr, "password pairing succeeded");
    if (!session) { server.stop(); return 1; }
    std::vector<std::string> roots;
    check(session->listRoots(roots) && roots.size() == 1, "only configured share exposed");
    std::vector<LanPairSession::DirEntry> entries;
    check(session->listDirectory(share, entries) && entries.size() == 1 && entries[0].name == "hello.txt", "authenticated listing succeeded");
    check(!session->listDirectory("C:\\", entries), "outside share rejected");
    check(!session->mkdir(share + "/../escaped"), "parent traversal rejected");
    check(session->mkdir(share + "/a..b"), "valid dotted folder accepted");
    const auto download = isolated.path / "download.txt";
    { std::ofstream file(download, std::ios::binary); file << "ABC"; }
    int status = -1;
    check(session->getFile(share + "/hello.txt", download.c_str(), 6, nullptr, true, true, &status) &&
          std::filesystem::file_size(download) == 6, "authenticated resume succeeded");
    check(session->putFile(download.c_str(), share + "/upload.txt", true, false, &status), "authenticated upload succeeded");
    check(session->rename(share + "/upload.txt", share + "/renamed.txt"), "authenticated rename succeeded");
    check(session->remove(share + "/renamed.txt"), "authenticated removal succeeded");
    session->disconnect();
    session = LanPairSession::connect("127.0.0.1", 45986, "synthetic-client", "", "", &error);
    check(session != nullptr, "stored trust reconnected without password");
    auto connectAuthenticated = [&]() {
        SOCKET socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in address{}; address.sin_family = AF_INET; address.sin_port = htons(45986);
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (::connect(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) ||
            !lanpair_internal::authenticatePeerClient(socket, "frame-test", "", "synthetic-pair-password",
                                                       lanpair::PairRole::Receiver, nullptr)) {
            lanpair_internal::closeSocket(socket); return INVALID_SOCKET;
        }
        return socket;
    };
    {
        SOCKET malformed = connectAuthenticated();
        check(malformed != INVALID_SOCKET, "malformed-hello test authenticated");
        if (malformed != INVALID_SOCKET) {
            lanpair_internal::sendLine(malformed, "LAN3 INVALID");
            std::string response;
            check(!lanpair_internal::recvLine(malformed, &response), "invalid authenticated hello rejected");
            lanpair_internal::closeSocket(malformed);
        }
    }
    {
        SOCKET altered = connectAuthenticated();
        check(altered != INVALID_SOCKET, "tamper test authenticated");
        if (altered != INVALID_SOCKET) {
            lanpair_internal::sendLine(altered, "LAN3 HELLO");
            std::string response;
            lanpair_internal::recvLine(altered, &response);
            auto channel = lanpair_internal::channelFor(altered);
            std::vector<uint8_t> frame(12 + 6);
            uint32_t length = htonl(6); memcpy(frame.data(), &length, 4);
            for (size_t i = 0; i < 8; ++i) frame[4+i] = static_cast<uint8_t>(channel->txSequence >> ((7-i)*8));
            memcpy(frame.data() + 12, "ROOTS\n", 6);
            auto mac = lanpair_internal::hmacSha256(channel->txKey, frame);
            frame[12] ^= 1;
            lanpair_internal::rawSendAll(altered, frame.data(), frame.size());
            lanpair_internal::rawSendAll(altered, mac->data(), mac->size());
            check(!lanpair_internal::recvLine(altered, &response), "modified authenticated frame rejected");
            lanpair_internal::closeSocket(altered);
        }
    }
    // Interrupt an authenticated idle client, then a pre-authentication client.
    SOCKET idle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in address{}; address.sin_family = AF_INET; address.sin_port = htons(45986);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    connect(idle, reinterpret_cast<sockaddr*>(&address), sizeof(address));
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    const auto start = std::chrono::steady_clock::now();
    server.stop();
    check(std::chrono::steady_clock::now() - start < std::chrono::seconds(1), "idle clients interrupted during shutdown");
    closesocket(idle);
    session.reset();
    return failures ? 1 : 0;
}
