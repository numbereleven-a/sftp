#include "global.h"
#include "LanPair.h"
#include "LanPairSession.h"
#include "LanPairInternal.h"
#include "LanPairAuth.h"
#include "LanPairProtocol.h"
#include "ProfileSettings.h"
#include "SftpClient.h"
#include "IsolatedAppData.h"
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <chrono>
#include <future>
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

    // 1. RFC 9382 P-256 SPAKE2 test vector.
    {
        auto hexVec = [](const char* h) {
            auto d = lanpair_internal::hexDecode(h);
            return d ? *d : std::vector<uint8_t>{};
        };
        auto hexEq = [&](auto&& arr, const char* h) {
            const auto d = hexVec(h);
            return d.size() == arr.size() && std::equal(arr.begin(), arr.end(), d.begin());
        };
        const auto w = hexVec("2ee57912099d31560b3a44b1184b9b4866e904c49d12ac5042c97dca461b1a5f");
        const auto x = hexVec("43dd0fd7215bdcb482879fca3220c6a968e66d70b1356cac18bb26c84a78d729");
        const auto y = hexVec("dcb60106f276b02606d8ef0a328c02e4b629f84f89786af5befb0bc75b6e66be");
        lanpair_proto::Spake2 a(lanpair_proto::Spake2::Role::A, "server", "client", w, x);
        lanpair_proto::Spake2 b(lanpair_proto::Spake2::Role::B, "server", "client", w, y);
        check(a.ok() && b.ok(), "SPAKE2 RFC 9382 init succeeded");
        check(a.finish(b.share(), "") && b.finish(a.share(), ""), "SPAKE2 RFC 9382 finish succeeded");
        check(hexEq(a.secrets().transcriptHash, "0e0672dc86f8e45565d338b0540abe6915bdf72e2b35b5c9e5663168e960a91b"),
              "SPAKE2 RFC 9382 transcript hash matches");
        check(hexEq(a.secrets().ke, "0e0672dc86f8e45565d338b0540abe69"), "SPAKE2 RFC 9382 Ke matches");
        check(hexEq(a.secrets().ka, "15bdf72e2b35b5c9e5663168e960a91b"), "SPAKE2 RFC 9382 Ka matches");
        check(hexEq(a.secrets().kcA, "00c12546835755c86d8c0db7851ae86f"), "SPAKE2 RFC 9382 KcA matches");
        check(hexEq(a.secrets().kcB, "a9fa3406c3b781b93d804485430ca27a"), "SPAKE2 RFC 9382 KcB matches");
        check(hexEq(a.confirmation(), "58ad4aa88e0b60d5061eb6b5dd93e80d9c4f00d127c65b3b35b1b5281fee38f0"),
              "SPAKE2 RFC 9382 cA matches");
        check(hexEq(b.confirmation(), "d3e2e547f1ae04f2dbdbf0fc4b79f8ecff2dff314b5d32fe9fcef2fb26dc459b"),
              "SPAKE2 RFC 9382 cB matches");
        check(a.secrets().transcriptHash == b.secrets().transcriptHash &&
              a.checkPeerConfirmation(b.confirmation()) && b.checkPeerConfirmation(a.confirmation()),
              "SPAKE2 RFC 9382 mutual key confirmation matches");

        // Mismatched passwords and invalid curve points must fail.
        const std::vector<uint8_t> otherW(32, 0xA5);
        lanpair_proto::Spake2 c(lanpair_proto::Spake2::Role::A, "server", "client", w);
        lanpair_proto::Spake2 d(lanpair_proto::Spake2::Role::B, "server", "client", otherW);
        check(c.ok() && d.ok() && c.finish(d.share(), "aad") && d.finish(c.share(), "aad") &&
              !c.checkPeerConfirmation(d.confirmation()) && !d.checkPeerConfirmation(c.confirmation()),
              "SPAKE2 mismatched keys fail confirmation");
        std::vector<uint8_t> badPoint(65, 0x04);
        lanpair_proto::Spake2 e(lanpair_proto::Spake2::Role::A, "server", "client", w);
        check(!e.finish(badPoint, "aad"), "SPAKE2 rejects off-curve share");
        std::vector<uint8_t> infinityPoint = {0x00};
        check(!e.finish(infinityPoint, "aad"), "SPAKE2 rejects infinity/short share");

        // AES-256-GCM frame encryption: confidentiality, tamper, replay, reorder.
        lanpair_proto::ChannelMaterial matA, matB;
        check(lanpair_proto::DeriveChannelMaterial(a.secrets(), true, matA) &&
              lanpair_proto::DeriveChannelMaterial(b.secrets(), false, matB),
              "channel material derived for both sides");
        lanpair_proto::GcmCipher txA, rxB;
        check(txA.init(matA.txKey, matA.txSalt) && rxB.init(matB.rxKey, matB.rxSalt),
              "AES-256-GCM ciphers initialized");
        const std::string secretPayload = "SECRET-PAYLOAD-LINE\n";
        std::vector<uint8_t> frame0, frame1;
        check(txA.encryptFrame(reinterpret_cast<const uint8_t*>(secretPayload.data()), secretPayload.size(), frame0),
              "AES-256-GCM encrypts frame 0");
        check(std::string(frame0.begin(), frame0.end()).find("SECRET-PAYLOAD") == std::string::npos,
              "encrypted frame hides plaintext");
        check(txA.encryptFrame(reinterpret_cast<const uint8_t*>(secretPayload.data()), secretPayload.size(), frame1),
              "AES-256-GCM encrypts frame 1");

        // Tamper ciphertext, tag, and length header; verify rejection.
        auto tamperedCt = frame0;
        tamperedCt[lanpair_proto::kFrameHeaderSize] ^= 0x01;
        std::vector<uint8_t> plain(secretPayload.size());
        {
            lanpair_proto::GcmCipher rxCheck;
            rxCheck.init(matB.rxKey, matB.rxSalt);
            check(!rxCheck.decryptFrame(tamperedCt.data(), tamperedCt.data() + 4, secretPayload.size(), plain.data()),
                  "AES-256-GCM rejects tampered ciphertext");
        }
        {
            auto tamperedTag = frame0;
            tamperedTag.back() ^= 0x01;
            lanpair_proto::GcmCipher rxCheck;
            rxCheck.init(matB.rxKey, matB.rxSalt);
            check(!rxCheck.decryptFrame(tamperedTag.data(), tamperedTag.data() + 4, secretPayload.size(), plain.data()),
                  "AES-256-GCM rejects tampered tag");
        }
        {
            lanpair_proto::GcmCipher rxReorder;
            rxReorder.init(matB.rxKey, matB.rxSalt);
            check(!rxReorder.decryptFrame(frame1.data(), frame1.data() + 4, secretPayload.size(), plain.data()),
                  "AES-256-GCM rejects reordered frame");
        }
        check(rxB.decryptFrame(frame0.data(), frame0.data() + 4, secretPayload.size(), plain.data()) &&
              std::string(plain.begin(), plain.end()) == secretPayload,
              "AES-256-GCM decrypts frame 0");
        check(!rxB.decryptFrame(frame0.data(), frame0.data() + 4, secretPayload.size(), plain.data()),
              "AES-256-GCM rejects replayed frame 0");
    }
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
    check(!session->putFile(download.c_str(), share + "/hello.txt", false, false, &status) && status == FS_FILE_EXISTS,
          "upload asks before replacing an existing file");
    check(!session->rename(share + "/upload.txt", share + "/hello.txt", false, &status) && status == FS_FILE_EXISTS,
          "rename asks before replacing an existing file");
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
            const std::string cmd = "ROOTS\n";
            std::vector<uint8_t> frame;
            check(channel && channel->txCipher &&
                  channel->txCipher->encryptFrame(reinterpret_cast<const uint8_t*>(cmd.data()), cmd.size(), frame),
                  "tamper test encrypted frame");
            frame[lanpair_proto::kFrameHeaderSize] ^= 1;
            lanpair_internal::rawSendAll(altered, frame.data(), frame.size());
            check(!lanpair_internal::recvLine(altered, &response), "modified encrypted frame rejected");
            lanpair_internal::closeSocket(altered);
        }
    }
    {
        auto connectRaw = [&]() {
            SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            sockaddr_in address{}; address.sin_family = AF_INET; address.sin_port = htons(45986);
            address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            if (::connect(s, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
                closesocket(s);
                return INVALID_SOCKET;
            }
            return s;
        };
        SOCKET legacyPair1 = connectRaw();
        if (legacyPair1 != INVALID_SOCKET) {
            lanpair_internal::rawSendAll(legacyPair1, reinterpret_cast<const uint8_t*>("PAIR1 HELLO old 0 00\n"), 21);
            std::string resp;
            check(lanpair_internal::recvLine(legacyPair1, &resp) && resp == "PAIR1 FAIL upgrade-required",
                  "legacy PAIR1 peer receives upgrade-required");
            closesocket(legacyPair1);
        } else {
            check(false, "legacy PAIR1 socket connected");
        }
        SOCKET oldPair3 = connectRaw();
        if (oldPair3 != INVALID_SOCKET) {
            lanpair_internal::rawSendAll(oldPair3, reinterpret_cast<const uint8_t*>("PAIR3 HELLO old 0 00\n"), 21);
            std::string resp;
            check(lanpair_internal::recvLine(oldPair3, &resp) && resp == "PAIR3 FAIL upgrade-required",
                  "pre-10.3.1 PAIR3 HELLO peer receives upgrade-required");
            closesocket(oldPair3);
        } else {
            check(false, "pre-10.3.1 PAIR3 socket connected");
        }
    }
    // Preserve existing destination across insufficient-space and interrupted overwrites.
    auto b64 = [](const std::string& in) {
        static constexpr char kTbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        int val = 0, valb = -6;
        for (unsigned char c : in) {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) { out.push_back(kTbl[(val >> valb) & 0x3F]); valb -= 6; }
        }
        if (valb > -6) out.push_back(kTbl[((val << 8) >> (valb + 8)) & 0x3F]);
        while (out.size() % 4) out.push_back('=');
        return out;
    };
    const auto preservedFile = root / "preserve.txt";
    { std::ofstream file(preservedFile, std::ios::binary); file << "ORIGINAL-DATA"; }
    auto readAll = [](const std::filesystem::path& p) {
        std::ifstream f(p, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(f), {});
    };
    {
        SOCKET spaceSock = connectAuthenticated();
        check(spaceSock != INVALID_SOCKET, "space-check test authenticated");
        if (spaceSock != INVALID_SOCKET) {
            lanpair_internal::sendLine(spaceSock, "LAN3 HELLO");
            std::string line;
            lanpair_internal::recvLine(spaceSock, &line);
            const std::string remoteTarget = share + "/preserve.txt";
            lanpair_internal::sendLine(
                spaceSock,
                "PUT2 " + b64(remoteTarget) + " 1152921504606846976 1");
            check(lanpair_internal::recvLine(spaceSock, &line) && line == "ERR insufficient-space",
                  "insufficient space rejected before truncating target");
            check(readAll(preservedFile) == "ORIGINAL-DATA", "insufficient space leaves existing file intact");
            lanpair_internal::closeSocket(spaceSock);
        }
    }
    {
        SOCKET partialSock = connectAuthenticated();
        check(partialSock != INVALID_SOCKET, "partial-overwrite test authenticated");
        if (partialSock != INVALID_SOCKET) {
            lanpair_internal::sendLine(partialSock, "LAN3 HELLO");
            std::string line;
            lanpair_internal::recvLine(partialSock, &line);
            const std::string remoteTarget = share + "/preserve.txt";
            lanpair_internal::sendLine(
                partialSock,
                "PUT2 " + b64(remoteTarget) + " 1024 1");
            check(lanpair_internal::recvLine(partialSock, &line) && line == "OK",
                  "staged overwrite accepted header before stream");
            lanpair_internal::sendAll(partialSock, reinterpret_cast<const uint8_t*>("PARTIAL"), 7);
            lanpair_internal::closeSocket(partialSock);
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
    check(readAll(preservedFile) == "ORIGINAL-DATA", "interrupted overwrite preserves original file");
    bool hasTempLeftover = false;
    for (const auto& entry : std::filesystem::directory_iterator(root)) {
        if (entry.path().filename().wstring().find(L".lan3tmp.") != std::wstring::npos)
            hasTempLeftover = true;
    }
    check(!hasTempLeftover, "interrupted overwrite cleans up staging temp file");
    closesocket(idle);
    session.reset();
    return failures ? 1 : 0;
}
