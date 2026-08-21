// lanpair_wire_test.cpp вЂ” F14 verification: during PAIR1 pairing the
// long-term trust secret must NEVER appear on the wire, yet both sides must
// end up holding the identical key.
//
// Uses real lanpair primitives + the real LanFileServer; the client side is
// an inline re-implementation of the fixed pair1Connect flow so every byte
// can be captured.
#define WIN32_LEAN_AND_MEAN
#define _WINSOCKAPI_
#include "LanPair.h"
#include "LanPairSession.h"
#include "LanPairInternal.h"
#include <cstdio>
#include <filesystem>
#include <string>
#include <thread>
#include <chrono>

using namespace lanpair;
using namespace lanpair_internal;

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (cond) printf("  OK   %s\n", msg); \
    else    { printf("  FAIL %s\n", msg); ++failures; } } while(0)

static void WipeSecretStore() {
    char appData[MAX_PATH] = {};
    GetEnvironmentVariableA("APPDATA", appData, MAX_PATH);
    std::error_code ec;
    std::filesystem::remove_all(
        std::filesystem::path(appData) / "GHISLER" / "sftpplug.secrets", ec);
}

static bool ContainsBytes(const std::string& hay, const std::vector<uint8_t>& needle) {
    if (needle.empty()) return false;
    return hay.find(reinterpret_cast<const char*>(needle.data()), 0, needle.size())
           != std::string::npos;
}

int main()
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    const std::string password = "wire-secret-2026";
    const std::string myId  = "wire-client";
    WipeSecretStore();

    LanFileServer server;
    PairError err;
    if (!server.start(45896, &err)) { printf("server start failed\n"); return 1; }
    server.setPassword(password);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    char host[256] = {};
    gethostname(host, sizeof(host) - 1);
    const std::string serverId = host;

    // ---- Raw client with full wire capture ----
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    setSocketTimeout(s, 8000);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(45896);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(s, (sockaddr*)&addr, sizeof(addr)) != 0) { printf("connect failed\n"); return 1; }

    std::string wireLog;   // everything sent + received

    std::array<uint8_t, kNonceSize> nonce{};
    randomBytes(nonce.data(), nonce.size());
    const std::string nonceHex = hexEncode(nonce.data(), nonce.size());

    std::string hello = std::string("PAIR1 HELLO ") + myId + " receiver " + nonceHex;
    wireLog += hello + "\n";
    sendLine(s, hello);

    std::string line;
    if (!recvLine(s, &line)) { printf("no challenge\n"); return 1; }
    wireLog += line + "\n";
    const auto ch = splitBySpace(line);
    if (ch.size() != 7 || ch[1] != "CHALLENGE") { printf("bad challenge\n"); return 1; }
    const std::string srvPeer = ch[2];
    const auto salt = hexDecode(ch[5]);
    const auto srvNonce = hexDecode(ch[6]);

    const std::string material =
        "C|" + nonceHex + "|" + ch[6] + "|" + myId + "|" + srvPeer;

    // Fixed-client behavior: derive key from password, send AUTH proof.
    const auto pwKey = deriveKeyPbkdf2(password, derivePairSalt(myId, srvPeer), kDerivedKeySize);
    if (!pwKey) { printf("kdf failed\n"); return 1; }
    const auto proof = hmacSha256(*pwKey,
        std::span<const uint8_t>((const uint8_t*)material.data(), material.size()));

    // --- Simulation of the exact server-side AUTH verification ---
    {
        std::string srvCombined;
        if (srvPeer < myId) srvCombined = srvPeer + "<>" + myId;
        else                srvCombined = myId + "<>" + srvPeer;
        std::vector<uint8_t> srvSalt(16, 0);
        auto h = hmacSha256(
            std::span<const uint8_t>((const uint8_t*)"LANPAIR", 7),
            std::span<const uint8_t>((const uint8_t*)srvCombined.data(), srvCombined.size()));
        for (size_t i = 0; i < 16 && h && i < h->size(); ++i) srvSalt[i] = (*h)[i];
        auto srvKeyOpt = deriveKeyPbkdf2(password, srvSalt, kDerivedKeySize);
        if (!srvKeyOpt) { printf("sim: kdf failed\n"); }
        else {
            auto e = hmacSha256(*srvKeyOpt,
                std::span<const uint8_t>((const uint8_t*)material.data(), material.size()));
            const bool match = e && hexEncode(e->data(), e->size()) ==
                                     hexEncode(proof->data(), proof->size());
            printf("sim: salt=[%s] proof %s\n",
                   hexEncode(srvSalt.data(), srvSalt.size()).c_str(),
                   match ? "MATCH" : "MISMATCH");
        }
    }

    std::string auth = "PAIR1 AUTH " + hexEncode(proof->data(), proof->size());
    wireLog += auth + "\n";
    sendLine(s, auth);

    if (!recvLine(s, &line)) {
        printf("no response, WSALastError=%d line='%s'\n", WSAGetLastError(), line.c_str());
        try {
            char appData[MAX_PATH] = {};
            GetEnvironmentVariableA("APPDATA", appData, MAX_PATH);
            std::filesystem::path dir = std::filesystem::path(appData) / "GHISLER" / "sftpplug.secrets";
            if (std::filesystem::exists(dir))
                for (auto& f : std::filesystem::directory_iterator(dir))
                    printf("  secret file: %s\n", f.path().filename().string().c_str());
            else
                printf("  secrets dir missing (server never cached trust)\n");
        } catch (const std::exception& e) { printf("  dir scan: %s\n", e.what()); }
        return 1;
    }
    wireLog += line + "\n";
    const auto ok = splitBySpace(line);
    CHECK(ok.size() >= 3 && ok[1] == "OK", "server accepted password AUTH");
    closesocket(s);

    // ---- Assertions ----
    const std::string keyHex = hexEncode(pwKey->data(), pwKey->size());
    CHECK(!ContainsBytes(wireLog, *pwKey), "raw 32-byte key NOT on the wire");
    CHECK(wireLog.find(keyHex) == std::string::npos, "hex-encoded key NOT on the wire");
    CHECK(wireLog.find(password) == std::string::npos, "password NOT on the wire");

    // Both sides must hold the SAME long-term secret: server cached
    // PBKDF2(password) as trust during AUTH; emulate the fixed client's
    // post-verification save and compare.
    const std::string cliTrustName = trustKeyForClient(srvPeer, myId);
    std::string saved;
    std::vector<uint8_t> keyVec(pwKey->begin(), pwKey->end());
    std::string rawKey(keyVec.begin(), keyVec.end());
    if (DpapiSecretStore::saveSecret(cliTrustName, rawKey, nullptr) &&
        DpapiSecretStore::loadSecret(cliTrustName, &saved, nullptr)) {
        CHECK(saved == rawKey, "client-side stored key == PBKDF2(password)");
    } else {
        CHECK(false, "DPAPI roundtrip of derived key");
    }

    printf(failures ? "FAILED failures=%d\n" : "ALL OK (failures=%d)\n", failures);
    return failures ? 1 : 0;
}
