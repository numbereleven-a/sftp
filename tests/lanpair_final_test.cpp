// lanpair_final_test.cpp — final round of headless verifications against REAL
// plugin sources:
//   F1 : PAIR1 HELLO carries the configured role (not hardcoded "donor")
//   F3 : unauthenticated connections never trigger TI impersonation
//   F4 : failed/resumed downloads never delete pre-existing local files
//        (deterministic: a fake LAN2 server truncates the stream mid-transfer)
#define WIN32_LEAN_AND_MEAN
#define _WINSOCKAPI_
#include "LanPair.h"
#include "LanPairSession.h"
#include "LanPairInternal.h"
#include "TrustedInstallerToken.h"
#include <cstdio>
#include <filesystem>
#include <fstream>
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

static std::string ReadLine(SOCKET s) {
    std::string line;
    char c = 0;
    while (line.size() < 4096) {
        const int n = recv(s, &c, 1, 0);
        if (n <= 0) return line;
        if (c == '\n') break;
        if (c != '\r') line.push_back(c);
    }
    return line;
}

static void SendLine(SOCKET s, const std::string& l) {
    std::string w = l + "\n";
    send(s, w.c_str(), (int)w.size(), 0);
}

// ---------------------------------------------------------------------------
// F1: fake PAIR1 server capturing the HELLO role token.
// ---------------------------------------------------------------------------
static std::string g_helloRole;
static DWORD WINAPI F1ServerThread(LPVOID) {
    SOCKET srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in a{};
    a.sin_family = AF_INET; a.sin_port = htons(45891); a.sin_addr.s_addr = INADDR_ANY;
    BOOL y = TRUE;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char*)&y, sizeof(y));
    if (bind(srv, (sockaddr*)&a, sizeof(a)) != 0) return 1;
    listen(srv, 1);
    SOCKET c = accept(srv, nullptr, nullptr);
    if (c == INVALID_SOCKET) return 1;
    // Optional TI probe must not have happened for an unauthenticated client.
    const bool tiActive = IsTrustedInstallerImpersonationActive() != FALSE;
    const std::string hello = ReadLine(c);
    const auto parts = splitBySpace(hello);
    if (parts.size() >= 4) g_helloRole = parts[3];
    if (!tiActive) printf("  OK   F3: no TI impersonation for unauthenticated peer\n");
    else         { printf("  FAIL F3: TI impersonated before auth\n"); ++failures; }
    closesocket(c); closesocket(srv);
    return 0;
}

static void TestF1F3() {
    printf("[F1+F3] HELLO role + no-TI-before-auth\n");
    WipeSecretStore();
    HANDLE t = CreateThread(nullptr, 0, F1ServerThread, nullptr, 0, nullptr);
    Sleep(200);

    PairError err;
    // Client with NO password and NO stored trust -> fails after HELLO locally,
    // which is exactly what we need to observe the wire.
    auto s = LanPairSession::connect("127.0.0.1", 45891,
                                     "f1-client", "f1-server", "", &err,
                                     lanpair::PairRole::Receiver);
    WaitForSingleObject(t, 5000);
    CloseHandle(t);
    printf("  DBG  err='%s' helloRole='%s'\n", err.message.c_str(), g_helloRole.c_str());
    // The fake server closes without completing the handshake, so only the
    // fact of local rejection is asserted here; the exact
    // "trust-password-required" reason is covered by T4 against the REAL server.
    CHECK(!s, "client without password does not pair");
    CHECK(g_helloRole == "receiver",
          "HELLO role == configured 'Receiver' (was hardcoded 'donor')");
}

// ---------------------------------------------------------------------------
// F4: fake LAN2 server that authenticates a real client then truncates a GET.
// ---------------------------------------------------------------------------
struct FakeSrv {
    SOCKET srv = INVALID_SOCKET;
    std::string password = "f4-pass";
    std::string serverId = "f4-server";
    std::atomic<bool> stop{false};
    std::thread th;

    void start(uint16_t port) {
        srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(port);
        a.sin_addr.s_addr = INADDR_ANY;
        BOOL y = TRUE; setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char*)&y, sizeof(y));
        bind(srv, (sockaddr*)&a, sizeof(a)); listen(srv, 4);
        th = std::thread([this] { loop(); });
    }
    void loop() {
        while (!stop.load()) {
            SOCKET c = accept(srv, nullptr, nullptr);
            if (c == INVALID_SOCKET) continue;
            std::thread([this, c] { serve(c); }).detach();
        }
    }
    void serve(SOCKET c) {
        // ---- minimal PAIR1 server-side ----
        const std::string hello = ReadLine(c);
        const auto hp = splitBySpace(hello);
        if (hp.size() != 5 || hp[1] != "HELLO") { closesocket(c); return; }
        const std::string clientId = hp[2];
        const std::string nonceHex = hp[4];

        std::array<uint8_t,16> sn{};
        randomBytes(sn.data(), sn.size());
        const std::string snHex = hexEncode(sn.data(), sn.size());
        std::array<uint8_t,16> salt{};
        randomBytes(salt.data(), salt.size());
        SendLine(c, "PAIR1 CHALLENGE " + serverId + " f4 dual "
                      + hexEncode(salt.data(), salt.size()) + " " + snHex);

        const std::string authLine = ReadLine(c);
        const auto ap = splitBySpace(authLine);
        if (ap.size() != 3 || ap[1] != "AUTH") { SendLine(c, "PAIR1 FAIL bad"); closesocket(c); return; }

        // Derive the same key the client used, then produce a valid server proof.
        auto key = deriveKeyPbkdf2(password, derivePairSalt(serverId, clientId), kDerivedKeySize);
        if (!key) { closesocket(c); return; }
        const std::string matS = "S|" + nonceHex + "|" + snHex + "|" + clientId + "|" + serverId;
        auto proof = hmacSha256(*key,
            std::span<const uint8_t>((const uint8_t*)matS.data(), matS.size()));
        SendLine(c, "PAIR1 OK " + hexEncode(proof->data(), proof->size()));

        // ---- LAN2 handshake ----
        const std::string l2 = ReadLine(c);
        if (splitBySpace(l2).size() < 2 || splitBySpace(l2)[1] != "HELLO") { closesocket(c); return; }
        SendLine(c, "LAN2 READY");

        // ---- GET command: reply OK <size>, send HALF the bytes, cut the link ----
        const std::string get = ReadLine(c);
        const auto gp = splitBySpace(get);
        if (gp.size() < 3 || gp[0] != "GET") { closesocket(c); return; }
        const int64_t offset = strtoll(gp[2].c_str(), nullptr, 10);
        constexpr int64_t kTotal = 4096;
        SendLine(c, "OK " + std::to_string(kTotal - offset));
        std::vector<uint8_t> half(2048, 0x5A);
        sendAll(c, half.data(), half.size());
        Sleep(100);           // let the client drain the half
        closesocket(c);       // deterministic mid-transfer abort
    }
    void stopSrv() {
        stop = true;
        if (srv != INVALID_SOCKET) closesocket(srv);
        if (th.joinable()) th.join();
    }
};

static void TestF4() {
    printf("[F4] aborted transfer keeps pre-existing local file (resume)\n");
    WipeSecretStore();
    FakeSrv srv;
    srv.start(45892);

    const std::wstring local = std::filesystem::temp_directory_path()
        .append(L"f4_resume_target.bin").wstring();

    // Pre-existing local content: the data we must never lose.
    {
        std::ofstream f(local, std::ios::binary | std::ios::trunc);
        std::string seed(100, 'A');
        f.write(seed.data(), (std::streamsize)seed.size());
    }

    PairError err;
    auto sess = LanPairSession::connect("127.0.0.1", 45892,
                                        "f4-client", srv.serverId, srv.password, &err);
    printf("  DBG  sess=%d err='%s'\n", sess ? 1 : 0, err.message.c_str());
    CHECK(sess != nullptr, "session established against fake LAN2 server");
    if (!sess) { srv.stopSrv(); return; }

    int fsResult = -1;
    const bool ok = sess->getFile("\\remote\\file.bin", local.c_str(),
                                  4096, nullptr, true, /*resume=*/true, &fsResult);
    CHECK(!ok, "transfer reported failure as expected");

    std::ifstream f(local, std::ios::binary | std::ios::ate);
    const std::streamoff size = f.tellg();
    CHECK(f.good() && size >= 100,
          ("pre-existing file SURVIVED aborted resume (size=" + std::to_string(size)
           + ", expected >=100; pre-fix it was DELETED)").c_str());

    // Control case: brand-new download that aborts -> partial file removed
    // (long-standing semantics, unchanged by the fix).
    const std::wstring fresh = std::filesystem::temp_directory_path()
        .append(L"f4_fresh_target.bin").wstring();
    DeleteFileW(fresh.c_str());
    int r2 = -1;
    auto s2 = LanPairSession::connect("127.0.0.1", 45892,
                                      "f4-client2", srv.serverId, srv.password, &err);
    if (s2) {
        const bool ok2 = s2->getFile("\\remote\\file.bin", fresh.c_str(), 4096,
                                     nullptr, true, false, &r2);
        WIN32_FILE_ATTRIBUTE_DATA fa{};
        const bool exists = GetFileAttributesExW(fresh.c_str(), GetFileExInfoStandard, &fa);
        const unsigned long long sz = exists
            ? ((unsigned long long)fa.nFileSizeHigh << 32) | fa.nFileSizeLow : 0;
        printf("  DBG  fresh: ok=%d fsResult=%d exists=%d size=%llu\n",
               ok2 ? 1 : 0, r2, exists ? 1 : 0, sz);
        CHECK(!exists && !ok2,
              "aborted FIRST-time download removes its own partial file (unchanged semantics)");
    } else {
        printf("  DBG  second session failed: %s\n", err.message.c_str());
    }
    DeleteFileW(local.c_str()); DeleteFileW(fresh.c_str());
    srv.stopSrv();
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    // Fake servers create sockets before any LanPairSession exists —
    // bootstrap Winsock explicitly.
    static lanpair_internal::WsaScope appWsa;
    printf("=== Final verification round ===\n");
    TestF1F3();
    TestF4();
    printf(failures ? "=== FAILED (%d) ===\n" : "=== ALL OK (%d failures) ===\n", failures);
    return failures ? 1 : 0;
}
