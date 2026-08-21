// lanpair_vuln_test.cpp вЂ” reproduces the TRUSTNEW no-auth vulnerability
// against the REAL LanFileServer code, then validates the fix behavior.
//
// Build (see build command in artifacts): links LanPair.cpp + LanPairSession.cpp
// + TrustedInstallerToken.cpp + DllExceptionBarrier.cpp.
// Same WinSock guards as src/include/global.h вЂ” prevents winsock1-vs-winsock2
// redefinition when windows.h comes in via headers before winsock2.h.
#define WIN32_LEAN_AND_MEAN
#define _WINSOCKAPI_
#include "LanPair.h"
#include "LanPairSession.h"
#include <cstdio>
#include <string>
#include <thread>
#include <chrono>

using namespace lanpair;

#include <filesystem>

// Wipes the DPAPI secret store so each case starts without leftovers from
// previous runs (mirrors DpapiSecretStore location in LanPair.cpp).
static void WipeSecretStore() {
    char appData[MAX_PATH] = {};
    GetEnvironmentVariableA("APPDATA", appData, MAX_PATH);
    std::filesystem::path dir = std::filesystem::path(appData) / "GHISLER" / "sftpplug.secrets";
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (cond) printf("  OK   %s\n", msg); \
    else    { printf("  FAIL %s\n", msg); ++failures; } } while(0)

int main()
{
    PairError err;

    // ---- Case 1: server WITHOUT password, attacker sends bare TRUSTNEW ----
        WipeSecretStore();{
        LanFileServer server;
        if (!server.start(45899, &err)) { printf("server start failed\n"); return 1; }
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        PairClient client;
        PairClientConfig cfg;
        cfg.targetIp = "127.0.0.1";
        cfg.targetPort = 45899;
        cfg.peerId = "attacker-box";
        cfg.password = "";               // knows NO password

        PairSessionInfo info; PairError perr;
        const bool paired = client.connectAndAuthenticate(cfg, &info, &perr);
        printf("case1 no-password TRUSTNEW: paired=%d (%s)\n", paired ? 1 : 0,
               perr.message.c_str());
        CHECK(!paired, "attack rejected on passwordless server");
        server.stop();
    }

    // ---- Case 2: server WITH password, attacker has no password ----
        WipeSecretStore();{
        LanFileServer server;
        if (!server.start(45898, &err)) { printf("server start failed\n"); return 1; }
        server.setPassword("correct-horse-battery");
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        PairClient client;
        PairClientConfig cfg;
        cfg.targetIp = "127.0.0.1";
        cfg.targetPort = 45898;
        cfg.peerId = "attacker-box";
        cfg.password = "";

        PairSessionInfo info; PairError perr;
        const bool paired = client.connectAndAuthenticate(cfg, &info, &perr);
        printf("case2 wrong/no-password AUTH: paired=%d (%s)\n", paired ? 1 : 0,
               perr.message.c_str());
        CHECK(!paired, "attack rejected on password-protected server");
        server.stop();
    }

    // ---- Case 3: legit pairing with matching password must SUCCEED ----
        WipeSecretStore();{
        LanFileServer server;
        if (!server.start(45897, &err)) { printf("server start failed\n"); return 1; }
        server.setPassword("shared-secret-42");
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        PairClient client;
        PairClientConfig cfg;
        cfg.targetIp = "127.0.0.1";
        cfg.targetPort = 45897;
        cfg.peerId = "legit-client";
        cfg.password = "shared-secret-42";

        PairSessionInfo info; PairError perr;
        const bool paired = client.connectAndAuthenticate(cfg, &info, &perr);
        printf("case3 legit password pairing: paired=%d (%s)\n", paired ? 1 : 0,
               perr.message.c_str());
        CHECK(paired, "legit pairing with correct password works");
        server.stop();
    }

    printf(failures ? "FAILED failures=%d\n" : "ALL OK (failures=%d)\n", failures);
    return failures ? 1 : 0;
}
