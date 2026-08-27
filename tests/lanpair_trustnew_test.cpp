// lanpair_trustnew_test.cpp — models the CONTROL FLOW of the LAN-pair trust
// protocol AFTER the fix:
//   * PairServer  : src/core/LanPair.cpp (no-password/no-trust -> clean
//                   "trust-required"; password path -> AUTH only)
//   * SessionSrv  : src/core/LanPairSession.cpp:959-994 (TRUSTNEW with a
//                   password proof re-issues the trust token -> OKTRUST)
//   * SessionCli  : src/core/LanPairSession.cpp forceNew path (NOW actually
//                   sends "PAIR1 TRUSTNEW <pbkdf2proof>" instead of failing
//                   locally with "trust-password-required")
// Crypto is mocked; what matters is the branch conditions.
#include <cstdio>
#include <string>
#include <vector>

// ---- PairServer (LanPair.cpp), fixed control flow ----
static std::string PairServer(bool passwordSet, bool haveTrustStored,
                              const std::vector<std::string>& auth,
                              bool proofMatchesPbkdf2)
{
    if (passwordSet) {
        // path A
        if ((int)auth.size() != 3 || auth[0] != "PAIR1" || auth[1] != "AUTH")
            return "";                       // silent return false
        return proofMatchesPbkdf2 ? "PAIR1 OK <srvproof>" : "PAIR1 FAIL bad-auth";
    }
    if (haveTrustStored) {
        // B1
        if ((int)auth.size() != 3 || auth[0] != "PAIR1" || auth[1] != "AUTH")
            return "";
        return proofMatchesPbkdf2 ? "PAIR1 OK <srvproof>" : "PAIR1 FAIL bad-trust";
    }
    // B2, fixed: clean rejection, no dead code
    return "PAIR1 FAIL trust-required";
}

// ---- LanPairSession server (LanPairSession.cpp:959-994), unchanged ----
static std::string SessionServer(bool pwSet, bool trustStored,
                                 const std::vector<std::string>& auth,
                                 bool proofMatchesPbkdf2)
{
    if (pwSet) {
        if ((int)auth.size() != 3 || auth[0] != "PAIR1")
            return "";
        if (auth[1] == "TRUSTNEW" && proofMatchesPbkdf2)
            return "PAIR1 OKTRUST <srvproof> <newtrusthex>";
        if (auth[1] == "AUTH" && proofMatchesPbkdf2)
            return "PAIR1 OK <srvproof>";
        return "PAIR1 FAIL bad-auth";
    }
    if (trustStored) {
        if (auth[1] == "TRUSTNEW") return "PAIR1 FAIL trust-unknown";
        if (auth[1] == "AUTH")
            return proofMatchesPbkdf2 ? "PAIR1 OK <srvproof>" : "PAIR1 FAIL bad-trust";
        return "";
    }
    if (auth[1] == "TRUSTNEW") return "PAIR1 FAIL trust-required";
    if (auth[1] == "AUTH")     return "PAIR1 FAIL bad-auth";
    return "";
}

// ---- LanPairSession client, fixed control flow ----
static std::string SessionClient(bool forceNew, bool pwSet, bool haveTrustStored)
{
    if (!forceNew) {
        if (pwSet)            return "send 'PAIR1 AUTH <pbkdf2proof>'";
        if (haveTrustStored)  return "send 'PAIR1 AUTH <trustproof>'";
        return "LOCAL FAIL 'trust-password-required' (sends NOTHING)";
    }
    // forceNew: the server rejected our stored trust key (trust-unknown)
    if (pwSet) return "send 'PAIR1 TRUSTNEW <pbkdf2proof>'";   // FIXED
    return "LOCAL FAIL 'trust-password-required' (sends NOTHING)";
}

static int failures = 0;
#define CHECK(cond, msg) do { \
    bool _ok = (cond); \
    printf("  [%s] %s\n", _ok ? "OK " : "BUG", msg); \
    if (!_ok) ++failures; \
} while (0)

int main() {
    printf("=== 1. PairServer: no password, no stored trust (first pairing) ===\n");
    {
        std::string r = PairServer(false, false, {"PAIR1", "TRUSTNEW", "<proof>"}, true);
        printf("  server reply: %s\n", r.c_str());
        CHECK(r.find("trust-required") != std::string::npos,
              "clean 'trust-required' (no dead code path)");
    }
    printf("=== 2. PairServer: password set (first pairing, normal path) ===\n");
    {
        std::string r = PairServer(true, false, {"PAIR1", "AUTH", "<validpbkdf2>"}, true);
        printf("  server reply: %s\n", r.c_str());
        CHECK(r.find("PAIR1 OK") != std::string::npos, "AUTH(pbkdf2) accepted");
    }
    printf("=== 3. PairServer: no password, stored trust (re-pairing) ===\n");
    {
        std::string r = PairServer(false, true, {"PAIR1", "AUTH", "<validtrust>"}, true);
        printf("  server reply: %s\n", r.c_str());
        CHECK(r.find("PAIR1 OK") != std::string::npos, "AUTH(trust) accepted");
    }
    printf("=== 4. Session client: forceNew (stale trust) + password -> FIXED ===\n");
    {
        std::string a = SessionClient(/*forceNew=*/true, /*pw=*/true, /*trust=*/true);
        printf("  client action: %s\n", a.c_str());
        CHECK(a.find("TRUSTNEW") != std::string::npos && a.find("LOCAL FAIL") == std::string::npos,
              "forceNew+password now sends TRUSTNEW (recovery path restored)");
    }
    printf("=== 5. Session client: no password, no trust -> clear local fail ===\n");
    {
        std::string a = SessionClient(false, false, false);
        printf("  client action: %s\n", a.c_str());
        CHECK(a.find("trust-password-required") != std::string::npos,
              "clear 'trust-password-required' (nothing ambiguous sent)");
    }
    printf("=== 6. Session client: forceNew WITHOUT password -> clear local fail ===\n");
    {
        std::string a = SessionClient(true, false, true);
        printf("  client action: %s\n", a.c_str());
        CHECK(a.find("LOCAL FAIL") != std::string::npos,
              "cannot prove a password -> local fail, no bare TRUSTNEW");
    }
    printf("=== 7. END-TO-END recovery: stale trust, both sides have password ===\n");
    {
        std::string a = SessionClient(true, true, true);
        std::string r = SessionServer(/*pw=*/true, /*trust=*/false,
                                      {"PAIR1", "TRUSTNEW", "<validpbkdf2>"}, true);
        printf("  client: %s\n", a.c_str());
        printf("  server: %s\n", r.c_str());
        bool ok = a.find("TRUSTNEW") != std::string::npos &&
                  r.find("OKTRUST") != std::string::npos;
        printf("  -> %s\n", ok ? "server re-issues trust token (OKTRUST)" : "BROKEN");
        CHECK(ok, "recovery handshake completes with a fresh trust token");
    }
    printf("=== 8. END-TO-END recovery: stale trust, server has NO password ===\n");
    {
        std::string r = SessionServer(false, false, {"PAIR1", "TRUSTNEW", "<proof>"}, true);
        printf("  server: %s\n", r.c_str());
        CHECK(r.find("trust-required") != std::string::npos,
              "passwordless server still rejects TRUSTNEW (no free trust)");
    }

    printf("\n%s\n", failures == 0 ? "ALL OK — fixed control flow behaves as intended" : "FAILED");
    return failures == 0 ? 0 : 1;
}
