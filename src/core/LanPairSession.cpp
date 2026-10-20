// ============================================================
// LanPairSession.cpp
// File-transfer session layer on top of the PAIR1 auth protocol.
// After PAIR1 the same TCP socket is kept open and a simple
// line-based command protocol (LAN3) is spoken on it.
// ============================================================

#include "LanPairSession.h"
#include "LanPair.h"
#include "LanPairInternal.h"
#include "LanPairAuth.h"
#include <set>
#include "DllExceptionBarrier.h"
#include "TrustedInstallerToken.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <fileapi.h>

#include <atomic>
#include <chrono>
#include <mutex>
#include <condition_variable>
#include <algorithm>
#include <thread>
#include <vector>
#include <string>
#include <sstream>
#include <span>
#include <array>
#include <cstdint>
#include <cstring>
#include <cctype>
#include <optional>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")

// fsplugin constants used for getFile / putFile return codes
#define FS_FILE_OK          0
#define FS_FILE_EXISTS      1
#define FS_FILE_NOTFOUND    2
#define FS_FILE_READERROR   3
#define FS_FILE_WRITEERROR  4
#define FS_FILE_USERABORT   5

namespace {

// Pull in all shared crypto / socket primitives.
using namespace lanpair_internal;

// ---- role helpers (local: use lanpair::PairRole with full qualifier) ----

std::string roleToString(lanpair::PairRole role) {
    switch (role) {
    case lanpair::PairRole::Donor:    return "donor";
    case lanpair::PairRole::Receiver: return "receiver";
    default:                      return "dual";
    }
}

lanpair::PairRole roleFromString(const std::string& s) {
    if (s == "donor")    return lanpair::PairRole::Donor;
    if (s == "receiver") return lanpair::PairRole::Receiver;
    return lanpair::PairRole::Dual;
}

// ---- socket helpers only needed here ----

bool recvAll(SOCKET s, uint8_t* buf, size_t len) {
    return receiveBytes(s, buf, len);
}

// ---- base64 ----

static constexpr char kB64Table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string b64Encode(const uint8_t* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    size_t i = 0;
    for (; i + 2 < len; i += 3) {
        uint32_t v = (static_cast<uint32_t>(data[i])     << 16)
                   | (static_cast<uint32_t>(data[i + 1]) <<  8)
                   |  static_cast<uint32_t>(data[i + 2]);
        out.push_back(kB64Table[(v >> 18) & 0x3F]);
        out.push_back(kB64Table[(v >> 12) & 0x3F]);
        out.push_back(kB64Table[(v >>  6) & 0x3F]);
        out.push_back(kB64Table[ v        & 0x3F]);
    }
    if (i + 1 == len) {
        uint32_t v = static_cast<uint32_t>(data[i]) << 16;
        out.push_back(kB64Table[(v >> 18) & 0x3F]);
        out.push_back(kB64Table[(v >> 12) & 0x3F]);
        out.push_back('='); out.push_back('=');
    } else if (i + 2 == len) {
        uint32_t v = (static_cast<uint32_t>(data[i])     << 16)
                   | (static_cast<uint32_t>(data[i + 1]) <<  8);
        out.push_back(kB64Table[(v >> 18) & 0x3F]);
        out.push_back(kB64Table[(v >> 12) & 0x3F]);
        out.push_back(kB64Table[(v >>  6) & 0x3F]);
        out.push_back('=');
    }
    return out;
}

std::string b64EncodeStr(const std::string& s) {
    return b64Encode(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

std::optional<std::vector<uint8_t>> b64Decode(std::string_view in) {
    static const uint8_t* kInv = []() -> const uint8_t* {
        static uint8_t t[256];
        for (int i = 0; i < 256; ++i) t[i] = 0xFF;
        for (int i = 0; i < 64; ++i)
            t[static_cast<unsigned char>(kB64Table[i])] = static_cast<uint8_t>(i);
        t[static_cast<unsigned char>('=')] = 0;
        return t;
    }();

    std::string stripped;
    stripped.reserve(in.size());
    for (char c : in)
        if (c != '\r' && c != '\n' && c != ' ') stripped.push_back(c);

    if (stripped.size() % 4 != 0) return std::nullopt;

    std::vector<uint8_t> out;
    out.reserve(stripped.size() / 4 * 3);
    for (size_t i = 0; i < stripped.size(); i += 4) {
        uint8_t a = kInv[static_cast<unsigned char>(stripped[i])];
        uint8_t b = kInv[static_cast<unsigned char>(stripped[i+1])];
        uint8_t c = kInv[static_cast<unsigned char>(stripped[i+2])];
        uint8_t d = kInv[static_cast<unsigned char>(stripped[i+3])];
        if (a == 0xFF || b == 0xFF || c == 0xFF || d == 0xFF) return std::nullopt;
        out.push_back(static_cast<uint8_t>((a << 2) | (b >> 4)));
        if (stripped[i+2] != '=') out.push_back(static_cast<uint8_t>((b << 4) | (c >> 2)));
        if (stripped[i+3] != '=') out.push_back(static_cast<uint8_t>((c << 6) |  d));
    }
    return out;
}

std::string b64DecodeStr(const std::string& in) {
    auto v = b64Decode(in);
    if (!v) return {};
    return std::string(v->begin(), v->end());
}

// ---- Wide <-> UTF-8 helpers ----

std::string wideToUtf8(LPCWSTR wide) {
    if (!wide || !*wide) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, wide, -1,
                                      nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string out(static_cast<size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, out.data(), n, nullptr, nullptr);
    return out;
}

std::wstring utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0,
                                      utf8.data(), static_cast<int>(utf8.size()),
                                      nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0,
                        utf8.data(), static_cast<int>(utf8.size()),
                        out.data(), n);
    return out;
}

// ---- PAIR1 client-side auth ----
// Returns an open, authenticated socket plus the shared key on success.
// On failure, sock == INVALID_SOCKET.

struct AuthResult {
    SOCKET               sock = INVALID_SOCKET;
    std::vector<uint8_t> key;
};

AuthResult pair1Connect(
    const std::string& targetIp,
    uint16_t           targetPort,
    const std::string& localPeerId,
    const std::string& remotePeerId,
    const std::string& password,
    lanpair::PairError* err,
    bool               forceNew = false,
    lanpair::PairRole  localRole = lanpair::PairRole::Dual) noexcept
{
    AuthResult result;

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        if (err) { err->code = WSAGetLastError(); err->message = "Cannot create socket"; }
        return result;
    }

    setSocketTimeout(s, 8000);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(targetPort);
    if (inet_pton(AF_INET, targetIp.c_str(), &addr.sin_addr) != 1) {
        closeSocket(s);
        if (err) { err->code = ERROR_INVALID_ADDRESS; err->message = "Invalid target IP"; }
        return result;
    }

    if (connect(s, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
        const int code = WSAGetLastError();
        closeSocket(s);
        if (err) { err->code = code; err->message = "connect() failed"; }
        return result;
    }

    const BOOL keepAlive = TRUE;
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE,
               reinterpret_cast<const char*>(&keepAlive), sizeof(keepAlive));

    if (!authenticatePeerClient(s, localPeerId, remotePeerId, password, localRole, nullptr)) {
        closeSocket(s);
        if (err) { err->code = ERROR_ACCESS_DENIED; err->message = "LAN3 authentication failed; update both peers and pair again."; }
        return result;
    }
    result.sock = s;
    return result;
}

// ---- LAN3 command helpers ----

bool lan2SendCmd(SOCKET s, const std::string& cmd) {
    return sendLine(s, cmd);
}

std::vector<std::string> lan2ReadResponse(SOCKET s) {
    std::string line;
    if (!recvLine(s, &line)) return {};
    return splitBySpace(line);
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// PrepareLanPairTrustKeys вЂ” public API, outside anonymous namespace
// ---------------------------------------------------------------------------
bool PrepareLanPairTrustKeys(const std::string&, const std::string&, const std::string&) noexcept
{
    // Trust is persisted only after a successful, challenge-bound handshake.
    return true;
}

// ============================================================
// LanPairSession::Impl
// ============================================================

struct LanPairSession::Impl {
    lanpair_internal::WsaScope wsa;
    SOCKET   sock_       = INVALID_SOCKET;
    bool     connected_  = false;
    int      timeoutMin_ = 0;
    std::chrono::steady_clock::time_point sessionStart_ = std::chrono::steady_clock::now();
    bool     trustedInstaller_ = false;

    bool isTimedOut() const noexcept {
        if (timeoutMin_ <= 0) return false;
        return std::chrono::steady_clock::now() - sessionStart_
               >= std::chrono::minutes(timeoutMin_);
    }

    void close() noexcept {
        if (sock_ != INVALID_SOCKET) {
            shutdown(sock_, SD_BOTH);
            closeSocket(sock_);
            sock_ = INVALID_SOCKET;
        }
        connected_ = false;
    }

    // Send a command line and return the response tokens.
    // Returns empty vector on I/O failure or session timeout.
    std::vector<std::string> cmd(const std::string& line) noexcept {
        if (isTimedOut()) { close(); return {}; }
        if (!sendLine(sock_, line)) { close(); return {}; }
        std::string resp;
        if (!recvLine(sock_, &resp)) { close(); return {}; }
        return splitBySpace(resp);
    }
};

// ============================================================
// LanPairSession public API
// ============================================================

LanPairSession::LanPairSession(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl)) {}

LanPairSession::~LanPairSession() {
    disconnect();
}

/*static*/
std::unique_ptr<LanPairSession> LanPairSession::connect(
    const std::string& targetIp,
    uint16_t           targetPort,
    const std::string& localPeerId,
    const std::string& remotePeerId,
    const std::string& password,
    lanpair::PairError* err,
    lanpair::PairRole  localRole) noexcept
{
    auto impl = std::make_unique<Impl>();
    if (!impl->wsa.ok()) {
        if (err) { err->code = WSAGetLastError(); err->message = "WSAStartup failed"; }
        return nullptr;
    }

    SFTP_LOG("LAN3", "connect() -> pair1Connect %s:%u local=%s remote=%s",
             targetIp.c_str(), targetPort, localPeerId.c_str(), remotePeerId.c_str());
    AuthResult ar = pair1Connect(targetIp, targetPort,
                                 localPeerId, remotePeerId, password, err,
                                 false, localRole);
    if (ar.sock == INVALID_SOCKET) {
        const bool trustUnknown = err && err->message.find("trust-unknown") != std::string::npos;
        if (trustUnknown) {
            // Server couldn't verify our stored key (e.g. DPAPI context mismatch after
            // enabling TrustedInstaller).  Delete the stale client-side key and retry
            // with TRUSTNEW so the peer issues a fresh shared secret.
            SFTP_LOG("LAN3", "trust-unknown: deleting stale client key, retrying with TRUSTNEW");
            lanpair::DpapiSecretStore::deleteSecret(
                trustKeyForClient(remotePeerId, localPeerId), nullptr);
            lanpair::PairError retryErr;
            ar = pair1Connect(targetIp, targetPort,
                              localPeerId, remotePeerId, password, &retryErr,
                              true, localRole);
            if (ar.sock != INVALID_SOCKET) {
                if (err) { err->code = 0; err->message.clear(); }
            } else {
                if (err) *err = retryErr;
            }
        }
        if (ar.sock == INVALID_SOCKET) {
            SFTP_LOG("LAN3", "pair1Connect FAILED: %s", err ? err->message.c_str() : "?");
            return nullptr;
        }
    }
    SFTP_LOG("LAN3", "pair1Connect OK, sending LAN3 HELLO");

    if (!sendLine(ar.sock, "LAN3 HELLO")) {
        closeSocket(ar.sock);
        if (err) { err->code = WSAGetLastError(); err->message = "Cannot send LAN3 HELLO"; }
        return nullptr;
    }
    std::string ready;
    if (!recvLine(ar.sock, &ready) || splitBySpace(ready).size() < 2
        || splitBySpace(ready)[0] != "LAN3" || splitBySpace(ready)[1] != "READY") {
        SFTP_LOG("LAN3", "No LAN3 READY, got: %s", ready.c_str());
        closeSocket(ar.sock);
        if (err) { err->code = ERROR_INVALID_DATA; err->message = "No LAN3 READY response"; }
        return nullptr;
    }

    SFTP_LOG("LAN3", "LAN3 session established OK");
    impl->sock_      = ar.sock;
    impl->connected_ = true;
    return std::unique_ptr<LanPairSession>(new LanPairSession(std::move(impl)));
}

bool LanPairSession::isConnected() const noexcept {
    return impl_ && impl_->connected_;
}

void LanPairSession::disconnect() noexcept {
    if (impl_) impl_->close();
}

void LanPairSession::setTimeoutMin(int minutes) noexcept {
    if (impl_) impl_->timeoutMin_ = minutes;
}

void LanPairSession::setTrustedInstaller(bool enabled) noexcept {
    if (impl_) impl_->trustedInstaller_ = enabled;
}

bool LanPairSession::listRoots(std::vector<std::string>& roots) noexcept {
    if (!isConnected()) return false;
    roots.clear();

    SFTP_LOG("LAN3", "listRoots: sending ROOTS");
    const auto resp = impl_->cmd("ROOTS");
    SFTP_LOG("LAN3", "listRoots: resp[0]=%s count=%s",
             resp.empty() ? "(empty)" : resp[0].c_str(),
             resp.size() >= 2 ? resp[1].c_str() : "?");
    if (resp.empty() || resp[0] != "OK" || resp.size() < 2) return false;

    char* end = nullptr;
    const long count = strtol(resp[1].c_str(), &end, 10);
    if (!end || *end || count < 0 || count > 100000) { impl_->close(); return false; }
    for (int i = 0; i < count; ++i) {
        std::string line;
        if (!recvLine(impl_->sock_, &line)) { impl_->close(); return false; }
        roots.push_back(std::move(line));
    }
    return true;
}

bool LanPairSession::listDirectory(const std::string&     path,
                                   std::vector<DirEntry>& entries) noexcept
{
    if (!isConnected()) return false;
    entries.clear();

    const std::string cmd = "LIST " + b64EncodeStr(path);
    SFTP_LOG("LAN3", "listDirectory: path=%s", path.c_str());
    const auto resp = impl_->cmd(cmd);
    SFTP_LOG("LAN3", "listDirectory: resp[0]=%s count=%s",
             resp.empty() ? "(empty)" : resp[0].c_str(),
             resp.size() >= 2 ? resp[1].c_str() : "?");
    if (resp.empty() || resp[0] != "OK" || resp.size() < 2) return false;

    char* end = nullptr;
    const long count = strtol(resp[1].c_str(), &end, 10);
    if (!end || *end || count < 0 || count > 100000) { impl_->close(); return false; }
    for (int i = 0; i < count; ++i) {
        std::string line;
        if (!recvLine(impl_->sock_, &line)) { impl_->close(); return false; }
        // Format: <F|D> <size> <mtime_uint64> <attrs_hex> <b64_name>
        const auto parts = splitBySpace(line);
        if (parts.size() < 5) continue;

        DirEntry e;
        e.isDir    = (parts[0] == "D");
        e.size     = static_cast<int64_t>(std::strtoll(parts[1].c_str(), nullptr, 10));
        const uint64_t ft64 = std::strtoull(parts[2].c_str(), nullptr, 10);
        e.lastWrite.dwLowDateTime  = static_cast<DWORD>(ft64 & 0xFFFFFFFFu);
        e.lastWrite.dwHighDateTime = static_cast<DWORD>(ft64 >> 32);
        e.winAttrs = static_cast<DWORD>(std::strtoul(parts[3].c_str(), nullptr, 16));
        e.name     = b64DecodeStr(parts[4]);
        entries.push_back(std::move(e));
    }
    return true;
}

bool LanPairSession::getFile(const std::string& remotePath,
                             LPCWSTR            localPath,
                             int64_t            /*remoteSize*/,
                             const FILETIME*    ft,
                             bool               overwrite,
                             bool               resume,
                             int*               fsResult) noexcept
{
    if (fsResult) *fsResult = FS_FILE_READERROR;
    if (!isConnected()) return false;

    const bool tiAcquired = (impl_ && impl_->trustedInstaller_) && AcquireTrustedInstallerToken();
    struct TiScope { bool a; ~TiScope() { if (a) ReleaseTrustedInstallerToken(); } } tiScope{tiAcquired};

    int64_t offset = 0;
    if (resume) {
        HANDLE hExist = CreateFileW(localPath, GENERIC_READ, FILE_SHARE_READ,
                                    nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (hExist != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER sz{};
            if (GetFileSizeEx(hExist, &sz)) offset = sz.QuadPart;
            CloseHandle(hExist);
        }
    }

    std::ostringstream req;
    req << "GET " << b64EncodeStr(remotePath) << " " << offset;
    const auto resp = impl_->cmd(req.str());
    if (resp.empty() || resp[0] != "OK" || resp.size() < 2) {
        if (fsResult) *fsResult = FS_FILE_READERROR;
        return false;
    }

    char* sizeEnd = nullptr;
    errno = 0;
    const int64_t dataSize = std::strtoll(resp[1].c_str(), &sizeEnd, 10);
    if (errno == ERANGE || !sizeEnd || sizeEnd == resp[1].c_str() || *sizeEnd || dataSize < 0) {
        impl_->close();
        return false;
    }

    const DWORD createDisp = resume ? OPEN_ALWAYS : (overwrite ? CREATE_ALWAYS : CREATE_NEW);
    // Remember whether the local file existed before we opened it, so a failed
    // transfer never deletes pre-existing user data (e.g. a resumed download).
    const bool existedBefore =
        GetFileAttributesW(localPath) != INVALID_FILE_ATTRIBUTES;
    HANDLE hLocal = CreateFileW(localPath, GENERIC_WRITE, 0, nullptr,
                                createDisp, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (hLocal == INVALID_HANDLE_VALUE) {
        if (fsResult) *fsResult =
            (GetLastError() == ERROR_FILE_EXISTS) ? FS_FILE_EXISTS : FS_FILE_WRITEERROR;
        impl_->close();
        return false;
    }

    if (resume && offset > 0) {
        LARGE_INTEGER li{}; li.QuadPart = offset;
        if (!SetFilePointerEx(hLocal, li, nullptr, FILE_BEGIN)) {
            CloseHandle(hLocal);
            impl_->close();
            if (fsResult) *fsResult = FS_FILE_WRITEERROR;
            return false;
        }
    }

    constexpr size_t kChunk = 65536;
    std::vector<uint8_t> buf(kChunk);
    int64_t remaining = dataSize;
    bool ok = true;

    while (remaining > 0) {
        const size_t want = static_cast<size_t>(
            std::min<int64_t>(remaining, static_cast<int64_t>(kChunk)));
        if (!recvAll(impl_->sock_, buf.data(), want)) {
            ok = false;
            if (fsResult) *fsResult = FS_FILE_READERROR;
            break;
        }
        DWORD written = 0;
        if (!WriteFile(hLocal, buf.data(), static_cast<DWORD>(want), &written, nullptr)
            || written != static_cast<DWORD>(want)) {
            ok = false;
            if (fsResult) *fsResult = FS_FILE_WRITEERROR;
            break;
        }
        remaining -= static_cast<int64_t>(want);
    }

    if (ok && ft) SetFileTime(hLocal, nullptr, nullptr, ft);
    CloseHandle(hLocal);

    if (!ok) {
        impl_->close();
        // Remove only the partial file we created ourselves; never delete
        // a file that already existed before this transfer started.
        if (!existedBefore)
            DeleteFileW(localPath);
        return false;
    }

    if (fsResult) *fsResult = FS_FILE_OK;
    return true;
}

bool LanPairSession::putFile(LPCWSTR            localPath,
                             const std::string& remotePath,
                             bool               /*overwrite*/,
                             bool               /*resume*/,
                             int*               fsResult) noexcept
{
    if (fsResult) *fsResult = FS_FILE_READERROR;
    if (!isConnected()) return false;

    const bool tiAcquired = (impl_ && impl_->trustedInstaller_) && AcquireTrustedInstallerToken();
    struct TiScope { bool a; ~TiScope() { if (a) ReleaseTrustedInstallerToken(); } } tiScope{tiAcquired};

    HANDLE hLocal = CreateFileW(localPath, GENERIC_READ, FILE_SHARE_READ,
                                nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (hLocal == INVALID_HANDLE_VALUE) {
        if (fsResult) *fsResult = FS_FILE_NOTFOUND;
        return false;
    }

    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(hLocal, &sz)) {
        CloseHandle(hLocal);
        if (fsResult) *fsResult = FS_FILE_READERROR;
        return false;
    }
    const int64_t fileSize = sz.QuadPart;

    std::ostringstream req;
    req << "PUT " << b64EncodeStr(remotePath) << " " << fileSize;
    const auto resp = impl_->cmd(req.str());
    if (resp.empty() || resp[0] != "OK") {
        CloseHandle(hLocal);
        if (fsResult) *fsResult = FS_FILE_WRITEERROR;
        return false;
    }

    constexpr size_t kChunk = 65536;
    std::vector<uint8_t> buf(kChunk);
    int64_t remaining = fileSize;
    bool ok = true;

    while (remaining > 0) {
        const DWORD want = static_cast<DWORD>(
            std::min<int64_t>(remaining, static_cast<int64_t>(kChunk)));
        DWORD bytesRead = 0;
        if (!ReadFile(hLocal, buf.data(), want, &bytesRead, nullptr) || bytesRead == 0) {
            ok = false;
            if (fsResult) *fsResult = FS_FILE_READERROR;
            break;
        }
        if (!sendAll(impl_->sock_, buf.data(), bytesRead)) {
            ok = false;
            if (fsResult) *fsResult = FS_FILE_WRITEERROR;
            break;
        }
        remaining -= static_cast<int64_t>(bytesRead);
    }
    CloseHandle(hLocal);

    if (!ok) { impl_->close(); return false; }

    std::string doneResp;
    const bool receivedDone = recvLine(impl_->sock_, &doneResp);
    const auto doneFields = splitBySpace(doneResp);
    if (!receivedDone || doneFields.empty() || doneFields[0] != "DONE") {
        impl_->close();
        if (fsResult) *fsResult = FS_FILE_WRITEERROR;
        return false;
    }

    if (fsResult) *fsResult = FS_FILE_OK;
    return true;
}

bool LanPairSession::mkdir(const std::string& path) noexcept {
    if (!isConnected()) return false;
    const auto resp = impl_->cmd("MKDIR " + b64EncodeStr(path));
    return !resp.empty() && resp[0] == "OK";
}

bool LanPairSession::remove(const std::string& path) noexcept {
    if (!isConnected()) return false;
    const auto resp = impl_->cmd("DEL " + b64EncodeStr(path));
    return !resp.empty() && resp[0] == "OK";
}

bool LanPairSession::rename(const std::string& oldPath,
                            const std::string& newPath) noexcept {
    if (!isConnected()) return false;
    const std::string line = "REN " + b64EncodeStr(oldPath)
                           + " "   + b64EncodeStr(newPath);
    const auto resp = impl_->cmd(line);
    return !resp.empty() && resp[0] == "OK";
}

// ============================================================
// LanFileServer::Impl - server-side command loop
// ============================================================

struct LanFileServer::Impl : public std::enable_shared_from_this<Impl> {
    lanpair_internal::WsaScope wsa;
    std::atomic<bool>   running_{false};
    SOCKET              listenSock_ = INVALID_SOCKET;
    std::thread         acceptThread_;
    std::string         serverPeerId_;
    uint16_t            port_         = 45846;
    mutable std::mutex  passwordMu_;
    std::string         password_;
    std::atomic<bool>   trustedInstaller_{false};

    struct ClientWorker {
        std::thread                        thread;
        std::shared_ptr<std::atomic<bool>> done;
    };

    std::mutex                clientThreadsMu_;
    std::condition_variable   clientThreadsCv_;
    std::vector<ClientWorker> clientThreads_;
    std::thread               clientReaperThread_;
    bool                      clientReaperStop_ = false;
    std::set<SOCKET> activeClients_;
    std::vector<std::wstring> allowedRoots_;

    static constexpr char kDefaultPeerId[] = "lanfilesrv";

    void closeListen() {
        running_ = false;
        if (listenSock_ != INVALID_SOCKET) {
            shutdown(listenSock_, SD_BOTH);
            closeSocket(listenSock_);
            listenSock_ = INVALID_SOCKET;
        }
    }

    bool authenticateClient(SOCKET s, std::string& clientPeerId) {
        std::string password;
        { std::lock_guard<std::mutex> lock(passwordMu_); password = password_; }
        lanpair::PairSessionInfo info;
        const bool ok = authenticatePeerServer(s, serverPeerId_, password, &info);
        SecureZeroMemory(password.data(), password.size());
        clientPeerId = info.remotePeerId;
        return ok;
    }

    void serveCommands(SOCKET s) {
        std::string line;
        while (recvLine(s, &line)) {
            const auto parts = splitBySpace(line);
            if (parts.empty()) continue;

            const std::string& cmd = parts[0];

            if (cmd == "QUIT") {
                sendLine(s, "BYE");
                break;
            } else if (cmd == "ROOTS") {
                cmdRoots(s);
            } else if (cmd == "LIST" && parts.size() >= 2) {
                cmdList(s, b64DecodeStr(parts[1]));
            } else if (cmd == "GET" && parts.size() >= 3) {
                const int64_t offset = static_cast<int64_t>(
                    std::strtoll(parts[2].c_str(), nullptr, 10));
                cmdGet(s, b64DecodeStr(parts[1]), offset);
            } else if (cmd == "PUT" && parts.size() >= 3) {
                const int64_t size = static_cast<int64_t>(
                    std::strtoll(parts[2].c_str(), nullptr, 10));
                cmdPut(s, b64DecodeStr(parts[1]), size);
            } else if (cmd == "MKDIR" && parts.size() >= 2) {
                cmdMkdir(s, b64DecodeStr(parts[1]));
            } else if (cmd == "DEL" && parts.size() >= 2) {
                cmdDel(s, b64DecodeStr(parts[1]));
            } else if (cmd == "REN" && parts.size() >= 3) {
                cmdRen(s, b64DecodeStr(parts[1]), b64DecodeStr(parts[2]));
            } else {
                sendLine(s, "ERR unknown-command");
            }
        }
    }

    // Reject device/UNC paths, alternate streams, traversal, and reparse points.
    // Missing final components are permitted only below a verified ancestor.
    std::wstring allowedPath(const std::string& path) const {
        if (path.find('\0') != std::string::npos) return {};
        std::wstring p = utf8ToWide(path);
        std::replace(p.begin(), p.end(), L'/', L'\\');
        while (!p.empty() && p.front() == L'\\') p.erase(0, 1);
        if (p.size() < 3 || p[1] != L':' || p[2] != L'\\' ||
            p.find(L':', 2) != std::wstring::npos) return {};
        for (size_t i = 3; i < p.size();) {
            const size_t end = p.find(L'\\', i);
            const auto component = p.substr(i, end == p.npos ? p.size() - i : end - i);
            if (component.empty() || component == L"." || component == L".." ||
                component.back() == L'.' || component.back() == L' ') return {};
            i = end == p.npos ? p.size() : end + 1;
        }
        std::array<wchar_t, 32768> full{};
        const DWORD n = GetFullPathNameW(p.c_str(), static_cast<DWORD>(full.size()), full.data(), nullptr);
        if (!n || n >= full.size()) return {};
        p.assign(full.data(), n);
        bool allowed = false;
        for (const auto& root : allowedRoots_) {
            if (p.size() >= root.size() && _wcsnicmp(p.c_str(), root.c_str(), root.size()) == 0 &&
                (p.size() == root.size() || root.back() == L'\\' || p[root.size()] == L'\\')) {
                allowed = true; break;
            }
        }
        if (!allowed) return {};
        for (size_t i = 3; i <= p.size(); ++i) {
            if (i != p.size() && p[i] != L'\\') continue;
            const auto part = p.substr(0, i);
            const DWORD attr = GetFileAttributesW(part.c_str());
            if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_REPARSE_POINT)) return {};
        }
        return p;
    }

    void cmdRoots(SOCKET s) {
        sendLine(s, "OK " + std::to_string(allowedRoots_.size()));
        for (const auto& root : allowedRoots_) sendLine(s, wideToUtf8(root.c_str()));
    }

    void cmdList(SOCKET s, const std::string& path) {
        const std::wstring wpath = allowedPath(path);
        if (wpath.empty()) { sendLine(s, "ERR path-not-allowed"); return; }
        std::wstring glob = wpath;
        if (!glob.empty() && glob.back() != L'\\') glob += L'\\';
        glob += L'*';

        WIN32_FIND_DATAW fd{};
        HANDLE h = FindFirstFileW(glob.c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) {
            sendLine(s, "ERR not-found");
            return;
        }

        std::vector<std::string> lines;
        do {
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
                continue;

            const bool    isDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            const int64_t size  = isDir ? 0 :
                (static_cast<int64_t>(fd.nFileSizeHigh) << 32) | fd.nFileSizeLow;
            const uint64_t ft64 =
                (static_cast<uint64_t>(fd.ftLastWriteTime.dwHighDateTime) << 32) |
                 fd.ftLastWriteTime.dwLowDateTime;

            char attrBuf[16]{};
            sprintf_s(attrBuf, sizeof(attrBuf), "%X", fd.dwFileAttributes);

            std::ostringstream entry;
            entry << (isDir ? "D" : "F") << " "
                  << size << " " << ft64 << " "
                  << attrBuf << " "
                  << b64EncodeStr(wideToUtf8(fd.cFileName));
            if (lines.size() >= 100000) { FindClose(h); sendLine(s, "ERR too-many-entries"); return; }
            lines.push_back(entry.str());
        } while (FindNextFileW(h, &fd));
        FindClose(h);

        std::ostringstream hdr;
        hdr << "OK " << lines.size();
        sendLine(s, hdr.str());
        for (const auto& l : lines) sendLine(s, l);
    }

    void cmdGet(SOCKET s, const std::string& path, int64_t offset) {
        if (offset < 0) { sendLine(s, "ERR bad-offset"); return; }
        const std::wstring wpath = allowedPath(path);
        if (wpath.empty()) { sendLine(s, "ERR path-not-allowed"); return; }
        HANDLE h = CreateFileW(wpath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (h == INVALID_HANDLE_VALUE) { sendLine(s, "ERR not-found"); return; }

        LARGE_INTEGER sz{};
        if (!GetFileSizeEx(h, &sz)) { CloseHandle(h); sendLine(s, "ERR stat-failed"); return; }

        if (offset > 0) {
            LARGE_INTEGER li{}; li.QuadPart = offset;
            if (!SetFilePointerEx(h, li, nullptr, FILE_BEGIN)) {
                CloseHandle(h); sendLine(s, "ERR seek-failed"); return;
            }
        }

        const int64_t dataSize = sz.QuadPart - offset;
        if (dataSize < 0) { CloseHandle(h); sendLine(s, "ERR bad-offset"); return; }

        std::ostringstream resp;
        resp << "OK " << dataSize;
        if (!sendLine(s, resp.str())) { CloseHandle(h); return; }

        constexpr size_t kChunk = 65536;
        std::vector<uint8_t> buf(kChunk);
        int64_t remaining = dataSize;
        while (remaining > 0) {
            const DWORD want = static_cast<DWORD>(
                std::min<int64_t>(remaining, static_cast<int64_t>(kChunk)));
            DWORD bytesRead = 0;
            if (!ReadFile(h, buf.data(), want, &bytesRead, nullptr) || bytesRead == 0) break;
            if (!sendAll(s, buf.data(), bytesRead)) break;
            remaining -= static_cast<int64_t>(bytesRead);
        }
        CloseHandle(h);
    }

    void cmdPut(SOCKET s, const std::string& path, int64_t size) {
        if (size < 0) { sendLine(s, "ERR bad-size"); return; }
        const std::wstring wpath = allowedPath(path);
        if (wpath.empty()) { sendLine(s, "ERR path-not-allowed"); return; }
        HANDLE h = CreateFileW(wpath.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            // Client sends data only AFTER receiving "OK", so nothing to drain here.
            sendLine(s, "ERR open-failed");
            return;
        }

        ULARGE_INTEGER available{};
        const auto separator = wpath.find_last_of(L'\\');
        if (separator == wpath.npos ||
            !GetDiskFreeSpaceExW(wpath.substr(0, separator + 1).c_str(), &available, nullptr, nullptr) ||
            static_cast<uint64_t>(size) > available.QuadPart) {
            CloseHandle(h); sendLine(s, "ERR insufficient-space"); return;
        }
        sendLine(s, "OK");

        constexpr size_t kChunk = 65536;
        std::vector<uint8_t> buf(kChunk);
        int64_t remaining = size;
        bool ok = true;
        while (remaining > 0) {
            const size_t want = static_cast<size_t>(
                std::min<int64_t>(remaining, static_cast<int64_t>(kChunk)));
            if (!recvAll(s, buf.data(), want)) { ok = false; break; }
            DWORD written = 0;
            if (!WriteFile(h, buf.data(), static_cast<DWORD>(want),
                           &written, nullptr) || written != static_cast<DWORD>(want)) {
                ok = false; break;
            }
            remaining -= static_cast<int64_t>(want);
        }
        CloseHandle(h);
        sendLine(s, ok ? "DONE" : "ERR write-failed");
    }

    void cmdMkdir(SOCKET s, const std::string& path) {
        const std::wstring wpath = allowedPath(path);
        if (wpath.empty()) { sendLine(s, "ERR path-not-allowed"); return; }
        sendLine(s, CreateDirectoryW(wpath.c_str(), nullptr) ? "OK" : "ERR mkdir-failed");
    }

    void cmdDel(SOCKET s, const std::string& path) {
        const std::wstring wpath = allowedPath(path);
        if (wpath.empty()) { sendLine(s, "ERR path-not-allowed"); return; }
        const DWORD attr = GetFileAttributesW(wpath.c_str());
        bool ok = false;
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY))
            ok = (RemoveDirectoryW(wpath.c_str()) != 0);
        else
            ok = (DeleteFileW(wpath.c_str()) != 0);
        sendLine(s, ok ? "OK" : "ERR delete-failed");
    }

    void cmdRen(SOCKET s, const std::string& oldPath,
                          const std::string& newPath) noexcept {
        const std::wstring wold = allowedPath(oldPath);
        const std::wstring wnew = allowedPath(newPath);
        if (wold.empty() || wnew.empty()) { sendLine(s, "ERR path-not-allowed"); return; }
        sendLine(s, MoveFileExW(wold.c_str(), wnew.c_str(), MOVEFILE_REPLACE_EXISTING)
                        ? "OK" : "ERR rename-failed");
    }

    void handleClient(SOCKET client) {
        u_long blocking = 0;
        ioctlsocket(client, FIONBIO, &blocking);
        const BOOL keepAlive = TRUE;
        setsockopt(client, SOL_SOCKET, SO_KEEPALIVE,
                   reinterpret_cast<const char*>(&keepAlive), sizeof(keepAlive));
        setSocketTimeout(client, 8000); // bounded authentication wait

        struct SocketScope {
            Impl* owner; SOCKET socket;
            ~SocketScope() {
                std::lock_guard<std::mutex> lock(owner->clientThreadsMu_);
                owner->activeClients_.erase(socket);
                closeSocket(socket);
            }
        } socketScope{this, client};
        std::string clientPeerId;
        if (!authenticateClient(client, clientPeerId)) {
            return;
        }

        setSocketTimeout(client, 300000);
        // Impersonate only AFTER the peer has authenticated successfully;
        // unauthenticated connections must never trigger TI token acquisition.
        const bool ti = trustedInstaller_.load(std::memory_order_relaxed) && AcquireTrustedInstallerToken();
        struct TiScope { bool active; ~TiScope() { if (active) ReleaseTrustedInstallerToken(); } } tiScope{ti};

        std::string helloLine;
        if (!recvLine(client, &helloLine)) { return; }
        const auto hp = splitBySpace(helloLine);
        if (hp.size() < 2 || hp[0] != "LAN3" || hp[1] != "HELLO") return;

        if (!sendLine(client, "LAN3 READY")) { return; }

        serveCommands(client);
    }

    void runAcceptLoop() {
        while (running_.load(std::memory_order_relaxed)) {
            fd_set ready; FD_ZERO(&ready); FD_SET(listenSock_, &ready);
            timeval wait{0, 100000};
            if (select(0, &ready, nullptr, nullptr, &wait) <= 0) continue;
            sockaddr_in from{};
            int fromLen = sizeof(from);
            SOCKET client = accept(listenSock_,
                                   reinterpret_cast<sockaddr*>(&from), &fromLen);
            if (client == INVALID_SOCKET) continue;

            auto self = shared_from_this();
            auto done = std::make_shared<std::atomic<bool>>(false);
            std::lock_guard<std::mutex> lk(clientThreadsMu_);
            if (!running_) { closeSocket(client); break; }
            resetSocketCancellation(client);
            activeClients_.insert(client);
            clientThreads_.push_back(ClientWorker{
                std::thread([self, client, done] {
                    {
                        sftp::DllExceptionBarrier barrier;
                        sftp::dll_invoke_void(barrier, [self, client] { self->handleClient(client); });
                    }
                    done->store(true, std::memory_order_release);
                    self->clientThreadsCv_.notify_one();
                }),
                std::move(done)
            });
        }
    }

    void runClientReaper() {
        for (;;) {
            std::vector<std::thread> completed;
            bool stopping = false;
            {
                std::unique_lock<std::mutex> lk(clientThreadsMu_);
                clientThreadsCv_.wait(lk, [this] {
                    return clientReaperStop_ ||
                           std::any_of(clientThreads_.begin(), clientThreads_.end(),
                               [](const ClientWorker& worker) {
                                   return worker.done->load(std::memory_order_acquire);
                               });
                });

                stopping = clientReaperStop_;
                for (auto it = clientThreads_.begin(); it != clientThreads_.end();) {
                    if (stopping || it->done->load(std::memory_order_acquire)) {
                        completed.push_back(std::move(it->thread));
                        it = clientThreads_.erase(it);
                    } else {
                        ++it;
                    }
                }
            }

            for (auto& thread : completed) {
                if (thread.joinable())
                    thread.join();
            }
            if (stopping)
                return;
        }
    }

    void startClientReaper() {
        {
            std::lock_guard<std::mutex> lk(clientThreadsMu_);
            clientReaperStop_ = false;
        }
        auto self = shared_from_this();
        clientReaperThread_ = std::thread([self] { self->runClientReaper(); });
    }

    void stopClientReaper() {
        {
            std::lock_guard<std::mutex> lk(clientThreadsMu_);
            clientReaperStop_ = true;
        }
        clientThreadsCv_.notify_one();
        if (clientReaperThread_.joinable())
            clientReaperThread_.join();
    }
};

// ============================================================
// LanFileServer public API
// ============================================================

LanFileServer::LanFileServer()
    : impl_(std::make_shared<Impl>()) {}

LanFileServer::~LanFileServer() { stop(); }

bool LanFileServer::start(uint16_t port, lanpair::PairError* err) noexcept {
    stop();

    if (!impl_->wsa.ok()) {
        if (err) { err->code = WSAGetLastError(); err->message = "WSAStartup failed"; }
        return false;
    }

    if (impl_->password_.empty() || impl_->allowedRoots_.empty()) {
        if (err) { err->code = ERROR_ACCESS_DENIED; err->message = "Set a donor password and shared folder before starting LAN Pair."; }
        return false;
    }
    impl_->port_ = port;
    char host[256] = {};
    gethostname(host, static_cast<int>(sizeof(host) - 1));
    impl_->serverPeerId_ = host[0] ? std::string(host) : Impl::kDefaultPeerId;

    impl_->listenSock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (impl_->listenSock_ == INVALID_SOCKET) {
        if (err) { err->code = WSAGetLastError(); err->message = "Cannot create listen socket"; }
        return false;
    }

    const BOOL yes = TRUE;
    setsockopt(impl_->listenSock_, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&yes), sizeof(yes));

    sockaddr_in bindAddr{};
    bindAddr.sin_family      = AF_INET;
    bindAddr.sin_port        = htons(port);
    bindAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(impl_->listenSock_,
             reinterpret_cast<const sockaddr*>(&bindAddr), sizeof(bindAddr)) != 0) {
        if (err) { err->code = WSAGetLastError(); err->message = "bind() failed"; }
        impl_->closeListen();
        return false;
    }

    if (listen(impl_->listenSock_, SOMAXCONN) != 0) {
        if (err) { err->code = WSAGetLastError(); err->message = "listen() failed"; }
        impl_->closeListen();
        return false;
    }

    u_long nonblocking = 1;
    ioctlsocket(impl_->listenSock_, FIONBIO, &nonblocking);
    impl_->running_ = true;
    impl_->startClientReaper();
    impl_->acceptThread_ = std::thread([this] {
        sftp::DllExceptionBarrier barrier;
        sftp::dll_invoke_void(barrier, [this] { impl_->runAcceptLoop(); });
    });
    return true;
}

void LanFileServer::stop() noexcept {
    if (!impl_) return;
    impl_->running_ = false;
    impl_->closeListen();
    if (impl_->acceptThread_.joinable())
        impl_->acceptThread_.join();
    {
        std::lock_guard<std::mutex> lock(impl_->clientThreadsMu_);
        for (SOCKET socket : impl_->activeClients_) cancelSocket(socket);
    }
    impl_->stopClientReaper();
}

bool LanFileServer::isRunning() const noexcept {
    return impl_ && impl_->running_.load(std::memory_order_relaxed);
}

void LanFileServer::setPassword(const std::string& password) noexcept {
    if (!impl_) return;
    std::lock_guard<std::mutex> lk(impl_->passwordMu_);
    impl_->password_ = password;
}

void LanFileServer::setTrustedInstaller(bool enabled) noexcept {
    if (!impl_) return;
    impl_->trustedInstaller_.store(enabled, std::memory_order_relaxed);
}

void LanFileServer::setAllowedRoots(const std::vector<std::string>& roots) noexcept {
    if (!impl_ || isRunning()) return;
    impl_->allowedRoots_.clear();
    for (const auto& root : roots) {
        std::wstring value = utf8ToWide(root);
        std::array<wchar_t, 32768> full{};
        const DWORD n = GetFullPathNameW(value.c_str(), static_cast<DWORD>(full.size()), full.data(), nullptr);
        if (!n || n >= full.size()) continue;
        value.assign(full.data(), n);
        while (value.size() > 3 && value.back() == L'\\') value.pop_back();
        const DWORD attr = GetFileAttributesW(value.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) &&
            !(attr & FILE_ATTRIBUTE_REPARSE_POINT)) impl_->allowedRoots_.push_back(value);
    }
}
