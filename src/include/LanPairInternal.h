#pragma once
// LanPairInternal.h — shared crypto and socket primitives for LanPair.cpp / LanPairSession.cpp.
//
// NOT part of the public API.  Include ONLY from those two translation units.
//
// Every definition here is marked `inline` so the header may be included from
// multiple TUs without ODR violations (C++17 inline variables / functions).
// The `static inline` members of WsaScope give a single process-wide reference
// count, which is correct: WSAStartup/WSACleanup are themselves reference-counted
// by Windows, and the plugin always runs in one process.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>

#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <map>
#include <set>
#include <memory>
#include <algorithm>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace lanpair_internal {

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

inline constexpr size_t kNonceSize       = 16;
inline constexpr size_t kSaltSize        = 16;
inline constexpr size_t kDerivedKeySize  = 32;
inline constexpr ULONG  kPbkdf2Iterations = 120'000;

// ---------------------------------------------------------------------------
// WsaScope — reference-counted WSAStartup / WSACleanup guard
// ---------------------------------------------------------------------------

class WsaScope {
public:
    WsaScope() {
        std::lock_guard<std::mutex> lk(mu_);
        if (refCount_++ == 0) {
            WSADATA wsa{};
            ok_      = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
            started_ = ok_;
        } else {
            ok_ = started_;
        }
    }

    ~WsaScope() {
        std::lock_guard<std::mutex> lk(mu_);
        if (refCount_ == 0) return;
        if (--refCount_ == 0 && started_) {
            WSACleanup();
            started_ = false;
        }
    }

    WsaScope(const WsaScope&)            = delete;
    WsaScope& operator=(const WsaScope&) = delete;

    bool ok() const noexcept { return ok_; }

private:
    bool ok_ = false;

    static inline std::mutex mu_;
    static inline int        refCount_ = 0;
    static inline bool       started_  = false;
};

// ---------------------------------------------------------------------------
// Hex encoding / decoding
// ---------------------------------------------------------------------------

inline std::string hexEncode(const uint8_t* data, size_t len) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out(len * 2, '\0');
    for (size_t i = 0; i < len; ++i) {
        out[2 * i]     = kHex[(data[i] >> 4) & 0x0F];
        out[2 * i + 1] = kHex[ data[i]       & 0x0F];
    }
    return out;
}

inline std::optional<std::vector<uint8_t>> hexDecode(std::string_view in) {
    if (in.size() % 2 != 0) return std::nullopt;

    auto val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };

    std::vector<uint8_t> out(in.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        const int hi = val(in[2 * i]);
        const int lo = val(in[2 * i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Cryptographic primitives
// ---------------------------------------------------------------------------

inline bool randomBytes(uint8_t* out, size_t len) {
    return BCryptGenRandom(nullptr, out, static_cast<ULONG>(len),
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
}

inline std::optional<std::vector<uint8_t>> hmacSha256(
    std::span<const uint8_t> key,
    std::span<const uint8_t> data)
{
    // Cache the HMAC-SHA256 algorithm provider process-wide. Opening it on
    // every call dominated PBKDF2 cost (120k iterations per key derivation).
    // Inline-function statics are shared across TUs (single instance, C++17).
    static BCRYPT_ALG_HANDLE cachedAlg   = nullptr;
    static std::mutex      cachedAlgMu;

    BCRYPT_ALG_HANDLE  alg   = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    DWORD objLen = 0, cb = 0, hashLen = 0;

    {
        std::lock_guard<std::mutex> lk(cachedAlgMu);
        alg = cachedAlg;
    }
    if (!alg) {
        BCRYPT_ALG_HANDLE fresh = nullptr;
        if (BCryptOpenAlgorithmProvider(&fresh, BCRYPT_SHA256_ALGORITHM, nullptr,
                                        BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
            return std::nullopt;
        std::lock_guard<std::mutex> lk(cachedAlgMu);
        if (!cachedAlg) {
            cachedAlg = fresh;
            alg       = fresh;
        } else {
            BCryptCloseAlgorithmProvider(fresh, 0);
            alg = cachedAlg;
        }
    }

    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
                          reinterpret_cast<PUCHAR>(&objLen), sizeof(objLen),
                          &cb, 0) != 0) {
        return std::nullopt;
    }
    if (BCryptGetProperty(alg, BCRYPT_HASH_LENGTH,
                          reinterpret_cast<PUCHAR>(&hashLen), sizeof(hashLen),
                          &cb, 0) != 0) {
        return std::nullopt;
    }

    std::vector<uint8_t> hashObj(objLen);
    std::vector<uint8_t> out(hashLen);

    if (BCryptCreateHash(alg, &hHash,
                         hashObj.data(), objLen,
                         const_cast<PUCHAR>(key.data()),
                         static_cast<ULONG>(key.size()), 0) != 0) {
        return std::nullopt;
    }

    const NTSTATUS h1 = BCryptHashData(hHash,
                                       const_cast<PUCHAR>(data.data()),
                                       static_cast<ULONG>(data.size()), 0);
    const NTSTATUS h2 = BCryptFinishHash(hHash, out.data(),
                                         static_cast<ULONG>(out.size()), 0);
    BCryptDestroyHash(hHash);
    // The algorithm provider stays cached — do NOT close it here.

    if (h1 != 0 || h2 != 0) return std::nullopt;
    return out;
}

inline std::optional<std::vector<uint8_t>> deriveKeyPbkdf2(
    std::string_view password,
    std::span<const uint8_t> salt,
    size_t keyLen)
{
    if (keyLen == 0) return std::vector<uint8_t>{};

    const std::vector<uint8_t> passBytes(password.begin(), password.end());
    if (passBytes.empty()) return std::nullopt;

    constexpr size_t hLen = 32; // SHA-256 output size
    const size_t blockCount = (keyLen + hLen - 1) / hLen;

    // Fast path: prime ONE keyed hash object with the password, then clone it
    // per iteration via BCryptDuplicateHash instead of rebuilding the keyed
    // HMAC state 120k times.
    static BCRYPT_ALG_HANDLE cachedAlg = nullptr;
    static std::mutex        cachedAlgMu;
    BCRYPT_ALG_HANDLE alg = nullptr;
    {
        std::lock_guard<std::mutex> lk(cachedAlgMu);
        alg = cachedAlg;
    }
    if (!alg) {
        BCRYPT_ALG_HANDLE fresh = nullptr;
        if (BCryptOpenAlgorithmProvider(&fresh, BCRYPT_SHA256_ALGORITHM, nullptr,
                                        BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
            return std::nullopt;
        std::lock_guard<std::mutex> lk(cachedAlgMu);
        if (!cachedAlg) { cachedAlg = fresh; alg = fresh; }
        else { BCryptCloseAlgorithmProvider(fresh, 0); alg = cachedAlg; }
    }

    DWORD objLen = 0, cb = 0;
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
                          reinterpret_cast<PUCHAR>(&objLen), sizeof(objLen),
                          &cb, 0) != 0)
        return std::nullopt;

    BCRYPT_HASH_HANDLE hMaster = nullptr;
    std::vector<uint8_t> masterObj(objLen);
    if (BCryptCreateHash(alg, &hMaster, masterObj.data(), objLen,
                         const_cast<PUCHAR>(passBytes.data()),
                         static_cast<ULONG>(passBytes.size()), 0) != 0)
        return std::nullopt;

    std::vector<uint8_t> derived;
    derived.reserve(blockCount * hLen);
    bool ok = true;

    for (size_t block = 1; block <= blockCount && ok; ++block) {
        // PRF input: salt || INT(block)  (RFC 2898 §5.2)
        std::vector<uint8_t> saltBlock(salt.begin(), salt.end());
        saltBlock.push_back(static_cast<uint8_t>((block >> 24) & 0xFF));
        saltBlock.push_back(static_cast<uint8_t>((block >> 16) & 0xFF));
        saltBlock.push_back(static_cast<uint8_t>((block >>  8) & 0xFF));
        saltBlock.push_back(static_cast<uint8_t>( block        & 0xFF));

        std::vector<uint8_t> t(hLen, 0);
        std::vector<uint8_t> u(hLen, 0);
        BCRYPT_HASH_HANDLE hIter = nullptr;

        auto macOnce = [&](std::span<const uint8_t> in,
                           std::vector<uint8_t>& outBuf) -> bool {
            BCRYPT_HASH_HANDLE h = nullptr;
            std::vector<uint8_t> obj(objLen);
            if (BCryptDuplicateHash(hMaster, &h, obj.data(), objLen, 0) != 0)
                return false;
            const NTSTATUS r1 = BCryptHashData(h,
                const_cast<PUCHAR>(in.data()), static_cast<ULONG>(in.size()), 0);
            const NTSTATUS r2 = BCryptFinishHash(h, outBuf.data(),
                                                 static_cast<ULONG>(outBuf.size()), 0);
            BCryptDestroyHash(h);
            return r1 == 0 && r2 == 0;
        };

        if (!macOnce(saltBlock, u)) { ok = false; break; }
        t = u;
        for (ULONG i = 2; i <= kPbkdf2Iterations && ok; ++i) {
            std::span<const uint8_t> uIn(u.data(), u.size());
            if (!macOnce(uIn, u)) { ok = false; break; }
            for (size_t j = 0; j < t.size(); ++j)
                t[j] ^= u[j];
        }
        if (ok)
            derived.insert(derived.end(), t.begin(), t.end());
    }

    BCryptDestroyHash(hMaster);
    if (!ok) return std::nullopt;

    derived.resize(keyLen);
    return derived;
}

// ---------------------------------------------------------------------------
// Deterministic per-pair PBKDF2 salt: HMAC-SHA256("LANPAIR", "a<>b" sorted).
inline std::vector<uint8_t> derivePairSalt(std::string_view peerIdA,
                                           std::string_view peerIdB) {
    std::string combined;
    if (peerIdA < peerIdB) combined = std::string(peerIdA) + "<>" + std::string(peerIdB);
    else                   combined = std::string(peerIdB) + "<>" + std::string(peerIdA);
    std::vector<uint8_t> salt(16, 0);
    auto h = hmacSha256(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>("LANPAIR"), 7),
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(combined.data()), combined.size()));
    if (h && h->size() >= 16) {
        for (size_t i = 0; i < 16; ++i) salt[i] = (*h)[i];
    } else {
        memcpy(salt.data(), "sftpplug-pair...", 16);
    }
    return salt;
}

inline std::optional<std::vector<uint8_t>> derivePairKey(
    std::string_view password,
    std::string_view peerIdA,
    std::string_view peerIdB)
{
    if (password.empty()) return std::nullopt;
    const auto salt = derivePairSalt(peerIdA, peerIdB);
    return deriveKeyPbkdf2(password, salt, kDerivedKeySize);
}

// Key / token helpers
// ---------------------------------------------------------------------------

// Sanitise an arbitrary string so it can be used as a filename component
// or DPAPI key discriminator.
inline std::string sanitizeKey(std::string_view key) {
    std::string out;
    out.reserve(key.size());
    for (char c : key) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-')
            out.push_back(c);
        else
            out.push_back('_');
    }
    return out.empty() ? "default" : out;
}

inline std::string trustKeyForServer(std::string_view serverPeerId,
                                     std::string_view clientPeerId) {
    return "lanpair_trust_srv_" + sanitizeKey(serverPeerId)
         + "__" + sanitizeKey(clientPeerId);
}

inline std::string trustKeyForClient(std::string_view serverPeerId,
                                     std::string_view clientPeerId) {
    return "lanpair_trust_cli_" + sanitizeKey(serverPeerId)
         + "__" + sanitizeKey(clientPeerId);
}

// Percent-encode a token for wire lines.
inline std::string escapeToken(std::string_view in) {
    std::ostringstream oss;
    for (unsigned char c : in) {
        if (std::isalnum(c) || c == '_' || c == '-' || c == '.') {
            oss << static_cast<char>(c);
        } else {
            oss << '%' << std::uppercase << std::hex;
            if (c < 16) oss << '0';
            oss << static_cast<int>(c) << std::nouppercase << std::dec;
        }
    }
    return oss.str();
}

inline std::string unescapeToken(std::string_view in) {
    std::string out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '%' && i + 2 < in.size()) {
            const auto decoded = hexDecode(in.substr(i + 1, 2));
            if (decoded && decoded->size() == 1) {
                out.push_back(static_cast<char>((*decoded)[0]));
                i += 2;
                continue;
            }
        }
        out.push_back(in[i]);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Socket helpers
// ---------------------------------------------------------------------------

inline bool setSocketTimeout(SOCKET s, DWORD ms) {
    return setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
                      reinterpret_cast<const char*>(&ms), sizeof(ms)) == 0
        && setsockopt(s, SOL_SOCKET, SO_SNDTIMEO,
                      reinterpret_cast<const char*>(&ms), sizeof(ms)) == 0;
}

inline std::mutex cancellationMutex;
inline std::set<SOCKET> cancelledSockets;
inline bool socketCancelled(SOCKET s) {
    std::lock_guard<std::mutex> lock(cancellationMutex);
    return cancelledSockets.contains(s);
}
inline void cancelSocket(SOCKET s) {
    std::lock_guard<std::mutex> lock(cancellationMutex);
    cancelledSockets.insert(s);
    shutdown(s, SD_BOTH);
}
inline void resetSocketCancellation(SOCKET s) {
    std::lock_guard<std::mutex> lock(cancellationMutex);
    cancelledSockets.erase(s);
}
inline bool waitSocket(SOCKET s, bool writing, ULONGLONG deadline) {
    while (!socketCancelled(s) && GetTickCount64() < deadline) {
        fd_set set; FD_ZERO(&set); FD_SET(s, &set);
        timeval timeout{0, 100000};
        const int result = select(0, writing ? nullptr : &set, writing ? &set : nullptr, nullptr, &timeout);
        if (result > 0) return true;
        if (result == SOCKET_ERROR) return false;
    }
    return false;
}

inline bool rawSendAll(SOCKET s, const uint8_t* data, size_t len) {
    u_long nonblocking = 1; ioctlsocket(s, FIONBIO, &nonblocking);
    size_t sent = 0;
    DWORD timeout = 300000; int optionLength = sizeof(timeout);
    getsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char*>(&timeout), &optionLength);
    if (!timeout) timeout = 300000;
    const ULONGLONG deadline = GetTickCount64() + timeout;
    while (sent < len) {
        if (!waitSocket(s, true, deadline)) return false;
        const int n = send(s,
                           reinterpret_cast<const char*>(data + sent),
                           static_cast<int>(std::min<size_t>(len - sent, 65536)), 0);
        if (n == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) continue;
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

inline bool rawRecvAll(SOCKET s, uint8_t* data, size_t len) {
    u_long nonblocking = 1; ioctlsocket(s, FIONBIO, &nonblocking);
    size_t got = 0;
    DWORD timeout = 300000; int optionLength = sizeof(timeout);
    getsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), &optionLength);
    if (!timeout) timeout = 300000;
    const ULONGLONG deadline = GetTickCount64() + timeout;
    while (got < len) {
        if (!waitSocket(s, false, deadline)) return false;
        const int n = recv(s, reinterpret_cast<char*>(data + got),
                           static_cast<int>(std::min<size_t>(len - got, 65536)), 0);
        if (n == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) continue;
        if (n <= 0) return false;
        got += static_cast<size_t>(n);
    }
    return true;
}

inline bool constantTimeEqual(std::span<const uint8_t> a, std::span<const uint8_t> b) {
    if (a.size() != b.size()) return false;
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); ++i) diff = static_cast<uint8_t>(diff | (a[i] ^ b[i]));
    return diff == 0;
}

inline bool verifyHexMac(const std::optional<std::vector<uint8_t>>& expected,
                         const std::string& supplied) {
    auto decoded = hexDecode(supplied);
    return expected && decoded && constantTimeEqual(*expected, *decoded);
}

// LAN3 encrypts and authenticates every frame after the SPAKE2 handshake
// using per-direction AES-256-GCM keys and monotonic 64-bit sequence IVs.
} // namespace lanpair_internal

#include "LanPairProtocol.h"

namespace lanpair_internal {

struct LanChannel {
    std::shared_ptr<lanpair_proto::GcmCipher> txCipher;
    std::shared_ptr<lanpair_proto::GcmCipher> rxCipher;
    std::vector<uint8_t> pending;
    size_t pendingOffset = 0;

    ~LanChannel() {
        if (!pending.empty()) {
            SecureZeroMemory(pending.data(), pending.size());
        }
    }
};
inline std::mutex channelsMutex;
inline std::map<SOCKET, std::shared_ptr<LanChannel>> channels;

inline std::shared_ptr<LanChannel> channelFor(SOCKET s) {
    std::lock_guard<std::mutex> lock(channelsMutex);
    auto it = channels.find(s);
    return it == channels.end() ? nullptr : it->second;
}

inline bool secureSocketGcm(SOCKET s, const lanpair_proto::Spake2::Secrets& secrets, bool initiator) {
    lanpair_proto::ChannelMaterial mat;
    if (!lanpair_proto::DeriveChannelMaterial(secrets, initiator, mat))
        return false;
    auto tx = std::make_shared<lanpair_proto::GcmCipher>();
    auto rx = std::make_shared<lanpair_proto::GcmCipher>();
    if (!tx->init(mat.txKey, mat.txSalt) || !rx->init(mat.rxKey, mat.rxSalt))
        return false;
    auto channel = std::make_shared<LanChannel>();
    channel->txCipher = std::move(tx);
    channel->rxCipher = std::move(rx);
    std::lock_guard<std::mutex> lock(channelsMutex);
    channels[s] = std::move(channel);
    return true;
}

inline void closeSocket(SOCKET s) {
    { std::lock_guard<std::mutex> lock(channelsMutex); channels.erase(s); }
    closesocket(s);
    resetSocketCancellation(s);
}

inline bool sendAll(SOCKET s, const uint8_t* data, size_t len) {
    auto channel = channelFor(s);
    if (!channel || !channel->txCipher) return rawSendAll(s, data, len);
    std::vector<uint8_t> frame;
    while (len) {
        const size_t n = (std::min)(len, lanpair_proto::kMaxFramePlaintext);
        if (!channel->txCipher->encryptFrame(data, n, frame) ||
            !rawSendAll(s, frame.data(), frame.size())) {
            return false;
        }
        data += n;
        len -= n;
    }
    return true;
}

inline bool receiveBytes(SOCKET s, uint8_t* data, size_t len) {
    auto channel = channelFor(s);
    if (!channel || !channel->rxCipher) return rawRecvAll(s, data, len);
    while (len) {
        if (channel->pendingOffset == channel->pending.size()) {
            std::array<uint8_t, lanpair_proto::kFrameHeaderSize> header{};
            if (!rawRecvAll(s, header.data(), header.size())) return false;
            const uint32_t size = (static_cast<uint32_t>(header[0]) << 24) |
                                  (static_cast<uint32_t>(header[1]) << 16) |
                                  (static_cast<uint32_t>(header[2]) << 8)  |
                                  static_cast<uint32_t>(header[3]);
            if (!size || size > lanpair_proto::kMaxFramePlaintext) return false;
            std::vector<uint8_t> ciphertextAndTag(static_cast<size_t>(size) + lanpair_proto::kGcmTagSize);
            if (!rawRecvAll(s, ciphertextAndTag.data(), ciphertextAndTag.size())) return false;
            if (!channel->pending.empty())
                SecureZeroMemory(channel->pending.data(), channel->pending.size());
            channel->pending.resize(size);
            if (!channel->rxCipher->decryptFrame(header.data(), ciphertextAndTag.data(), size,
                                                 channel->pending.data())) {
                channel->pending.clear();
                channel->pendingOffset = 0;
                return false;
            }
            channel->pendingOffset = 0;
        }
        const size_t n = (std::min)(len, channel->pending.size() - channel->pendingOffset);
        memcpy(data, channel->pending.data() + channel->pendingOffset, n);
        channel->pendingOffset += n;
        data += n;
        len -= n;
    }
    return true;
}

inline bool recvLine(SOCKET s, std::string* out, size_t maxLen = 4096) {
    out->clear();
    char c = 0;
    DWORD timeout = 300000; int optionLength = sizeof(timeout);
    getsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), &optionLength);
    const ULONGLONG deadline = GetTickCount64() + (timeout ? timeout : 300000);
    while (out->size() < maxLen) {
        if (GetTickCount64() >= deadline || socketCancelled(s)) return false;
        if (!receiveBytes(s, reinterpret_cast<uint8_t*>(&c), 1)) return false;
        if (c == '\n') return true;
        if (c != '\r') out->push_back(c);
    }
    return false;
}

inline bool sendLine(SOCKET s, const std::string& line) {
    return sendAll(s, reinterpret_cast<const uint8_t*>(line.data()), line.size())
        && sendAll(s, reinterpret_cast<const uint8_t*>("\n"), 1);
}

inline std::vector<std::string> splitBySpace(const std::string& line) {
    std::istringstream iss(line);
    std::vector<std::string> parts;
    for (std::string tok; iss >> tok;)
        parts.push_back(std::move(tok));
    return parts;
}

} // namespace lanpair_internal
