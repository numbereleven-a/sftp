#pragma once
#include "RequestDigest.h"
#include <optional>
#include <mutex>
#include <ctime>
#include <cstdint>

inline std::optional<std::vector<uint8_t>> PhpHmacSha256(const std::string& key,
                                                          const std::string& data)
{
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

    DWORD objLen = 0, cb = 0, hashLen = 0;
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
                          reinterpret_cast<PUCHAR>(&objLen), sizeof(objLen), &cb, 0) != 0)
        return std::nullopt;
    if (BCryptGetProperty(alg, BCRYPT_HASH_LENGTH,
                          reinterpret_cast<PUCHAR>(&hashLen), sizeof(hashLen), &cb, 0) != 0)
        return std::nullopt;

    std::vector<uint8_t> obj(objLen);
    BCRYPT_HASH_HANDLE hHash = nullptr;
    if (BCryptCreateHash(alg, &hHash, obj.data(), objLen,
                         reinterpret_cast<PUCHAR>(const_cast<char*>(key.data())),
                         static_cast<ULONG>(key.size()), 0) != 0)
        return std::nullopt;

    std::vector<uint8_t> out(hashLen);
    const NTSTATUS r1 = BCryptHashData(hHash,
        reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())),
        static_cast<ULONG>(data.size()), 0);
    const NTSTATUS r2 = BCryptFinishHash(hHash, out.data(),
                                         static_cast<ULONG>(out.size()), 0);
    BCryptDestroyHash(hHash);
    if (r1 != 0 || r2 != 0) return std::nullopt;
    return out;
}


inline std::string SignPhpRequest(const std::string& password, const std::string& salt,
    const std::string& method, const std::string& operation, const std::string& target,
    const std::string& bodyHash)
{
    if (password.empty() || bodyHash.empty()) return {};
    const std::string keyMaterial = salt.empty() ? password : salt + ":" + password;
    const std::string key = RequestDigest::memory(keyMaterial.data(), keyMaterial.size());
    if (key.empty()) return {};
    std::array<uint8_t, 16> nonce{};
    if (BCryptGenRandom(nullptr, nonce.data(), static_cast<ULONG>(nonce.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) return {};
    constexpr char digits[] = "0123456789abcdef";
    std::string nonceText(32, '0');
    for (size_t i = 0; i < nonce.size(); ++i) {
        nonceText[2*i] = digits[nonce[i] >> 4]; nonceText[2*i+1] = digits[nonce[i] & 15];
    }
    const std::string stamp = std::to_string(time(nullptr));
    const std::string canonical = method + "\n" + operation + "\n" + target +
        "\n" + stamp + "\n" + nonceText + "\n" + bodyHash;
    auto signature = PhpHmacSha256(key, canonical);
    if (!signature) return {};
    std::string hex(signature->size() * 2, '0');
    for (size_t i = 0; i < signature->size(); ++i) {
        hex[2*i] = digits[(*signature)[i] >> 4]; hex[2*i+1] = digits[(*signature)[i] & 15];
    }
    return "X-SFTP-OP: " + operation + "\r\nX-SFTP-SIGNATURE-VERSION: 2\r\nX-SFTP-TS: " +
        stamp + "\r\nX-SFTP-NONCE: " + nonceText + "\r\nX-SFTP-SIGNATURE: " + hex + "\r\n";
}

