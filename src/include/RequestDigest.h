#pragma once
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <cstdint>
#include <array>
#include <string>
#include <vector>

class RequestDigest {
    BCRYPT_ALG_HANDLE algorithm_ = nullptr;
    BCRYPT_HASH_HANDLE hash_ = nullptr;
    std::vector<unsigned char> object_;
public:
    RequestDigest() {
        DWORD length = 0, written = 0;
        if (BCryptOpenAlgorithmProvider(&algorithm_, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return;
        if (BCryptGetProperty(algorithm_, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&length),
                              sizeof(length), &written, 0) != 0) return;
        object_.resize(length);
        BCryptCreateHash(algorithm_, &hash_, object_.data(), length, nullptr, 0, 0);
    }
    ~RequestDigest() {
        if (hash_) BCryptDestroyHash(hash_);
        if (algorithm_) BCryptCloseAlgorithmProvider(algorithm_, 0);
    }
    RequestDigest(const RequestDigest&) = delete;
    RequestDigest& operator=(const RequestDigest&) = delete;
    bool add(const void* data, size_t length) {
        if (!hash_) return false;
        const auto* bytes = static_cast<const unsigned char*>(data);
        while (length) {
            const ULONG n = static_cast<ULONG>((std::min)(length, size_t(65536)));
            if (BCryptHashData(hash_, const_cast<PUCHAR>(bytes), n, 0) != 0) return false;
            bytes += n; length -= n;
        }
        return true;
    }
    std::string finish() {
        std::array<unsigned char, 32> bytes{};
        if (!hash_ || BCryptFinishHash(hash_, bytes.data(), static_cast<ULONG>(bytes.size()), 0) != 0) return {};
        static constexpr char digits[] = "0123456789abcdef";
        std::string text(64, '0');
        for (size_t i = 0; i < bytes.size(); ++i) {
            text[2*i] = digits[bytes[i] >> 4]; text[2*i+1] = digits[bytes[i] & 15];
        }
        return text;
    }
    static std::string memory(const void* data, size_t length) {
        RequestDigest digest;
        return digest.add(data, length) ? digest.finish() : std::string{};
    }
    static std::string file(HANDLE file, int64_t offset, int64_t length) {
        LARGE_INTEGER position{}; position.QuadPart = offset;
        if (!SetFilePointerEx(file, position, nullptr, FILE_BEGIN)) return {};
        RequestDigest digest;
        std::array<unsigned char, 65536> buffer{};
        while (length > 0) {
            const DWORD wanted = static_cast<DWORD>((std::min)(length, int64_t(buffer.size())));
            DWORD read = 0;
            if (!ReadFile(file, buffer.data(), wanted, &read, nullptr) || !read || !digest.add(buffer.data(), read)) return {};
            length -= read;
        }
        if (!SetFilePointerEx(file, position, nullptr, FILE_BEGIN)) return {};
        return digest.finish();
    }
};
