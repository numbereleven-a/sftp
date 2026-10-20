#pragma once
#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <format>
#include "SftpClient.h"

inline std::string Sha256HostFingerprint(ISshSession* session) {
    const char* raw = session->hostkeyHash(LIBSSH2_HOSTKEY_HASH_SHA256);
    if (!raw) return {};
    DWORD length = 0;
    if (!CryptBinaryToStringA(reinterpret_cast<const BYTE*>(raw), 32,
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &length)) return {};
    std::string encoded(length, '\0');
    if (!CryptBinaryToStringA(reinterpret_cast<const BYTE*>(raw), 32,
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, encoded.data(), &length)) return {};
    encoded.resize(length);
    while (!encoded.empty() && (encoded.back() == '\0' || encoded.back() == '=')) encoded.pop_back();
    return "SHA256:" + encoded;
}

inline bool MatchesLegacyFingerprint(ISshSession* session, const std::string& saved) {
    const char* raw = session->hostkeyHash(LIBSSH2_HOSTKEY_HASH_MD5);
    if (!raw || saved.empty() || saved.starts_with("SHA256:")) return false;
    std::string text;
    for (size_t i = 0; i < 16; ++i) {
        if (i) text += ' ';
        text += std::format("{:02X}", static_cast<unsigned char>(raw[i]));
    }
    return text == saved;
}
