#pragma once
#include "LanPair.h"
#include "LanPairInternal.h"

namespace lanpair_internal {

inline std::optional<std::vector<uint8_t>> authMac(
    const std::vector<uint8_t>& key, const std::string& text) {
    return hmacSha256(key, std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(text.data()), text.size()));
}

inline bool validPeerId(const std::string& id) {
    return !id.empty() && id.size() <= 255 &&
        id.find_first_of(" \t\r\n|\0", 0, 6) == std::string::npos;
}

inline std::string trustName(bool server, const std::string& serverId, const std::string& clientId) {
    const std::string pair = serverId + "|" + clientId;
    auto digest = authMac(std::vector<uint8_t>{'L','A','N','3'}, pair);
    return std::string(server ? "lan3_srv_" : "lan3_cli_") +
        (digest ? hexEncode(digest->data(), digest->size()) : "invalid");
}

inline bool finishAuth(SOCKET socket, bool server, bool passwordAuth,
                       const std::string& serverId, const std::string& clientId,
                       const std::string& transcript, const std::vector<uint8_t>& key) {
    auto trust = passwordAuth ? authMac(key, "trust|" + transcript)
                              : std::optional<std::vector<uint8_t>>(key);
    auto session = authMac(key, "session|" + transcript);
    if (!trust || !session || !secureSocket(socket, *session, server)) return false;
    const std::string raw(trust->begin(), trust->end());
    return lanpair::DpapiSecretStore::saveSecret(trustName(server, serverId, clientId), raw, nullptr);
}

inline bool authenticatePeerClient(SOCKET socket, const std::string& localId,
    const std::string& expectedId, const std::string& password,
    lanpair::PairRole role, lanpair::PairSessionInfo* info) {
    if (!validPeerId(localId)) return false;
    std::array<uint8_t, 16> nonce{};
    if (!randomBytes(nonce.data(), nonce.size())) return false;
    const std::string clientNonce = hexEncode(nonce.data(), nonce.size());
    const std::string hello = "PAIR3 HELLO " + localId + " " +
        std::to_string(static_cast<int>(role)) + " " + clientNonce;
    if (!sendLine(socket, hello)) return false;
    std::string line;
    if (!recvLine(socket, &line)) return false;
    const auto challenge = splitBySpace(line);
    if (challenge.size() != 5 || challenge[0] != "PAIR3" || challenge[1] != "CHALLENGE" ||
        !validPeerId(challenge[2]) || (!expectedId.empty() && challenge[2] != expectedId)) return false;
    auto salt = hexDecode(challenge[3]), serverNonce = hexDecode(challenge[4]);
    if (!salt || salt->size() != 16 || !serverNonce || serverNonce->size() != 16) return false;
    const bool passwordAuth = !password.empty();
    std::vector<uint8_t> key;
    if (passwordAuth) {
        auto derived = deriveKeyPbkdf2(password, *salt, 32);
        if (!derived) return false;
        key = *derived;
    } else {
        std::string stored;
        if (!lanpair::DpapiSecretStore::loadSecret(trustName(false, challenge[2], localId), &stored, nullptr) ||
            stored.size() != 32) return false;
        key.assign(stored.begin(), stored.end());
    }
    const std::string mode = passwordAuth ? "PASSWORD" : "TRUST";
    const std::string transcript = hello + "|" + line + "|" + mode;
    auto proof = authMac(key, "client|" + transcript);
    if (!proof || !sendLine(socket, "PAIR3 " + mode + " " + hexEncode(proof->data(), proof->size())) ||
        !recvLine(socket, &line)) return false;
    auto result = splitBySpace(line);
    if (result.size() != 3 || result[0] != "PAIR3" || result[1] != "OK" ||
        !verifyHexMac(authMac(key, "server|" + transcript), result[2])) return false;
    if (!finishAuth(socket, false, passwordAuth, challenge[2], localId, transcript, key)) return false;
    if (info) { info->remotePeerId = challenge[2]; info->remoteDisplayName = challenge[2]; }
    return true;
}

inline bool authenticatePeerServer(SOCKET socket, const std::string& localId,
    const std::string& password, lanpair::PairSessionInfo* info) {
    std::string hello;
    if (!validPeerId(localId) || !recvLine(socket, &hello)) return false;
    const auto fields = splitBySpace(hello);
    if (fields.size() != 5 || fields[0] != "PAIR3" || fields[1] != "HELLO" || !validPeerId(fields[2]))
        return false;
    auto clientNonce = hexDecode(fields[4]);
    if (!clientNonce || clientNonce->size() != 16) return false;
    std::array<uint8_t, 16> salt{}, nonce{};
    if (!randomBytes(salt.data(), salt.size()) || !randomBytes(nonce.data(), nonce.size())) return false;
    const std::string challenge = "PAIR3 CHALLENGE " + localId + " " +
        hexEncode(salt.data(), salt.size()) + " " + hexEncode(nonce.data(), nonce.size());
    std::string line;
    if (!sendLine(socket, challenge) || !recvLine(socket, &line)) return false;
    const auto auth = splitBySpace(line);
    if (auth.size() != 3 || auth[0] != "PAIR3" || (auth[1] != "PASSWORD" && auth[1] != "TRUST")) return false;
    const bool passwordAuth = auth[1] == "PASSWORD";
    std::vector<uint8_t> key;
    if (passwordAuth) {
        auto derived = deriveKeyPbkdf2(password, salt, 32);
        if (!derived) return false;
        key = *derived;
    } else {
        std::string stored;
        if (!lanpair::DpapiSecretStore::loadSecret(trustName(true, localId, fields[2]), &stored, nullptr) ||
            stored.size() != 32) return false;
        key.assign(stored.begin(), stored.end());
    }
    const std::string transcript = hello + "|" + challenge + "|" + auth[1];
    if (!verifyHexMac(authMac(key, "client|" + transcript), auth[2])) return false;
    auto proof = authMac(key, "server|" + transcript);
    if (!proof || !sendLine(socket, "PAIR3 OK " + hexEncode(proof->data(), proof->size()))) return false;
    if (!finishAuth(socket, true, passwordAuth, localId, fields[2], transcript, key)) return false;
    if (info) { info->remotePeerId = fields[2]; info->remoteDisplayName = fields[2]; }
    return true;
}
} // namespace lanpair_internal
