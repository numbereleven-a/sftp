#pragma once
#include "LanPair.h"
#include "LanPairInternal.h"
#include "LanPairProtocol.h"

namespace lanpair_internal {

inline constexpr std::string_view kConfirmationAad = "TCSFTP LANPAIR3";

inline bool validPeerId(const std::string& id) {
    return !id.empty() && id.size() <= 255 &&
        id.find_first_of(" \t\r\n|\0", 0, 6) == std::string::npos;
}

inline lanpair::PairRole roleFromIntToken(const std::string& tok) noexcept {
    if (tok == "0") return lanpair::PairRole::Donor;
    if (tok == "1") return lanpair::PairRole::Receiver;
    return lanpair::PairRole::Dual;
}

inline std::string trustName(bool server, const std::string& serverId, const std::string& clientId) {
    const std::string pair = serverId + "|" + clientId;
    auto digest = hmacSha256(
        std::vector<uint8_t>{'L','A','N','3'},
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(pair.data()), pair.size()));
    return std::string(server ? "lan3_srv_" : "lan3_cli_") +
        (digest ? hexEncode(digest->data(), digest->size()) : "invalid");
}

inline bool authenticatePeerClient(SOCKET socket, const std::string& localId,
    const std::string& expectedId, const std::string& password,
    lanpair::PairRole role, lanpair::PairSessionInfo* info,
    lanpair::PairError* err = nullptr) {
    auto fail = [&](int code, const char* msg) {
        if (err) {
            err->code = code;
            err->message = msg;
        }
        return false;
    };

    if (!validPeerId(localId))
        return fail(ERROR_INVALID_PARAMETER, "Invalid local peer ID.");

    const bool passwordAuth = !password.empty();
    const std::string mode = passwordAuth ? "PASSWORD" : "TRUST";
    const std::string hello = "PAIR3 HELLO2 " + escapeToken(localId) + " " +
        std::to_string(static_cast<int>(role)) + " " + mode;
    if (!sendLine(socket, hello))
        return fail(WSAGetLastError(), "Cannot reach the other computer.");

    std::string line;
    if (!recvLine(socket, &line))
        return fail(ERROR_INVALID_DATA, "The other computer closed the connection during handshake (it may run an older plugin without encrypted LAN Pair).");

    const auto shareFields = splitBySpace(line);
    if (!shareFields.empty() &&
        ((shareFields.size() >= 3 && shareFields[1] == "FAIL" && shareFields[2] == "upgrade-required") ||
         (shareFields.size() >= 2 && shareFields[0] == "PAIR3" && shareFields[1] == "CHALLENGE") ||
         shareFields[0] == "PAIR1")) {
        return fail(ERROR_NOT_SUPPORTED, "The peer runs an older plugin without encrypted LAN Pair; update both peers to v10.3.1+ and pair again.");
    }
    if (shareFields.size() >= 3 && shareFields[0] == "PAIR3" && shareFields[1] == "FAIL") {
        if (shareFields[2] == "no-key")
            return fail(ERROR_ACCESS_DENIED, "The other computer has no LAN Pair key for this peer; pair them with the same password first.");
        return fail(ERROR_ACCESS_DENIED, "The other computer refused the LAN Pair connection.");
    }
    if (shareFields.size() != 6 || shareFields[0] != "PAIR3" || shareFields[1] != "SHARE")
        return fail(ERROR_INVALID_DATA, "Unexpected LAN Pair handshake response; update both peers and pair again.");

    const std::string serverId = unescapeToken(shareFields[2]);
    const std::string displayName = unescapeToken(shareFields[3]);
    if (!validPeerId(serverId) || (!expectedId.empty() && serverId != expectedId))
        return fail(ERROR_ACCESS_DENIED, "LAN Pair peer ID mismatch.");

    const auto pB = hexDecode(shareFields[5]);
    if (!pB || pB->size() != 65)
        return fail(ERROR_INVALID_DATA, "Invalid LAN Pair SPAKE2 share.");

    std::vector<uint8_t> key;
    if (passwordAuth) {
        auto derived = derivePairKey(password, localId, serverId);
        if (!derived)
            return fail(ERROR_INVALID_DATA, "LAN Pair key derivation failed.");
        key = std::move(*derived);
    } else {
        std::string stored;
        if (!lanpair::DpapiSecretStore::loadSecret(trustName(false, serverId, localId), &stored, nullptr) ||
            stored.size() != kDerivedKeySize) {
            if (!stored.empty()) SecureZeroMemory(stored.data(), stored.size());
            return fail(ERROR_ACCESS_DENIED, "No LAN Pair password or stored key for this peer; pair with the password first.");
        }
        key.assign(stored.begin(), stored.end());
        SecureZeroMemory(stored.data(), stored.size());
    }

    auto clearKey = [&]() {
        if (!key.empty()) SecureZeroMemory(key.data(), key.size());
    };

    auto w = lanpair_proto::ScalarFromKey(key);
    if (!w) {
        clearKey();
        return fail(ERROR_INVALID_DATA, "LAN Pair scalar derivation failed.");
    }

    lanpair_proto::Spake2 spake(lanpair_proto::Spake2::Role::A, localId, serverId, *w);
    SecureZeroMemory(w->data(), w->size());
    if (!spake.ok() || !spake.finish(*pB, kConfirmationAad)) {
        clearKey();
        return fail(ERROR_INVALID_DATA, "LAN Pair SPAKE2 handshake failed.");
    }

    const auto cA = spake.confirmation();
    const std::string confirmLine = "PAIR3 CONFIRM " +
        hexEncode(spake.share().data(), spake.share().size()) + " " +
        hexEncode(cA.data(), cA.size());
    if (!sendLine(socket, confirmLine) || !recvLine(socket, &line)) {
        clearKey();
        return fail(WSAGetLastError(), "Connection lost during LAN Pair confirmation.");
    }

    const auto result = splitBySpace(line);
    if (result.size() >= 3 && result[0] == "PAIR3" && result[1] == "FAIL") {
        clearKey();
        return fail(ERROR_ACCESS_DENIED, "Wrong LAN Pair password or stored trust key mismatch.");
    }
    const auto cB = (result.size() == 3 && result[0] == "PAIR3" && result[1] == "OK")
        ? hexDecode(result[2])
        : std::nullopt;
    if (!cB || !spake.checkPeerConfirmation(*cB)) {
        clearKey();
        return fail(ERROR_ACCESS_DENIED, "The other computer could not prove the LAN Pair password.");
    }

    if (!secureSocketGcm(socket, spake.secrets(), true)) {
        clearKey();
        return fail(ERROR_INVALID_DATA, "Cannot initialize encrypted LAN Pair channel.");
    }

    if (passwordAuth) {
        std::string raw(key.begin(), key.end());
        const bool saved = lanpair::DpapiSecretStore::saveSecret(trustName(false, serverId, localId), raw, nullptr);
        SecureZeroMemory(raw.data(), raw.size());
        if (!saved) {
            clearKey();
            return fail(ERROR_WRITE_FAULT, "Failed to persist LAN Pair trust key.");
        }
    }
    clearKey();

    if (info) {
        info->remotePeerId = serverId;
        info->remoteDisplayName = displayName.empty() ? serverId : displayName;
        info->remoteRole = roleFromIntToken(shareFields[4]);
    }
    return true;
}

inline bool authenticatePeerServer(SOCKET socket, const std::string& localId,
    const std::string& password, lanpair::PairSessionInfo* info,
    bool allowTrustLookup = true) {
    if (!validPeerId(localId))
        return false;

    std::string hello;
    if (!recvLine(socket, &hello))
        return false;

    const auto fields = splitBySpace(hello);
    if (!fields.empty() && fields[0] == "PAIR1") {
        sendLine(socket, "PAIR1 FAIL upgrade-required");
        return false;
    }
    if (fields.size() >= 2 && fields[0] == "PAIR3" && fields[1] == "HELLO") {
        sendLine(socket, "PAIR3 FAIL upgrade-required");
        return false;
    }
    if (fields.size() != 5 || fields[0] != "PAIR3" || fields[1] != "HELLO2" ||
        (fields[4] != "PASSWORD" && fields[4] != "TRUST")) {
        return false;
    }

    const std::string clientId = unescapeToken(fields[2]);
    if (!validPeerId(clientId))
        return false;

    const bool passwordAuth = (fields[4] == "PASSWORD");
    std::vector<uint8_t> key;
    bool persistTrust = false;

    if (passwordAuth) {
        if (password.empty()) {
            sendLine(socket, "PAIR3 FAIL no-key");
            return false;
        }
        auto derived = derivePairKey(password, localId, clientId);
        if (!derived)
            return false;
        key = std::move(*derived);
        persistTrust = true;
    } else {
        std::string stored;
        if (allowTrustLookup &&
            lanpair::DpapiSecretStore::loadSecret(trustName(true, localId, clientId), &stored, nullptr) &&
            stored.size() == kDerivedKeySize) {
            key.assign(stored.begin(), stored.end());
            SecureZeroMemory(stored.data(), stored.size());
        } else {
            if (!stored.empty()) SecureZeroMemory(stored.data(), stored.size());
            if (!password.empty()) {
                auto derived = derivePairKey(password, localId, clientId);
                if (derived) {
                    key = std::move(*derived);
                    persistTrust = true;
                }
            }
        }
        if (key.empty()) {
            sendLine(socket, "PAIR3 FAIL no-key");
            return false;
        }
    }

    auto clearKey = [&]() {
        if (!key.empty()) SecureZeroMemory(key.data(), key.size());
    };

    auto w = lanpair_proto::ScalarFromKey(key);
    if (!w) {
        clearKey();
        return false;
    }

    lanpair_proto::Spake2 spake(lanpair_proto::Spake2::Role::B, clientId, localId, *w);
    SecureZeroMemory(w->data(), w->size());
    if (!spake.ok()) {
        clearKey();
        return false;
    }

    const std::string shareLine = "PAIR3 SHARE " + escapeToken(localId) + " " +
        escapeToken(localId) + " " + std::to_string(static_cast<int>(lanpair::PairRole::Dual)) +
        " " + hexEncode(spake.share().data(), spake.share().size());
    std::string confirm;
    if (!sendLine(socket, shareLine) || !recvLine(socket, &confirm)) {
        clearKey();
        return false;
    }

    const auto confirmFields = splitBySpace(confirm);
    const auto pA = (confirmFields.size() == 4 && confirmFields[0] == "PAIR3" && confirmFields[1] == "CONFIRM")
        ? hexDecode(confirmFields[2])
        : std::nullopt;
    const auto cA = pA ? hexDecode(confirmFields[3]) : std::nullopt;
    if (!pA || !cA || !spake.finish(*pA, kConfirmationAad) || !spake.checkPeerConfirmation(*cA)) {
        clearKey();
        Sleep(1000); // Rate-limit online password guessing to 1 attempt per second.
        sendLine(socket, "PAIR3 FAIL bad-auth");
        return false;
    }

    const auto cB = spake.confirmation();
    if (!sendLine(socket, "PAIR3 OK " + hexEncode(cB.data(), cB.size()))) {
        clearKey();
        return false;
    }

    if (!secureSocketGcm(socket, spake.secrets(), false)) {
        clearKey();
        return false;
    }

    if (persistTrust) {
        std::string raw(key.begin(), key.end());
        const bool saved = lanpair::DpapiSecretStore::saveSecret(trustName(true, localId, clientId), raw, nullptr);
        SecureZeroMemory(raw.data(), raw.size());
        if (!saved) {
            clearKey();
            return false;
        }
    }
    clearKey();

    if (info) {
        info->remotePeerId = clientId;
        info->remoteDisplayName = clientId;
        info->remoteRole = roleFromIntToken(fields[3]);
    }
    return true;
}

} // namespace lanpair_internal
