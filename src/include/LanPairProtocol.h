#pragma once

// LAN Pair protocol 3 ("PAIR3") cryptographic primitives:
// - SPAKE2 over NIST P-256 (RFC 9382, suite SPAKE2-P256-SHA256-HKDF-HMAC)
// - AES-256-GCM per-direction frame encryption with monotonic sequence IVs

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace lanpair_proto {

using KeyBytes = std::vector<uint8_t>;

inline constexpr size_t kMaxFramePlaintext = 65536;
inline constexpr size_t kFrameHeaderSize   = 4;
inline constexpr size_t kGcmTagSize        = 16;

// Derive 48-byte SPAKE2 scalar input from a 256-bit pair key (HKDF-SHA256).
std::optional<std::array<uint8_t, 48>> ScalarFromKey(std::span<const uint8_t> key);

class Spake2 {
public:
    enum class Role { A, B };

    struct Secrets {
        std::array<uint8_t, 32> transcriptHash{};
        std::array<uint8_t, 16> ke{};
        std::array<uint8_t, 16> ka{};
        std::array<uint8_t, 16> kcA{};
        std::array<uint8_t, 16> kcB{};
    };

    // `w` is reduced modulo the P-256 order. `ephemeral` is for deterministic
    // RFC 9382 test vectors only; pass empty for fresh cryptographic randomness.
    Spake2(Role role, std::string_view idA, std::string_view idB,
           std::span<const uint8_t> w, std::span<const uint8_t> ephemeral = {});
    ~Spake2();

    Spake2(const Spake2&) = delete;
    Spake2& operator=(const Spake2&) = delete;

    bool ok() const noexcept;
    // Public share pA or pB as 65-byte uncompressed SEC1 encoding.
    const std::vector<uint8_t>& share() const noexcept;

    bool finish(std::span<const uint8_t> peerShare, std::string_view aad);
    std::array<uint8_t, 32> confirmation() const;
    bool checkPeerConfirmation(std::span<const uint8_t> mac) const;
    const Secrets& secrets() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Per-direction AES-256-GCM frame cipher (4B length AAD + ciphertext + 16B tag).
class GcmCipher {
public:
    GcmCipher();
    ~GcmCipher();

    GcmCipher(const GcmCipher&) = delete;
    GcmCipher& operator=(const GcmCipher&) = delete;

    bool init(std::span<const uint8_t> key32, std::span<const uint8_t> salt4) noexcept;

    // Encrypts 1..kMaxFramePlaintext bytes into [4B big-endian len][ct][16B tag].
    bool encryptFrame(const uint8_t* plaintext, size_t len, std::vector<uint8_t>& outFrame) noexcept;

    // Decrypts and authenticates `len` bytes from `ciphertextAndTag` (size len + 16),
    // authenticated against 4-byte `header4`.
    bool decryptFrame(const uint8_t header4[4], const uint8_t* ciphertextAndTag, size_t len,
                      uint8_t* outPlaintext) noexcept;

    uint64_t sequence() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

struct ChannelMaterial {
    std::array<uint8_t, 32> txKey{};
    std::array<uint8_t, 4>  txSalt{};
    std::array<uint8_t, 32> rxKey{};
    std::array<uint8_t, 4>  rxSalt{};
    ~ChannelMaterial();
};

bool DeriveChannelMaterial(const Spake2::Secrets& secrets, bool initiator, ChannelMaterial& out) noexcept;

} // namespace lanpair_proto
