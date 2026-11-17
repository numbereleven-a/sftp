#include "global.h"
#include "LanPairProtocol.h"
#include "LanPairInternal.h"

#include <mbedtls/bignum.h>
#include <mbedtls/ecp.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/platform_util.h>

#include <algorithm>
#include <cstring>

namespace lanpair_proto {

namespace {

using namespace lanpair_internal;

// RFC 9382 section 6: M and N for P-256, compressed SEC1.
constexpr char kSpake2M[] = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f";
constexpr char kSpake2N[] = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49";

int MbedRng(void*, unsigned char* output, size_t len)
{
    if (len == 0)
        return 0;
    return randomBytes(output, len) ? 0 : -1;
}

bool HkdfSha256(std::span<const uint8_t> key, std::span<const uint8_t> salt,
                std::string_view info, std::span<uint8_t> out)
{
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md || key.empty() || out.empty())
        return false;
    return mbedtls_hkdf(
        md,
        salt.empty() ? nullptr : salt.data(), salt.size(),
        key.data(), key.size(),
        info.empty() ? nullptr : reinterpret_cast<const unsigned char*>(info.data()), info.size(),
        out.data(), out.size()) == 0;
}

bool Sha256(std::span<const uint8_t> data, std::span<uint8_t> out32)
{
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md || out32.size() != 32)
        return false;
    return mbedtls_md(md, data.data(), data.size(), out32.data()) == 0;
}

void AppendWithLength(std::vector<uint8_t>& tt, std::span<const uint8_t> data)
{
    uint64_t len = data.size();
    for (int i = 0; i < 8; ++i) {
        tt.push_back(static_cast<uint8_t>(len & 0xFF));
        len >>= 8;
    }
    tt.insert(tt.end(), data.begin(), data.end());
}

std::span<const uint8_t> AsBytes(std::string_view s)
{
    return {reinterpret_cast<const uint8_t*>(s.data()), s.size()};
}

bool ImportPointHex(const mbedtls_ecp_group* grp, mbedtls_ecp_point* pt, const char* hex)
{
    const auto bytes = hexDecode(hex);
    if (!bytes)
        return false;
    return mbedtls_ecp_point_read_binary(grp, pt, bytes->data(), bytes->size()) == 0 &&
           mbedtls_ecp_check_pubkey(grp, pt) == 0;
}

std::vector<uint8_t> EncodeUncompressed(const mbedtls_ecp_group* grp, const mbedtls_ecp_point* pt)
{
    std::vector<uint8_t> out(65);
    size_t olen = 0;
    if (mbedtls_ecp_point_write_binary(grp, pt, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, out.data(), out.size()) != 0 ||
        olen != 65) {
        return {};
    }
    return out;
}

// Computes R = s * P using blinded scalar multiplication when s != 0.
bool MulPointBlinded(mbedtls_ecp_group* grp, mbedtls_ecp_point* R,
                     const mbedtls_mpi* s, const mbedtls_ecp_point* P)
{
    if (mbedtls_mpi_cmp_int(s, 0) == 0)
        return mbedtls_ecp_set_zero(R) == 0;
    return mbedtls_ecp_mul(grp, R, s, P, MbedRng, nullptr) == 0;
}

std::array<uint8_t, 12> MakeIv(const std::array<uint8_t, 4>& salt, uint64_t seq) noexcept
{
    std::array<uint8_t, 12> iv{};
    std::copy(salt.begin(), salt.end(), iv.begin());
    for (int i = 0; i < 8; ++i)
        iv[4 + i] = static_cast<uint8_t>(seq >> (56 - 8 * i));
    return iv;
}

} // namespace

std::optional<std::array<uint8_t, 48>> ScalarFromKey(std::span<const uint8_t> key)
{
    std::array<uint8_t, 48> w{};
    if (key.empty() || !HkdfSha256(key, {}, "TCSFTP LANPAIR3 w", w))
        return std::nullopt;
    return w;
}

struct Spake2::Impl {
    Role role = Role::A;
    std::string idA;
    std::string idB;
    mbedtls_ecp_group grp{};
    mbedtls_mpi w{};
    mbedtls_mpi eph{};
    mbedtls_ecp_point m{};
    mbedtls_ecp_point n{};
    std::vector<uint8_t> share;
    std::vector<uint8_t> tt;
    Secrets secrets;
    bool ok = false;
    bool finished = false;

    Impl()
    {
        mbedtls_ecp_group_init(&grp);
        mbedtls_mpi_init(&w);
        mbedtls_mpi_init(&eph);
        mbedtls_ecp_point_init(&m);
        mbedtls_ecp_point_init(&n);
    }

    ~Impl()
    {
        mbedtls_ecp_point_free(&m);
        mbedtls_ecp_point_free(&n);
        mbedtls_mpi_free(&eph);
        mbedtls_mpi_free(&w);
        mbedtls_ecp_group_free(&grp);
        mbedtls_platform_zeroize(&secrets, sizeof(secrets));
        if (!tt.empty())
            mbedtls_platform_zeroize(tt.data(), tt.size());
    }
};

Spake2::Spake2(Role role, std::string_view idA, std::string_view idB,
               std::span<const uint8_t> wBytes, std::span<const uint8_t> ephemeral)
    : impl_(std::make_unique<Impl>())
{
    Impl& s = *impl_;
    s.role = role;
    s.idA.assign(idA);
    s.idB.assign(idB);
    if (wBytes.empty() ||
        mbedtls_ecp_group_load(&s.grp, MBEDTLS_ECP_DP_SECP256R1) != 0 ||
        !ImportPointHex(&s.grp, &s.m, kSpake2M) ||
        !ImportPointHex(&s.grp, &s.n, kSpake2N)) {
        return;
    }

    mbedtls_mpi wRaw{};
    mbedtls_mpi_init(&wRaw);
    const bool wOk =
        mbedtls_mpi_read_binary(&wRaw, wBytes.data(), wBytes.size()) == 0 &&
        mbedtls_mpi_mod_mpi(&s.w, &wRaw, &s.grp.N) == 0;
    mbedtls_mpi_free(&wRaw);
    if (!wOk)
        return;

    if (!ephemeral.empty()) {
        if (mbedtls_mpi_read_binary(&s.eph, ephemeral.data(), ephemeral.size()) != 0 ||
            mbedtls_ecp_check_privkey(&s.grp, &s.eph) != 0) {
            return;
        }
    } else {
        if (mbedtls_ecp_gen_privkey(&s.grp, &s.eph, MbedRng, nullptr) != 0)
            return;
    }

    // pA = x*G + w*M, pB = y*G + w*N using constant-time blinded multiplications.
    mbedtls_ecp_point ephG{}, wGen{}, p{};
    mbedtls_mpi one{};
    mbedtls_ecp_point_init(&ephG);
    mbedtls_ecp_point_init(&wGen);
    mbedtls_ecp_point_init(&p);
    mbedtls_mpi_init(&one);

    bool shareOk = false;
    if (mbedtls_mpi_lset(&one, 1) == 0 &&
        MulPointBlinded(&s.grp, &ephG, &s.eph, &s.grp.G) &&
        MulPointBlinded(&s.grp, &wGen, &s.w, role == Role::A ? &s.m : &s.n)) {
        if (mbedtls_ecp_is_zero(&wGen)) {
            shareOk = mbedtls_ecp_copy(&p, &ephG) == 0;
        } else {
            shareOk = mbedtls_ecp_muladd(&s.grp, &p, &one, &ephG, &one, &wGen) == 0;
        }
    }
    if (shareOk && !mbedtls_ecp_is_zero(&p))
        s.share = EncodeUncompressed(&s.grp, &p);

    mbedtls_mpi_free(&one);
    mbedtls_ecp_point_free(&p);
    mbedtls_ecp_point_free(&wGen);
    mbedtls_ecp_point_free(&ephG);
    s.ok = !s.share.empty();
}

Spake2::~Spake2() = default;

bool Spake2::ok() const noexcept { return impl_ && impl_->ok; }
const std::vector<uint8_t>& Spake2::share() const noexcept { return impl_->share; }
const Spake2::Secrets& Spake2::secrets() const noexcept { return impl_->secrets; }

bool Spake2::finish(std::span<const uint8_t> peerShare, std::string_view aad)
{
    Impl& s = *impl_;
    if (!s.ok || s.finished || peerShare.size() != 65 || peerShare[0] != 0x04)
        return false;

    mbedtls_ecp_point peer{}, wPeerGen{}, blind{}, kPt{};
    mbedtls_mpi one{}, minusOne{};
    mbedtls_ecp_point_init(&peer);
    mbedtls_ecp_point_init(&wPeerGen);
    mbedtls_ecp_point_init(&blind);
    mbedtls_ecp_point_init(&kPt);
    mbedtls_mpi_init(&one);
    mbedtls_mpi_init(&minusOne);

    bool good =
        mbedtls_mpi_lset(&one, 1) == 0 &&
        mbedtls_mpi_lset(&minusOne, -1) == 0 &&
        mbedtls_ecp_point_read_binary(&s.grp, &peer, peerShare.data(), peerShare.size()) == 0 &&
        mbedtls_ecp_check_pubkey(&s.grp, &peer) == 0 &&
        !mbedtls_ecp_is_zero(&peer) &&
        MulPointBlinded(&s.grp, &wPeerGen, &s.w, s.role == Role::A ? &s.n : &s.m);

    if (good) {
        if (mbedtls_ecp_is_zero(&wPeerGen)) {
            good = mbedtls_ecp_copy(&blind, &peer) == 0;
        } else {
            good = mbedtls_ecp_muladd(&s.grp, &blind, &one, &peer, &minusOne, &wPeerGen) == 0;
        }
    }
    good = good &&
        !mbedtls_ecp_is_zero(&blind) &&
        MulPointBlinded(&s.grp, &kPt, &s.eph, &blind) &&
        !mbedtls_ecp_is_zero(&kPt);

    std::vector<uint8_t> peerEncoded;
    std::vector<uint8_t> kEncoded;
    if (good) {
        peerEncoded = EncodeUncompressed(&s.grp, &peer);
        kEncoded = EncodeUncompressed(&s.grp, &kPt);
        good = peerEncoded.size() == 65 && kEncoded.size() == 65;
    }

    mbedtls_mpi_free(&minusOne);
    mbedtls_mpi_free(&one);
    mbedtls_ecp_point_free(&kPt);
    mbedtls_ecp_point_free(&blind);
    mbedtls_ecp_point_free(&wPeerGen);
    mbedtls_ecp_point_free(&peer);
    if (!good) {
        if (!kEncoded.empty()) mbedtls_platform_zeroize(kEncoded.data(), kEncoded.size());
        return false;
    }

    std::array<uint8_t, 32> wBytes{};
    const bool wWritten = mbedtls_mpi_write_binary(&s.w, wBytes.data(), wBytes.size()) == 0;
    if (!wWritten) {
        mbedtls_platform_zeroize(kEncoded.data(), kEncoded.size());
        mbedtls_platform_zeroize(wBytes.data(), wBytes.size());
        return false;
    }

    const std::vector<uint8_t>& pA = s.role == Role::A ? s.share : peerEncoded;
    const std::vector<uint8_t>& pB = s.role == Role::A ? peerEncoded : s.share;
    s.tt.clear();
    AppendWithLength(s.tt, AsBytes(s.idA));
    AppendWithLength(s.tt, AsBytes(s.idB));
    AppendWithLength(s.tt, pA);
    AppendWithLength(s.tt, pB);
    AppendWithLength(s.tt, kEncoded);
    AppendWithLength(s.tt, wBytes);
    mbedtls_platform_zeroize(kEncoded.data(), kEncoded.size());
    mbedtls_platform_zeroize(wBytes.data(), wBytes.size());

    if (!Sha256(s.tt, s.secrets.transcriptHash))
        return false;
    std::copy_n(s.secrets.transcriptHash.begin(), 16, s.secrets.ke.begin());
    std::copy_n(s.secrets.transcriptHash.begin() + 16, 16, s.secrets.ka.begin());

    std::string info = "ConfirmationKeys";
    info.append(aad);
    std::array<uint8_t, 32> kc{};
    const bool kcOk = HkdfSha256(s.secrets.ka, {}, info, kc);
    if (kcOk) {
        std::copy_n(kc.begin(), 16, s.secrets.kcA.begin());
        std::copy_n(kc.begin() + 16, 16, s.secrets.kcB.begin());
    }
    mbedtls_platform_zeroize(kc.data(), kc.size());
    if (!kcOk)
        return false;

    s.finished = true;
    return true;
}

std::array<uint8_t, 32> Spake2::confirmation() const
{
    std::array<uint8_t, 32> mac{};
    const Impl& s = *impl_;
    if (!s.finished)
        return mac;
    const auto& key = s.role == Role::A ? s.secrets.kcA : s.secrets.kcB;
    auto h = hmacSha256(key, s.tt);
    if (h && h->size() == mac.size())
        std::copy(h->begin(), h->end(), mac.begin());
    return mac;
}

bool Spake2::checkPeerConfirmation(std::span<const uint8_t> mac) const
{
    const Impl& s = *impl_;
    if (!s.finished || mac.size() != 32)
        return false;
    const auto& key = s.role == Role::A ? s.secrets.kcB : s.secrets.kcA;
    auto expected = hmacSha256(key, s.tt);
    return expected && expected->size() == 32 && constantTimeEqual(*expected, mac);
}

// ===========================================================================
// GcmCipher
// ===========================================================================
struct GcmCipher::Impl {
    mbedtls_gcm_context ctx{};
    std::array<uint8_t, 4> salt{};
    uint64_t seq = 0;
    bool initialized = false;

    Impl() { mbedtls_gcm_init(&ctx); }
    ~Impl()
    {
        mbedtls_gcm_free(&ctx);
        mbedtls_platform_zeroize(salt.data(), salt.size());
        seq = 0;
    }
};

GcmCipher::GcmCipher() : impl_(std::make_unique<Impl>()) {}
GcmCipher::~GcmCipher() = default;

bool GcmCipher::init(std::span<const uint8_t> key32, std::span<const uint8_t> salt4) noexcept
{
    if (!impl_ || key32.size() != 32 || salt4.size() != 4)
        return false;
    if (mbedtls_gcm_setkey(&impl_->ctx, MBEDTLS_CIPHER_ID_AES, key32.data(), 256) != 0)
        return false;
    std::copy(salt4.begin(), salt4.end(), impl_->salt.begin());
    impl_->seq = 0;
    impl_->initialized = true;
    return true;
}

bool GcmCipher::encryptFrame(const uint8_t* plaintext, size_t len, std::vector<uint8_t>& outFrame) noexcept
{
    if (!impl_ || !impl_->initialized || !plaintext || len == 0 || len > kMaxFramePlaintext || impl_->seq == UINT64_MAX)
        return false;
    outFrame.resize(kFrameHeaderSize + len + kGcmTagSize);
    for (int i = 0; i < 4; ++i)
        outFrame[i] = static_cast<uint8_t>(len >> (24 - 8 * i));
    const auto iv = MakeIv(impl_->salt, impl_->seq++);
    const int rc = mbedtls_gcm_crypt_and_tag(
        &impl_->ctx,
        MBEDTLS_GCM_ENCRYPT,
        len,
        iv.data(), iv.size(),
        outFrame.data(), kFrameHeaderSize,
        plaintext,
        outFrame.data() + kFrameHeaderSize,
        kGcmTagSize,
        outFrame.data() + kFrameHeaderSize + len);
    if (rc != 0) {
        mbedtls_platform_zeroize(outFrame.data(), outFrame.size());
        outFrame.clear();
        return false;
    }
    return true;
}

bool GcmCipher::decryptFrame(const uint8_t header4[4], const uint8_t* ciphertextAndTag, size_t len,
                             uint8_t* outPlaintext) noexcept
{
    if (!impl_ || !impl_->initialized || !header4 || !ciphertextAndTag || !outPlaintext ||
        len == 0 || len > kMaxFramePlaintext || impl_->seq == UINT64_MAX) {
        return false;
    }
    const auto iv = MakeIv(impl_->salt, impl_->seq++);
    const int rc = mbedtls_gcm_auth_decrypt(
        &impl_->ctx,
        len,
        iv.data(), iv.size(),
        header4, kFrameHeaderSize,
        ciphertextAndTag + len, kGcmTagSize,
        ciphertextAndTag,
        outPlaintext);
    if (rc != 0) {
        mbedtls_platform_zeroize(outPlaintext, len);
        return false;
    }
    return true;
}

uint64_t GcmCipher::sequence() const noexcept
{
    return impl_ ? impl_->seq : 0;
}

ChannelMaterial::~ChannelMaterial()
{
    mbedtls_platform_zeroize(txKey.data(), txKey.size());
    mbedtls_platform_zeroize(txSalt.data(), txSalt.size());
    mbedtls_platform_zeroize(rxKey.data(), rxKey.size());
    mbedtls_platform_zeroize(rxSalt.data(), rxSalt.size());
}

bool DeriveChannelMaterial(const Spake2::Secrets& secrets, bool initiator, ChannelMaterial& out) noexcept
{
    std::array<uint8_t, 36> i2r{};
    std::array<uint8_t, 36> r2i{};
    const bool ok =
        HkdfSha256(secrets.ke, secrets.transcriptHash, "TCSFTP LANPAIR3 initiator to responder", i2r) &&
        HkdfSha256(secrets.ke, secrets.transcriptHash, "TCSFTP LANPAIR3 responder to initiator", r2i);
    if (ok) {
        const auto& tx = initiator ? i2r : r2i;
        const auto& rx = initiator ? r2i : i2r;
        std::copy_n(tx.begin(), 32, out.txKey.begin());
        std::copy_n(tx.begin() + 32, 4, out.txSalt.begin());
        std::copy_n(rx.begin(), 32, out.rxKey.begin());
        std::copy_n(rx.begin() + 32, 4, out.rxSalt.begin());
    }
    mbedtls_platform_zeroize(i2r.data(), i2r.size());
    mbedtls_platform_zeroize(r2i.data(), r2i.size());
    return ok;
}

} // namespace lanpair_proto
