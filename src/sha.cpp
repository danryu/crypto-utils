#include <openssl/evp.h>

#include "macros/autoptr.hpp"
#include "macros/unwrap.hpp"
#include "sha.hpp"

namespace crypto::sha {
namespace {
declare_autoptr(MDContext, EVP_MD_CTX, EVP_MD_CTX_free);

template <size_t N>
auto calc_generic(const BytesRef data, const char* const algo) -> std::optional<std::array<std::byte, N>> {
    auto ctx = AutoMDContext(EVP_MD_CTX_new());
    if(ctx.get() == NULL) return std::nullopt;
    auto md = EVP_get_digestbyname(algo);
    if(md == NULL) return std::nullopt;

    auto buf = std::array<std::byte, N>();
    if(EVP_DigestInit_ex(ctx.get(), md, NULL) != 1) return std::nullopt;
    if(EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1) return std::nullopt;
    if(EVP_DigestFinal_ex(ctx.get(), reinterpret_cast<unsigned char*>(buf.data()), NULL) != 1) return std::nullopt;
    return buf;
}
} // namespace

auto calc_sha1(const BytesRef data) -> std::optional<std::array<std::byte, 20>> {
    return calc_generic<20>(data, "SHA1");
}

auto calc_sha256(const BytesRef data) -> std::optional<std::array<std::byte, 32>> {
    return calc_generic<32>(data, "SHA256");
}
} // namespace crypto::sha
