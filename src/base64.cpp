#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <array>

#include "base64.hpp"
#include "bytes.hpp"
#include "macros/unwrap.hpp"

namespace crypto::base64 {
namespace {

const auto encode_table = std::string_view(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/");

constexpr auto generate_decode_table() -> std::array<uint8_t, 0xff> {
    auto ret = std::array<uint8_t, 0xff>();
    std::ranges::fill(ret, 0xff);
    for(auto i = 'A'; i <= 'Z'; i += 1) {
        ret[i] = i - 'A';
    }
    for(auto i = 'a'; i <= 'z'; i += 1) {
        ret[i] = 26 + i - 'a';
    }
    for(auto i = '0'; i <= '9'; i += 1) {
        ret[i] = 52 + i - '0';
    }
    ret['+'] = 62;
    ret['/'] = 63;
    ret['='] = 0;
    return ret;
}

constexpr auto decode_table = generate_decode_table();

auto encode_block(const std::array<std::byte, 3> bytes) -> std::array<std::byte, 4> {
    const auto a = std::byte(encode_table[((uint8_t)bytes[0] & 0xfc) >> 2]);
    const auto b = std::byte(encode_table[(((uint8_t)bytes[0] & 0x03) << 4) + (((uint8_t)bytes[1] & 0xf0) >> 4)]);
    const auto c = std::byte(encode_table[(((uint8_t)bytes[1] & 0x0f) << 2) + (((uint8_t)bytes[2] & 0xc0) >> 6)]);
    const auto d = std::byte(encode_table[(uint8_t)bytes[2] & 0x3f]);
    return {a, b, c, d};
}

auto decode_block(const std::array<char, 4> chars) -> std::optional<std::array<std::byte, 3>> {
    auto bytes = std::array<uint8_t, 4>();
    for(auto i = 0; i < 4; i += 1) {
        bytes[i] = decode_table[chars[i]];
        ensure(bytes[i] != 0xff, "invalid character '{}'", chars[i]);
    }
    const auto a = std::byte((bytes[0] << 2) + ((bytes[1] & 0x30) >> 4));
    const auto b = std::byte(((bytes[1] & 0xf) << 4) + ((bytes[2] & 0x3c) >> 2));
    const auto c = std::byte(((bytes[2] & 0x3) << 6) + bytes[3]);
    return std::array{a, b, c};
}
} // namespace

auto encode(const BytesRef bytes) -> std::string {
    auto r = std::string();

    const auto l = bytes.size();
    for(auto i = 0uz; i + 2 < l; i += 3) {
        const auto e = encode_block({bytes[i + 0], bytes[i + 1], bytes[i + 2]});
        r += std::string_view(reinterpret_cast<const char*>(&e), 4);
    }
    if(const auto rest = l % 3; rest == 1) {
        const auto offset = l - rest;
        const auto e      = encode_block({bytes[offset + 0], std::byte(0), std::byte(0)});
        r += std::string_view(reinterpret_cast<const char*>(&e), 2);
        r += "==";
    } else if(rest == 2) {
        const auto offset = l - rest;
        const auto e      = encode_block({bytes[offset + 0], bytes[offset + 1], std::byte(0)});
        r += std::string_view(reinterpret_cast<const char*>(&e), 3);
        r += "=";
    }

    return r;
}

auto decode(const std::string_view str, MutBytesRef dest) -> std::optional<size_t> {
    for(auto i = 0uz; i < str.size(); i += 4) {
        unwrap(d, decode_block({str[i + 0], str[i + 1], str[i + 2], str[i + 3]}), "invalid character found around {}", i);
        dest[i / 4 * 3 + 0] = d[0];
        dest[i / 4 * 3 + 1] = d[1];
        dest[i / 4 * 3 + 2] = d[2];
    }
    auto ret = dest.size();
    ret += *(str.end() - 1) == '=' ? -1 : 0;
    ret += *(str.end() - 2) == '=' ? -1 : 0;
    return ret;
}

auto decode(const std::string_view str) -> std::optional<BytesArray> {
    unwrap(size, calc_decode_buffer_size(str.size()));
    auto dest = BytesArray(size);
    unwrap(real_size, decode(str, dest));
    dest.resize(real_size);
    return dest;
}
} // namespace crypto::base64
