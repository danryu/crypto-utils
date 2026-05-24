#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <array>

#include "bytes.hpp"

namespace crypto::base64 {
namespace {
const auto base64_chars = std::string_view(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/");

auto encode_block(const std::array<std::byte, 3> bytes) -> std::array<std::byte, 4> {
    const auto a = std::byte(base64_chars[((uint8_t)bytes[0] & 0xfc) >> 2]);
    const auto b = std::byte(base64_chars[(((uint8_t)bytes[0] & 0x03) << 4) + (((uint8_t)bytes[1] & 0xf0) >> 4)]);
    const auto c = std::byte(base64_chars[(((uint8_t)bytes[1] & 0x0f) << 2) + (((uint8_t)bytes[2] & 0xc0) >> 6)]);
    const auto d = std::byte(base64_chars[(uint8_t)bytes[2] & 0x3f]);
    return {a, b, c, d};
}

auto decode_block(const std::array<char, 4> chars) -> std::array<std::byte, 3> {
    auto bytes = std::array<std::byte, 4>();
    for(auto i = 0; i < 4; i += 1) {
        bytes[i] = std::byte(chars[i] == '=' ? 0 : base64_chars.find(chars[i]));
    }
    const auto a = std::byte(((uint8_t)bytes[0] << 2) + (((uint8_t)bytes[1] & 0x30) >> 4));
    const auto b = std::byte((((uint8_t)bytes[1] & 0xf) << 4) + (((uint8_t)bytes[2] & 0x3c) >> 2));
    const auto c = std::byte((((uint8_t)bytes[2] & 0x3) << 6) + (uint8_t)bytes[3]);
    return {a, b, c};
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

auto decode(const std::string_view str) -> BytesArray {
    auto r = BytesArray();
    r.reserve(str.size() * 3 / 4);

    for(auto i = 0uz; i < str.size(); i += 4) {
        const auto d = decode_block({str[i + 0], str[i + 1], str[i + 2], str[i + 3]});
        r.push_back(d[0]);
        r.push_back(d[1]);
        r.push_back(d[2]);
    }
    if(*(str.end() - 1) == '=') {
        r.pop_back();
    }
    if(*(str.end() - 2) == '=') {
        r.pop_back();
    }
    return r;
}
} // namespace crypto::base64
