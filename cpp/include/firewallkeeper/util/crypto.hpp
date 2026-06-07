#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace firewallkeeper::util {

std::string sha256_hex(std::string_view data);
std::string sha256_hex(const std::vector<uint8_t>& data);
std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t>& key, std::string_view msg);
std::vector<uint8_t> hmac_sha256(std::string_view key, std::string_view msg);
std::string hmac_sha256_hex(const std::vector<uint8_t>& key, std::string_view msg);
std::string hmac_sha1_base64(std::string_view key, std::string_view msg);
std::string random_nonce_hex();

}  // namespace firewallkeeper::util
