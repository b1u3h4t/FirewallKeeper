#include "firewallkeeper/util/crypto.hpp"

#include <chrono>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <sstream>

namespace firewallkeeper::util {

namespace {

std::string bytes_to_hex(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

std::vector<uint8_t> sha256_bytes(std::string_view data) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_Digest(data.data(), data.size(), hash, &len, EVP_sha256(), nullptr);
    return {hash, hash + len};
}

}  // namespace

std::string sha256_hex(std::string_view data) {
    auto bytes = sha256_bytes(data);
    return bytes_to_hex(bytes.data(), bytes.size());
}

std::string sha256_hex(const std::vector<uint8_t>& data) {
    return sha256_hex(std::string_view(reinterpret_cast<const char*>(data.data()), data.size()));
}

std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t>& key, std::string_view msg) {
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), out, &len);
    return {out, out + len};
}

std::vector<uint8_t> hmac_sha256(std::string_view key, std::string_view msg) {
    return hmac_sha256(std::vector<uint8_t>(key.begin(), key.end()), msg);
}

std::string hmac_sha256_hex(const std::vector<uint8_t>& key, std::string_view msg) {
    auto out = hmac_sha256(key, msg);
    return bytes_to_hex(out.data(), out.size());
}

std::string hmac_sha1_base64(std::string_view key, std::string_view msg) {
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(EVP_sha1(), key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), out, &len);
    static const char* kTable =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string encoded;
    encoded.reserve(((len + 2) / 3) * 4);
    for (unsigned int i = 0; i < len; i += 3) {
        uint32_t n = static_cast<uint32_t>(out[i]) << 16;
        if (i + 1 < len) n |= static_cast<uint32_t>(out[i + 1]) << 8;
        if (i + 2 < len) n |= static_cast<uint32_t>(out[i + 2]);
        encoded.push_back(kTable[(n >> 18) & 63]);
        encoded.push_back(kTable[(n >> 12) & 63]);
        encoded.push_back(i + 1 < len ? kTable[(n >> 6) & 63] : '=');
        encoded.push_back(i + 2 < len ? kTable[n & 63] : '=');
    }
    return encoded;
}

std::string random_nonce_hex() {
    unsigned char buf[16];
    if (RAND_bytes(buf, sizeof(buf)) != 1) {
        return std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    }
    return bytes_to_hex(buf, sizeof(buf));
}

}  // namespace firewallkeeper::util
