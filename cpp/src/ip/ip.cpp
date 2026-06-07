#include "firewallkeeper/ip/ip.hpp"

#include "firewallkeeper/util/http.hpp"
#include "firewallkeeper/util/string_util.hpp"

#include <regex>
#include <sstream>

namespace firewallkeeper::ip {

namespace {

const std::regex kIPv4RE(
    R"(\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b)");

std::string fetch_one(util::HttpClient& client, const std::string& url, std::string& err) {
    err.clear();
    try {
        util::HttpRequest req;
        req.url = url;
        req.timeout_seconds = 10;
        auto resp = client.request(req);
        if (resp.status < 200 || resp.status >= 300) {
            err = "HTTP " + std::to_string(resp.status);
            return {};
        }
        if (resp.body.size() > 4096) resp.body.resize(4096);
        std::smatch m;
        if (std::regex_search(resp.body, m, kIPv4RE)) {
            return m.str();
        }
        err = "响应中未找到 IPv4";
    } catch (const std::exception& e) {
        err = e.what();
    }
    return {};
}

}  // namespace

std::string fetch_public_ipv4(const std::vector<std::string>& urls, std::string& error) {
    error.clear();
    util::HttpClient client;
    std::ostringstream errs;

    for (const auto& url : urls) {
        std::string one_err;
        auto ip = fetch_one(client, url, one_err);
        if (!ip.empty()) return ip;
        if (!errs.str().empty()) errs << '\n';
        errs << "  " << url << ": " << one_err;
    }

    error = "无法获取公网 IPv4:\n" + errs.str();
    return {};
}

std::string to_cidr(const std::string& ip) {
    if (ip.find('/') != std::string::npos) return ip;
    return ip + "/32";
}

}  // namespace firewallkeeper::ip
