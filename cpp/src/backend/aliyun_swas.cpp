// 阿里云 SWAS 无可用官方 C++ SDK，REST 内联于本文件
#include "firewallkeeper/backend/backend.hpp"
#include "firewallkeeper/ip/ip.hpp"
#include "firewallkeeper/util/http.hpp"
#include "firewallkeeper/util/string_util.hpp"
#include "firewallkeeper/util/crypto.hpp"
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace firewallkeeper::ali_api {


inline constexpr const char* kAPIVersion = "2020-06-01";

struct APIError : std::runtime_error {
    std::string code;

    APIError(std::string code, std::string message)
        : std::runtime_error(message), code(std::move(code)) {}
};

struct FirewallRule {
    std::string rule_id;
    std::string rule_protocol;
    std::string port;
    std::string source_cidr_ip;
    std::string remark;
};

class Client {
public:
    Client(std::string access_key_id, std::string access_key_secret, std::string region,
           std::string endpoint);

    nlohmann::json do_action(const std::string& action, std::map<std::string, std::string> params);

private:
    std::string access_key_id_;
    std::string access_key_secret_;
    std::string region_;
    std::string endpoint_;
    util::HttpClient http_;
};

class SWASClient {
public:
    SWASClient(std::string access_key_id, std::string access_key_secret, std::string region,
               std::string endpoint, std::string instance_id);

    void create_rules(const std::string& protocol, const std::string& port,
                      const std::string& source_cidr, const std::string& remark);
    void delete_rules_by_match(const std::string& protocol, const std::string& port,
                               const std::string& source_cidr);

private:
    std::vector<FirewallRule> list_all_firewall_rules();

    Client api_;
    std::string instance_id_;
};


namespace {

std::string percent_encode(std::string_view s) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : s) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else if (c == ' ') {
            out += "%20";
        } else if (c == '*') {
            out += "%2A";
        } else {
            out.push_back('%');
            out.push_back(hex[c >> 4]);
            out.push_back(hex[c & 0x0F]);
        }
    }
    return out;
}

std::string sign_rpc(const std::map<std::string, std::string>& params,
                     const std::string& secret) {
    std::vector<std::string> keys;
    keys.reserve(params.size());
    for (const auto& [k, v] : params) {
        if (k != "Signature") keys.push_back(k);
    }
    std::sort(keys.begin(), keys.end());

    std::ostringstream canonical;
    for (size_t i = 0; i < keys.size(); ++i) {
        if (i > 0) canonical << '&';
        canonical << percent_encode(keys[i]) << '=' << percent_encode(params.at(keys[i]));
    }

    const std::string string_to_sign =
        "POST&" + percent_encode("/") + "&" + percent_encode(canonical.str());
    return util::hmac_sha1_base64(secret + "&", string_to_sign);
}

std::string utc_timestamp() {
    const auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

std::string form_encode(const std::map<std::string, std::string>& params) {
    std::ostringstream form;
    bool first = true;
    for (const auto& [k, v] : params) {
        if (!first) form << '&';
        first = false;
        form << percent_encode(k) << '=' << percent_encode(v);
    }
    return form.str();
}

}  // namespace

Client::Client(std::string access_key_id, std::string access_key_secret, std::string region,
               std::string endpoint)
    : access_key_id_(std::move(access_key_id)),
      access_key_secret_(std::move(access_key_secret)),
      region_(std::move(region)) {
    if (endpoint.empty()) {
        endpoint_ = "https://swas." + region_ + ".aliyuncs.com";
    } else {
        endpoint_ = endpoint;
        if (endpoint_.find("http") != 0) endpoint_ = "https://" + endpoint_;
    }
    while (!endpoint_.empty() && endpoint_.back() == '/') endpoint_.pop_back();
}

nlohmann::json Client::do_action(const std::string& action,
                                 std::map<std::string, std::string> params) {
    params["Action"] = action;
    params["Version"] = kAPIVersion;
    params["Format"] = "JSON";
    params["RegionId"] = region_;
    params["AccessKeyId"] = access_key_id_;
    params["SignatureMethod"] = "HMAC-SHA1";
    params["SignatureVersion"] = "1.0";
    params["SignatureNonce"] = util::random_nonce_hex();
    params["Timestamp"] = utc_timestamp();

    params["Signature"] = sign_rpc(params, access_key_secret_);

    util::HttpRequest req;
    req.method = "POST";
    req.url = endpoint_ + "/";
    req.body = form_encode(params);
    req.timeout_seconds = 30;
    req.headers = {{"Content-Type", "application/x-www-form-urlencoded"}};

    const auto resp = http_.request(req);

    nlohmann::json parsed;
    try {
        parsed = nlohmann::json::parse(resp.body);
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("解析响应失败: ") + e.what() + ", body=" +
                                 util::truncate_str(resp.body, 512));
    }

    if (parsed.contains("Code") && parsed["Code"].is_string()) {
        const auto code = parsed["Code"].get<std::string>();
        if (!code.empty()) {
            throw APIError(code, parsed.value("Message", std::string{}));
        }
    }

    if (resp.status < 200 || resp.status >= 300) {
        throw std::runtime_error("HTTP " + std::to_string(resp.status) + ": " +
                                 util::truncate_str(resp.body, 512));
    }
    return parsed;
}

namespace {

std::string format_port(std::string port) {
    port = util::trim(port);
    if (port.empty()) return port;
    if (port.find('/') != std::string::npos) return port;
    if (port.find(',') != std::string::npos || port.find('-') != std::string::npos) return port;
    return port + "/" + port;
}

std::string normalize_port(std::string port) {
    port = util::trim(port);
    const auto slash = port.find('/');
    if (slash != std::string::npos) {
        const auto a = port.substr(0, slash);
        const auto b = port.substr(slash + 1);
        if (a == b) return a;
    }
    return port;
}

bool port_equal(const std::string& a, const std::string& b) {
    return normalize_port(a) == normalize_port(b) || a == b;
}

std::string string_from_json(const nlohmann::json& v) {
    if (v.is_string()) return v.get<std::string>();
    if (v.is_number_integer()) return std::to_string(v.get<int64_t>());
    if (v.is_number_float()) return std::to_string(static_cast<int64_t>(v.get<double>()));
    return v.dump();
}

int int_from_json(const nlohmann::json& v) {
    if (v.is_number_integer()) return v.get<int>();
    if (v.is_number_float()) return static_cast<int>(v.get<double>());
    if (v.is_string()) return std::stoi(v.get<std::string>());
    return 0;
}

}  // namespace

SWASClient::SWASClient(std::string access_key_id, std::string access_key_secret,
                       std::string region, std::string endpoint, std::string instance_id)
    : api_(std::move(access_key_id), std::move(access_key_secret), std::move(region),
           std::move(endpoint)),
      instance_id_(std::move(instance_id)) {}

void SWASClient::create_rules(const std::string& protocol, const std::string& port,
                              const std::string& source_cidr, const std::string& remark) {
    std::map<std::string, std::string> params{
        {"InstanceId", instance_id_},
        {"FirewallRules.1.RuleProtocol", protocol},
        {"FirewallRules.1.Port", format_port(port)},
        {"FirewallRules.1.SourceCidrIp", source_cidr},
    };
    if (!remark.empty()) params["FirewallRules.1.Remark"] = remark;
    api_.do_action("CreateFirewallRules", params);
}

void SWASClient::delete_rules_by_match(const std::string& protocol, const std::string& port,
                                       const std::string& source_cidr) {
    const auto rules = list_all_firewall_rules();
    const std::string want_port = normalize_port(port);
    std::vector<std::string> rule_ids;
    for (const auto& r : rules) {
        if (!port_equal(normalize_port(r.port), want_port)) continue;
        if (!util::iequals(r.rule_protocol, protocol)) continue;
        if (r.source_cidr_ip != source_cidr) continue;
        rule_ids.push_back(r.rule_id);
    }

    if (rule_ids.empty()) {
        throw APIError("RuleNotFound", "no matching firewall rule");
    }

    std::map<std::string, std::string> params{
        {"InstanceId", instance_id_},
        {"ClientToken", util::random_nonce_hex()},
    };
    for (size_t i = 0; i < rule_ids.size(); ++i) {
        params["RuleIds." + std::to_string(i + 1)] = rule_ids[i];
    }
    api_.do_action("DeleteFirewallRules", params);
}

std::vector<FirewallRule> SWASClient::list_all_firewall_rules() {
    std::vector<FirewallRule> all;
    int page = 1;
    constexpr int page_size = 50;

    while (true) {
        const auto resp = api_.do_action("ListFirewallRules",
                                         {{"InstanceId", instance_id_},
                                          {"PageNumber", std::to_string(page)},
                                          {"PageSize", std::to_string(page_size)}});

        if (resp.contains("FirewallRules") && resp["FirewallRules"].is_array()) {
            for (const auto& item : resp["FirewallRules"]) {
                all.push_back(FirewallRule{
                    string_from_json(item.value("RuleId", nlohmann::json{})),
                    string_from_json(item.value("RuleProtocol", nlohmann::json{})),
                    string_from_json(item.value("Port", nlohmann::json{})),
                    string_from_json(item.value("SourceCidrIp", nlohmann::json{})),
                    string_from_json(item.value("Remark", nlohmann::json{})),
                });
            }
        }

        const int total = int_from_json(resp.value("TotalCount", nlohmann::json{0}));
        const auto count = resp.contains("FirewallRules") && resp["FirewallRules"].is_array()
                               ? resp["FirewallRules"].size()
                               : 0;
        if (static_cast<int>(all.size()) >= total || static_cast<int>(count) < page_size) break;
        ++page;
    }
    return all;
}

}  // namespace firewallkeeper::ali_api

namespace firewallkeeper::backend {

namespace {

bool is_aliyun_duplicate(const std::exception& e) {
    if (const auto* api_err = dynamic_cast<const ali_api::APIError*>(&e)) {
        return api_err->code == "FirewallRuleAlreadyExist";
    }
    return is_duplicate(e.what());
}

bool is_aliyun_not_found(const std::exception& e) {
    if (const auto* api_err = dynamic_cast<const ali_api::APIError*>(&e)) {
        return api_err->code == "RuleNotFound" || api_err->code == "InvalidRuleIds.NotFound";
    }
    return is_not_found(e.what());
}

class AliyunSwasBackend : public IBackend {
public:
    AliyunSwasBackend(std::string name, ali_api::SWASClient client)
        : name_(std::move(name)), client_(std::move(client)) {}

    std::string name() const override { return name_; }

    bool upsert_whitelist(const std::string& ip, const std::optional<std::string>& old_ip,
                          const config::Config& cfg, std::string& error) override {
        const auto cidr = ip::to_cidr(ip);
        const auto proto = util::to_upper(cfg.protocol);
        return sync_whitelist_ports(
            ip, old_ip, cfg,
            [&](const std::string& port, std::string& err) {
                return create_rule(cfg, proto, cidr, port, err);
            },
            [&](const std::string& port, std::string& err) {
                return delete_rule(proto, ip::to_cidr(*old_ip), port, err);
            },
            error);
    }

private:
    bool create_rule(const config::Config& cfg, const std::string& proto, const std::string& cidr,
                     const std::string& port, std::string& error) {
        const auto remark = rule_description(cfg, port, 64);
        try {
            client_.create_rules(proto, port, cidr, remark);
            std::cout << "[" << name_ << "] 已添加阿里云 SWAS 防火墙规则: " << cidr << " " << proto
                      << " " << port << '\n';
            return true;
        } catch (const std::exception& e) {
            if (is_aliyun_duplicate(e)) {
                std::cout << "[" << name_ << "] 规则已存在，跳过: " << cidr << " " << proto << " "
                          << port << '\n';
                return true;
            }
            error = std::string("CreateFirewallRules: ") + e.what();
            return false;
        }
    }

    bool delete_rule(const std::string& proto, const std::string& cidr, const std::string& port,
                     std::string& error) {
        try {
            client_.delete_rules_by_match(proto, port, cidr);
            std::cout << "[" << name_ << "] 已删除旧阿里云 SWAS 防火墙规则: " << cidr << " " << proto
                      << " " << port << '\n';
            return true;
        } catch (const std::exception& e) {
            if (is_aliyun_not_found(e)) {
                std::cout << "[" << name_ << "] 旧规则不存在，跳过删除: " << cidr << " " << port
                          << '\n';
                return true;
            }
            error = std::string("DeleteFirewallRules: ") + e.what();
            return false;
        }
    }

    std::string name_;
    ali_api::SWASClient client_;
};

}  // namespace

std::unique_ptr<IBackend> new_aliyun_swas(const config::Target& t, const config::Config&,
                                          std::string& error) {
    error.clear();
    return std::make_unique<AliyunSwasBackend>(
        t.name, ali_api::SWASClient(t.access_key_id, t.access_key_secret, t.region, t.endpoint,
                                      t.instance_id));
}

}  // namespace firewallkeeper::backend
