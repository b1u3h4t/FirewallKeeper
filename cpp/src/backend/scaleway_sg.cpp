// Scaleway 无官方 C++ SDK，REST 内联于本文件
#include "firewallkeeper/backend/backend.hpp"
#include "firewallkeeper/ip/ip.hpp"
#include "firewallkeeper/util/http.hpp"
#include "firewallkeeper/util/string_util.hpp"
#include <cstdint>
#include <arpa/inet.h>
#include <netdb.h>
#include <iostream>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace firewallkeeper::sc_api {


struct APIError : std::runtime_error {
    std::string message;
    std::string type;
    int status = 0;
    std::string body;

    APIError() : std::runtime_error("") {}

    const char* what() const noexcept override {
        static thread_local std::string msg;
        if (!type.empty()) {
            msg = type + ": " + message;
        } else if (!message.empty()) {
            msg = message;
        } else {
            msg = "HTTP " + std::to_string(status) + ": " + body;
        }
        return msg.c_str();
    }
};

class Client {
public:
    explicit Client(std::string secret_key, std::string base_url = "https://api.scaleway.com");

    void do_request(const std::string& method, const std::string& path,
                    const nlohmann::json* body, nlohmann::json* out);

private:
    std::string secret_key_;
    std::string base_url_;
    util::HttpClient http_;
};

struct Rule {
    std::string id;
    std::string protocol;
    std::string direction;
    std::string action;
    std::string ip_range;
    std::optional<uint32_t> dest_port_from;
    std::optional<uint32_t> dest_port_to;
};

class SecurityGroupClient {
public:
    SecurityGroupClient(std::string secret_key, std::string zone, std::string security_group_id);

    void create_inbound_accept(const std::string& protocol, uint32_t port,
                               const std::string& ip_range);
    std::vector<Rule> list_rules();
    void delete_rule(const std::string& rule_id);
    void delete_inbound_by_match(const std::string& protocol, uint32_t port,
                                 const std::string& ip_range);
    bool rule_exists(const std::string& protocol, uint32_t port, const std::string& ip_range);

private:
    std::string rules_path() const;

    Client api_;
    std::string zone_;
    std::string security_group_id_;
};

uint32_t parse_port(const std::string& port);


Client::Client(std::string secret_key, std::string base_url)
    : secret_key_(std::move(secret_key)), base_url_(std::move(base_url)) {
    while (!base_url_.empty() && base_url_.back() == '/') base_url_.pop_back();
}

void Client::do_request(const std::string& method, const std::string& path,
                        const nlohmann::json* body, nlohmann::json* out) {
    util::HttpRequest req;
    req.method = method;
    req.url = base_url_ + path;
    req.timeout_seconds = 30;
    req.headers = {{"X-Auth-Token", secret_key_}};

    if (body != nullptr) {
        req.body = body->dump();
        req.headers["Content-Type"] = "application/json";
    }

    const auto resp = http_.request(req);

    if (resp.status < 200 || resp.status >= 300) {
        APIError err;
        try {
            const auto j = nlohmann::json::parse(resp.body);
            err.message = j.value("message", std::string{});
            err.type = j.value("type", std::string{});
        } catch (...) {
        }
        err.status = static_cast<int>(resp.status);
        err.body = resp.body;
        if (err.message.empty()) err.message = util::truncate_str(resp.body, 512);
        throw err;
    }

    if (out != nullptr && !resp.body.empty()) {
        try {
            *out = nlohmann::json::parse(resp.body);
        } catch (const std::exception& e) {
            throw std::runtime_error(std::string("解析响应失败: ") + e.what() + ", body=" +
                                    util::truncate_str(resp.body, 512));
        }
    }
}

namespace {

std::string normalize_protocol(std::string p) {
    p = util::to_upper(util::trim(p));
    if (p == "TCP" || p == "UDP" || p == "ICMP" || p == "ANY") return p;
    return "TCP";
}

std::string normalize_cidr(std::string s) {
    s = util::trim(s);
    if (s.empty()) return s;
    if (s.find('/') != std::string::npos) {
        in_addr addr{};
        in_addr mask{};
        if (inet_pton(AF_INET, s.substr(0, s.find('/')).c_str(), &addr) == 1) {
            const int prefix = std::stoi(s.substr(s.find('/') + 1));
            uint32_t m = prefix == 0 ? 0 : (~0u << (32 - prefix));
            mask.s_addr = htonl(m);
            char buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, buf, sizeof(buf));
            return std::string(buf) + "/" + std::to_string(prefix);
        }
        return s;
    }
    in_addr addr{};
    if (inet_pton(AF_INET, s.c_str(), &addr) == 1) {
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, buf, sizeof(buf));
        return std::string(buf) + "/32";
    }
    in6_addr addr6{};
    if (inet_pton(AF_INET6, s.c_str(), &addr6) == 1) {
        char buf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr6, buf, sizeof(buf));
        return std::string(buf) + "/128";
    }
    return s;
}

bool port_matches(const std::optional<uint32_t>& from, const std::optional<uint32_t>& to,
                  uint32_t want) {
    if (want == 0) return !from.has_value() && !to.has_value();
    if (!from.has_value() && !to.has_value()) return false;
    uint32_t f = from.value_or(0);
    uint32_t t = to.value_or(0);
    if (t == 0 && f != 0) t = f;
    return want >= f && want <= t;
}

Rule rule_from_json(const nlohmann::json& j) {
    Rule r;
    r.id = j.value("id", std::string{});
    r.protocol = j.value("protocol", std::string{});
    r.direction = j.value("direction", std::string{});
    r.action = j.value("action", std::string{});
    r.ip_range = j.value("ip_range", std::string{});
    if (j.contains("dest_port_from") && !j["dest_port_from"].is_null()) {
        r.dest_port_from = j["dest_port_from"].get<uint32_t>();
    }
    if (j.contains("dest_port_to") && !j["dest_port_to"].is_null()) {
        r.dest_port_to = j["dest_port_to"].get<uint32_t>();
    }
    return r;
}

}  // namespace

SecurityGroupClient::SecurityGroupClient(std::string secret_key, std::string zone,
                                         std::string security_group_id)
    : api_(std::move(secret_key)),
      zone_(std::move(zone)),
      security_group_id_(std::move(security_group_id)) {}

std::string SecurityGroupClient::rules_path() const {
    return "/instance/v1/zones/" + zone_ + "/security_groups/" + security_group_id_ + "/rules";
}

void SecurityGroupClient::create_inbound_accept(const std::string& protocol, uint32_t port,
                                                const std::string& ip_range) {
    nlohmann::json body = {
        {"protocol", normalize_protocol(protocol)},
        {"direction", "inbound"},
        {"action", "accept"},
        {"ip_range", ip_range},
    };
    if (port > 0) {
        body["dest_port_from"] = port;
        body["dest_port_to"] = port;
    }
    nlohmann::json resp;
    api_.do_request("POST", rules_path(), &body, &resp);
}

std::vector<Rule> SecurityGroupClient::list_rules() {
    std::vector<Rule> all;
    int page = 1;
    constexpr int per_page = 100;

    while (true) {
        const std::string path =
            rules_path() + "?per_page=" + std::to_string(per_page) + "&page=" + std::to_string(page);
        nlohmann::json resp;
        api_.do_request("GET", path, nullptr, &resp);

        std::vector<Rule> page_rules;
        if (resp.contains("rules") && resp["rules"].is_array()) {
            for (const auto& item : resp["rules"]) page_rules.push_back(rule_from_json(item));
        }
        all.insert(all.end(), page_rules.begin(), page_rules.end());
        if (static_cast<int>(page_rules.size()) < per_page) break;
        ++page;
    }
    return all;
}

void SecurityGroupClient::delete_rule(const std::string& rule_id) {
    api_.do_request("DELETE", rules_path() + "/" + rule_id, nullptr, nullptr);
}

void SecurityGroupClient::delete_inbound_by_match(const std::string& protocol, uint32_t port,
                                                  const std::string& ip_range) {
    const auto rules = list_rules();
    const std::string proto = normalize_protocol(protocol);
    std::vector<std::string> ids;

    for (const auto& r : rules) {
        if (!util::iequals(r.direction, "inbound")) continue;
        if (!util::iequals(r.action, "accept")) continue;
        if (!util::iequals(r.protocol, proto)) continue;
        if (normalize_cidr(r.ip_range) != normalize_cidr(ip_range)) continue;
        if (!port_matches(r.dest_port_from, r.dest_port_to, port)) continue;
        ids.push_back(r.id);
    }

    if (ids.empty()) {
        APIError err;
        err.type = "not_found";
        err.message = "no matching security group rule";
        err.status = 404;
        throw err;
    }

    for (const auto& id : ids) delete_rule(id);
}

bool SecurityGroupClient::rule_exists(const std::string& protocol, uint32_t port,
                                      const std::string& ip_range) {
    const auto rules = list_rules();
    const std::string proto = normalize_protocol(protocol);
    for (const auto& r : rules) {
        if (!util::iequals(r.direction, "inbound") || !util::iequals(r.action, "accept") ||
            !util::iequals(r.protocol, proto)) {
            continue;
        }
        if (normalize_cidr(r.ip_range) != normalize_cidr(ip_range)) continue;
        if (port_matches(r.dest_port_from, r.dest_port_to, port)) return true;
    }
    return false;
}

uint32_t parse_port(const std::string& port) {
    const auto p = util::trim(port);
    if (p.empty()) return 0;
    if (p.find('-') != std::string::npos) {
        return static_cast<uint32_t>(std::stoul(util::trim(p.substr(0, p.find('-')))));
    }
    if (p.find('/') != std::string::npos) {
        return static_cast<uint32_t>(std::stoul(util::trim(p.substr(0, p.find('/')))));
    }
    return static_cast<uint32_t>(std::stoul(p));
}

}  // namespace firewallkeeper::sc_api

namespace firewallkeeper::backend {

namespace {

bool is_scaleway_duplicate(const std::exception& e) {
    if (const auto* api_err = dynamic_cast<const sc_api::APIError*>(&e)) {
        const auto msg = util::to_lower(api_err->message + " " + api_err->type);
        return api_err->status == 409 || util::contains_icase(msg, "already") ||
               util::contains_icase(msg, "duplicate") || util::contains_icase(msg, "exist");
    }
    return false;
}

bool is_scaleway_not_found(const std::exception& e) {
    if (const auto* api_err = dynamic_cast<const sc_api::APIError*>(&e)) {
        return api_err->status == 404 || api_err->type == "not_found";
    }
    return false;
}

class ScalewaySgBackend : public IBackend {
public:
    ScalewaySgBackend(std::string name, sc_api::SecurityGroupClient client)
        : name_(std::move(name)), client_(std::move(client)) {}

    std::string name() const override { return name_; }

    bool upsert_whitelist(const std::string& ip, const std::optional<std::string>& old_ip,
                          const config::Config& cfg, std::string& error) override {
        const auto cidr = ip::to_cidr(ip);
        const auto proto = util::to_upper(cfg.protocol);
        return sync_whitelist_ports(
            ip, old_ip, cfg,
            [&](const std::string& port_str, std::string& err) {
                try {
                    return create_rule(proto, cidr, sc_api::parse_port(port_str), port_str, err);
                } catch (const std::exception& e) {
                    err = "无效端口 \"" + port_str + "\": " + e.what();
                    return false;
                }
            },
            [&](const std::string& port_str, std::string& err) {
                try {
                    return delete_rule(proto, ip::to_cidr(*old_ip), sc_api::parse_port(port_str),
                                       port_str, err);
                } catch (const std::exception& e) {
                    err = "无效端口 \"" + port_str + "\": " + e.what();
                    return false;
                }
            },
            error);
    }

private:
    bool create_rule(const std::string& proto, const std::string& cidr, uint32_t port,
                     const std::string& port_str, std::string& error) {
        try {
            if (client_.rule_exists(proto, port, cidr)) {
                std::cout << "[" << name_ << "] 安全组规则已存在，跳过: " << cidr << " " << proto
                          << " " << port_str << '\n';
                return true;
            }
            client_.create_inbound_accept(proto, port, cidr);
            std::cout << "[" << name_ << "] 已添加 Scaleway 安全组入站规则: " << cidr << " " << proto
                      << " " << port_str << '\n';
            return true;
        } catch (const std::exception& e) {
            if (is_scaleway_duplicate(e) || is_duplicate(e.what())) {
                std::cout << "[" << name_ << "] 安全组规则已存在，跳过: " << cidr << " " << proto
                          << " " << port_str << '\n';
                return true;
            }
            error = std::string("CreateSecurityGroupRule: ") + e.what();
            return false;
        }
    }

    bool delete_rule(const std::string& proto, const std::string& cidr, uint32_t port,
                     const std::string& port_str, std::string& error) {
        try {
            client_.delete_inbound_by_match(proto, port, cidr);
            std::cout << "[" << name_ << "] 已删除旧 Scaleway 安全组入站规则: " << cidr << " "
                      << proto << " " << port_str << '\n';
            return true;
        } catch (const std::exception& e) {
            if (is_scaleway_not_found(e) || is_not_found(e.what())) {
                std::cout << "[" << name_ << "] 旧安全组规则不存在，跳过: " << cidr << " "
                          << port_str << '\n';
                return true;
            }
            error = std::string("DeleteSecurityGroupRule: ") + e.what();
            return false;
        }
    }

    std::string name_;
    sc_api::SecurityGroupClient client_;
};

}  // namespace

std::unique_ptr<IBackend> new_scaleway_sg(const config::Target& t, const config::Config&,
                                           std::string& error) {
    error.clear();
    const auto zone = t.zone.empty() ? t.region : t.zone;
    return std::make_unique<ScalewaySgBackend>(
        t.name, sc_api::SecurityGroupClient(t.secret_key, zone, t.security_group_id));
}

}  // namespace firewallkeeper::backend
