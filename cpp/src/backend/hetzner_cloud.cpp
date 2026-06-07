// Hetzner Cloud 无官方 C++ SDK，REST 内联于本文件
#include "firewallkeeper/backend/backend.hpp"
#include "firewallkeeper/ip/ip.hpp"
#include "firewallkeeper/util/http.hpp"
#include "firewallkeeper/util/string_util.hpp"
#include <cstdint>
#include <iostream>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace firewallkeeper::hc_api {


struct APIError : std::runtime_error {
    std::string code;
    std::string message;
    int status = 0;
    std::string body;

    APIError() : std::runtime_error("") {}

    const char* what() const noexcept override {
        static thread_local std::string msg;
        if (!code.empty()) {
            msg = code + ": " + message;
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
    explicit Client(std::string token, std::string base_url = "https://api.hetzner.cloud/v1");

    void do_request(const std::string& method, const std::string& path,
                    const nlohmann::json* body, nlohmann::json* out);

private:
    std::string token_;
    std::string base_url_;
    util::HttpClient http_;
};

struct Rule {
    std::string description;
    std::string direction;
    std::string protocol;
    std::string port;
    std::vector<std::string> source_ips;
    std::vector<std::string> destination_ips;
};

struct Firewall {
    int64_t id = 0;
    std::string name;
    std::vector<Rule> rules;
};

class FirewallClient {
public:
    static FirewallClient create(const std::string& token, const std::string& firewall_id,
                                 const std::string& endpoint = "");

    Firewall get();
    void set_rules(const std::vector<Rule>& rules);
    void upsert_inbound(const std::string& proto, const std::string& port,
                        const std::string& cidr, const std::string& desc);
    void remove_inbound(const std::string& proto, const std::string& port,
                        const std::string& cidr, const std::string& desc_prefix);

private:
    FirewallClient(Client api, int64_t firewall_id);

    std::string path() const;

    Client api_;
    int64_t firewall_id_;
};


Client::Client(std::string token, std::string base_url)
    : token_(std::move(token)), base_url_(std::move(base_url)) {
    while (!base_url_.empty() && base_url_.back() == '/') base_url_.pop_back();
}

void Client::do_request(const std::string& method, const std::string& path,
                        const nlohmann::json* body, nlohmann::json* out) {
    util::HttpRequest req;
    req.method = method;
    req.url = base_url_ + path;
    req.timeout_seconds = 30;
    req.headers = {{"Authorization", "Bearer " + token_}};

    if (body != nullptr) {
        req.body = body->dump();
        req.headers["Content-Type"] = "application/json";
    }

    const auto resp = http_.request(req);

    if (resp.status < 200 || resp.status >= 300) {
        APIError err;
        try {
            const auto j = nlohmann::json::parse(resp.body);
            if (j.contains("error")) {
                err.code = j["error"].value("code", std::string{});
                err.message = j["error"].value("message", std::string{});
            }
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
    p = util::to_lower(util::trim(p));
    if (p == "tcp" || p == "udp" || p == "icmp" || p == "esp" || p == "gre") return p;
    return "tcp";
}

std::string normalize_cidr(std::string s) { return util::trim(s); }

Rule rule_from_json(const nlohmann::json& j) {
    Rule r;
    r.description = j.value("description", std::string{});
    r.direction = j.value("direction", std::string{});
    r.protocol = j.value("protocol", std::string{});
    r.port = j.value("port", std::string{});
    if (j.contains("source_ips") && j["source_ips"].is_array()) {
        for (const auto& ip : j["source_ips"]) {
            if (ip.is_string()) r.source_ips.push_back(ip.get<std::string>());
        }
    }
    if (j.contains("destination_ips") && j["destination_ips"].is_array()) {
        for (const auto& ip : j["destination_ips"]) {
            if (ip.is_string()) r.destination_ips.push_back(ip.get<std::string>());
        }
    }
    return r;
}

nlohmann::json rule_to_json(const Rule& r) {
    nlohmann::json j = {
        {"direction", r.direction},
        {"protocol", r.protocol},
    };
    if (!r.description.empty()) j["description"] = r.description;
    if (!r.port.empty()) j["port"] = r.port;
    if (!r.source_ips.empty()) j["source_ips"] = r.source_ips;
    if (!r.destination_ips.empty()) j["destination_ips"] = r.destination_ips;
    return j;
}

bool rule_matches_inbound(const Rule& r, const std::string& proto, const std::string& port,
                          const std::string& cidr) {
    if (!util::iequals(r.direction, "in")) return false;
    if (!util::iequals(r.protocol, proto)) return false;
    if (!port.empty() && !r.port.empty() && r.port != port) return false;
    for (const auto& ip : r.source_ips) {
        if (normalize_cidr(ip) == normalize_cidr(cidr)) return true;
    }
    return false;
}

bool rule_exists(const std::vector<Rule>& rules, const std::string& proto,
                 const std::string& port, const std::string& cidr) {
    for (const auto& r : rules) {
        if (rule_matches_inbound(r, proto, port, cidr)) return true;
    }
    return false;
}

bool is_managed_rule(const Rule& r, const std::string& desc_prefix) {
    return !desc_prefix.empty() && r.description.rfind(desc_prefix, 0) == 0;
}

std::vector<Rule> remove_managed_inbound(const std::vector<Rule>& rules,
                                         const std::string& desc_prefix,
                                         const std::string& proto, const std::string& port,
                                         const std::string& cidr) {
    std::vector<Rule> out;
    for (const auto& r : rules) {
        if (is_managed_rule(r, desc_prefix) && rule_matches_inbound(r, proto, port, cidr)) {
            continue;
        }
        out.push_back(r);
    }
    return out;
}

}  // namespace

FirewallClient FirewallClient::create(const std::string& token, const std::string& firewall_id,
                                      const std::string& endpoint) {
    const auto id = std::stoll(util::trim(firewall_id));
    Client api(token);
    if (!endpoint.empty()) {
        api = Client(token, endpoint);
    }
    return FirewallClient(std::move(api), id);
}

FirewallClient::FirewallClient(Client api, int64_t firewall_id)
    : api_(std::move(api)), firewall_id_(firewall_id) {}

std::string FirewallClient::path() const {
    return "/firewalls/" + std::to_string(firewall_id_);
}

Firewall FirewallClient::get() {
    nlohmann::json resp;
    api_.do_request("GET", path(), nullptr, &resp);

    Firewall fw;
    if (!resp.contains("firewall")) return fw;
    const auto& j = resp["firewall"];
    fw.id = j.value("id", int64_t{0});
    fw.name = j.value("name", std::string{});
    if (j.contains("rules") && j["rules"].is_array()) {
        for (const auto& item : j["rules"]) fw.rules.push_back(rule_from_json(item));
    }
    return fw;
}

void FirewallClient::set_rules(const std::vector<Rule>& rules) {
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& r : rules) arr.push_back(rule_to_json(r));
    const nlohmann::json body{{"rules", arr}};
    api_.do_request("POST", path() + "/actions/set_rules", &body, nullptr);
}

void FirewallClient::upsert_inbound(const std::string& proto, const std::string& port,
                                    const std::string& cidr, const std::string& desc) {
    auto fw = get();
    const std::string norm_proto = normalize_protocol(proto);
    auto rules = fw.rules;

    if (rule_exists(rules, norm_proto, port, cidr)) return;

    Rule r;
    r.description = desc;
    r.direction = "in";
    r.protocol = norm_proto;
    r.port = port;
    r.source_ips = {cidr};
    rules.push_back(std::move(r));
    set_rules(rules);
}

void FirewallClient::remove_inbound(const std::string& proto, const std::string& port,
                                    const std::string& cidr, const std::string& desc_prefix) {
    auto fw = get();
    const std::string norm_proto = normalize_protocol(proto);
    const auto rules = remove_managed_inbound(fw.rules, desc_prefix, norm_proto, port, cidr);
    set_rules(rules);
}

}  // namespace firewallkeeper::hc_api

namespace firewallkeeper::backend {

namespace {

bool is_hetzner_cloud_duplicate(const std::exception& e) {
    if (const auto* api_err = dynamic_cast<const hc_api::APIError*>(&e)) {
        const auto msg = util::to_lower(api_err->message + " " + api_err->code);
        return util::contains_icase(msg, "duplicate") || util::contains_icase(msg, "already");
    }
    return false;
}

bool is_hetzner_cloud_not_found(const std::exception& e) {
    if (const auto* api_err = dynamic_cast<const hc_api::APIError*>(&e)) {
        return api_err->status == 404;
    }
    return false;
}

class HetznerCloudBackend : public IBackend {
public:
    HetznerCloudBackend(std::string name, hc_api::FirewallClient client, std::string desc_prefix)
        : name_(std::move(name)), client_(std::move(client)), desc_prefix_(std::move(desc_prefix)) {}

    std::string name() const override { return name_; }

    bool upsert_whitelist(const std::string& ip, const std::optional<std::string>& old_ip,
                          const config::Config& cfg, std::string& error) override {
        const auto cidr = ip::to_cidr(ip);
        return sync_whitelist_ports(
            ip, old_ip, cfg,
            [&](const std::string& port, std::string& err) {
                return upsert_rule(cfg.protocol, port, cidr, rule_description(cfg, port, 255), err);
            },
            [&](const std::string& port, std::string& err) {
                return remove_rule(cfg.protocol, port, ip::to_cidr(*old_ip), err);
            },
            error);
    }

private:
    bool upsert_rule(const std::string& proto, const std::string& port, const std::string& cidr,
                     const std::string& desc, std::string& error) {
        try {
            client_.upsert_inbound(proto, port, cidr, desc);
            log_added(name_, "已添加 Hetzner Cloud 防火墙规则: " + cidr + " " + proto + " " + port);
            return true;
        } catch (const std::exception& e) {
            if (is_hetzner_cloud_duplicate(e) || is_duplicate(e.what())) {
                log_skip_dup(name_, "防火墙规则已存在，跳过: " + cidr + " " + proto + " " + port);
                return true;
            }
            error = std::string("set_rules: ") + e.what();
            return false;
        }
    }

    bool remove_rule(const std::string& proto, const std::string& port, const std::string& cidr,
                     std::string& error) {
        try {
            client_.remove_inbound(proto, port, cidr, desc_prefix_);
            log_removed(name_, "已删除旧 Hetzner Cloud 防火墙规则: " + cidr + " " + proto + " " +
                                  port);
            return true;
        } catch (const std::exception& e) {
            if (is_hetzner_cloud_not_found(e) || is_not_found(e.what())) {
                log_skip_missing(name_, "旧防火墙规则不存在，跳过: " + cidr + " " + port);
                return true;
            }
            error = std::string("set_rules: ") + e.what();
            return false;
        }
    }

    std::string name_;
    hc_api::FirewallClient client_;
    std::string desc_prefix_;
};

}  // namespace

std::unique_ptr<IBackend> new_hetzner_cloud(const config::Target& t, const config::Config& cfg,
                                             std::string& error) {
    error.clear();
    try {
        auto client = hc_api::FirewallClient::create(t.secret_key, t.firewall_id, t.endpoint);
        return std::make_unique<HetznerCloudBackend>(t.name, std::move(client), cfg.rule_description);
    } catch (const std::exception& e) {
        error = e.what();
        return nullptr;
    }
}

}  // namespace firewallkeeper::backend
