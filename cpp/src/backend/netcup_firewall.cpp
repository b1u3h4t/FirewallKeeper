// Netcup 无官方 C++ SDK，REST 内联于本文件
#include "firewallkeeper/backend/backend.hpp"
#include "firewallkeeper/ip/ip.hpp"
#include "firewallkeeper/util/http.hpp"
#include "firewallkeeper/util/string_util.hpp"
#include <map>
#include <mutex>
#include <sstream>
#include <iostream>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace firewallkeeper::nc_api {


struct APIError : std::runtime_error {
    std::string code;
    std::string message;
    int status = 0;
    std::string body;

    APIError() : std::runtime_error("") {}

    const char* what() const noexcept override {
        static thread_local std::string msg;
        if (!message.empty()) {
            msg = code.empty() ? message : code + ": " + message;
        } else {
            msg = "HTTP " + std::to_string(status) + ": " + body;
        }
        return msg.c_str();
    }
};

class Client {
public:
    Client(std::string refresh_token, std::string access_token = "",
           std::string base_url = "https://www.servercontrolpanel.de/scp-core/api/v1");

    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    Client(Client&&) = default;
    Client& operator=(Client&&) = default;

    int current_user_id();
    void do_request(const std::string& method, const std::string& path,
                    const nlohmann::json* body, nlohmann::json* out);

private:
    struct TokenCache {
        std::mutex mu;
        std::string cached_token;
        std::chrono::steady_clock::time_point token_expiry{};
    };

    std::string bearer();

    std::string refresh_token_;
    std::string access_token_;
    std::string base_url_;
    util::HttpClient http_;
    std::shared_ptr<TokenCache> token_cache_;
};

struct Rule {
    std::string description;
    std::string direction;
    std::string protocol;
    std::string action;
    std::vector<std::string> sources;
    std::optional<std::string> source_ports;
    std::vector<std::string> destinations;
    std::optional<std::string> destination_ports;
};

struct FirewallPolicy {
    int id = 0;
    std::string name;
    std::string description;
    std::vector<Rule> rules;
};

class FirewallPolicyClient {
public:
    FirewallPolicyClient(std::string refresh_token, std::string access_token,
                         std::string base_url, int user_id, int policy_id);

    FirewallPolicy get();
    void update(const FirewallPolicy& policy);
    void upsert_ingress(const std::string& proto, const std::string& port,
                        const std::string& cidr, const std::string& desc);
    void remove_ingress(const std::string& proto, const std::string& port,
                        const std::string& cidr, const std::string& desc_prefix);

private:
    std::string path() const;

    Client api_;
    int user_id_;
    int policy_id_;
};

void reapply_server_firewall(Client& client, int server_id, const std::string& mac);
std::string first_interface_mac(Client& client, int server_id);
int parse_int_id(const std::string& s, const std::string& field);


namespace {

constexpr const char* kAuthURL =
    "https://www.servercontrolpanel.de/realms/scp/protocol/openid-connect";
constexpr const char* kClientID = "scp";

std::string form_encode(const std::map<std::string, std::string>& params) {
    static const char* hex = "0123456789ABCDEF";
    auto enc = [](std::string_view s) {
        static const char* h = "0123456789ABCDEF";
        std::string out;
        for (unsigned char c : s) {
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                c == '-' || c == '_' || c == '.' || c == '~') {
                out.push_back(static_cast<char>(c));
            } else {
                out.push_back('%');
                out.push_back(h[c >> 4]);
                out.push_back(h[c & 0x0F]);
            }
        }
        return out;
    };
    std::ostringstream oss;
    bool first = true;
    for (const auto& [k, v] : params) {
        if (!first) oss << '&';
        first = false;
        oss << enc(k) << '=' << enc(v);
    }
    return oss.str();
}

}  // namespace

std::string refresh_access_token(const std::string& refresh_token) {
    util::HttpClient http;
    util::HttpRequest req;
    req.method = "POST";
    req.url = std::string(kAuthURL) + "/token";
    req.body = form_encode({{"client_id", kClientID},
                            {"grant_type", "refresh_token"},
                            {"refresh_token", refresh_token}});
    req.headers = {{"Content-Type", "application/x-www-form-urlencoded"}};

    const auto resp = http.request(req);
    if (resp.status != 200) {
        throw std::runtime_error("token refresh failed: HTTP " + std::to_string(resp.status) +
                                 ": " + util::truncate_str(resp.body, 256));
    }

    const auto j = nlohmann::json::parse(resp.body);
    const std::string token = j.value("access_token", std::string{});
    if (token.empty()) throw std::runtime_error("token refresh: empty access_token");
    return token;
}

int fetch_current_user_id(const std::string& access_token) {
    util::HttpClient http;
    util::HttpRequest req;
    req.method = "GET";
    req.url = std::string(kAuthURL) + "/userinfo";
    req.headers = {{"Authorization", "Bearer " + access_token}, {"Accept", "application/json"}};

    const auto resp = http.request(req);
    if (resp.status != 200) {
        throw std::runtime_error("userinfo failed: HTTP " + std::to_string(resp.status) + ": " +
                                 util::truncate_str(resp.body, 256));
    }

    const auto j = nlohmann::json::parse(resp.body);
    if (j.contains("id") && j["id"].is_number_integer()) return j["id"].get<int>();
    const std::string sub = j.value("sub", std::string{});
    if (!sub.empty()) {
        try {
            const int id = std::stoi(sub);
            if (id > 0) return id;
        } catch (...) {
        }
    }
    throw std::runtime_error("userinfo: missing user id");
}

Client::Client(std::string refresh_token, std::string access_token, std::string base_url)
    : refresh_token_(util::trim(std::move(refresh_token))),
      access_token_(util::trim(std::move(access_token))),
      base_url_(std::move(base_url)),
      token_cache_(std::make_shared<TokenCache>()) {
    while (!base_url_.empty() && base_url_.back() == '/') base_url_.pop_back();
}

std::string Client::bearer() {
    if (!access_token_.empty()) return access_token_;
    if (refresh_token_.empty()) throw std::runtime_error("需要 refresh_token 或 access_token");

    std::lock_guard lock(token_cache_->mu);
    if (!token_cache_->cached_token.empty() &&
        std::chrono::steady_clock::now() < token_cache_->token_expiry) {
        return token_cache_->cached_token;
    }
    token_cache_->cached_token = refresh_access_token(refresh_token_);
    token_cache_->token_expiry = std::chrono::steady_clock::now() + std::chrono::minutes(4);
    return token_cache_->cached_token;
}

int Client::current_user_id() { return fetch_current_user_id(bearer()); }

void Client::do_request(const std::string& method, const std::string& path,
                        const nlohmann::json* body, nlohmann::json* out) {
    const std::string token = bearer();

    util::HttpRequest req;
    req.method = method;
    req.url = path.front() == '/' ? base_url_ + path : base_url_ + "/" + path;
    req.timeout_seconds = 60;
    req.headers = {{"Authorization", "Bearer " + token}, {"Accept", "application/json"}};

    if (body != nullptr) {
        req.body = body->dump();
        req.headers["Content-Type"] = "application/json";
    }

    const auto resp = http_.request(req);

    if (resp.status < 200 || resp.status >= 300) {
        APIError err;
        try {
            const auto j = nlohmann::json::parse(resp.body);
            err.code = j.value("code", std::string{});
            err.message = j.value("message", std::string{});
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
    if (p == "TCP" || p == "UDP" || p == "ICMP") return p;
    if (p == "ICMPV6") return "ICMPv6";
    return "TCP";
}

std::string format_port(std::string port) { return util::trim(port); }

std::optional<std::string> port_ptr(const std::string& s) {
    if (s.empty()) return std::nullopt;
    return s;
}

bool source_contains(const std::vector<std::string>& sources, const std::string& cidr) {
    const auto want = util::trim(cidr);
    for (const auto& s : sources) {
        if (util::trim(s) == want) return true;
    }
    return false;
}

bool port_equal(const std::optional<std::string>& dst, const std::string& want) {
    if (!dst.has_value() && want.empty()) return true;
    if (!dst.has_value()) return false;
    return *dst == want;
}

bool rule_matches(const Rule& r, const std::string& proto, const std::string& port,
                  const std::string& cidr) {
    if (!util::iequals(r.direction, "INGRESS") || !util::iequals(r.action, "ACCEPT")) return false;
    if (!util::iequals(r.protocol, proto)) return false;
    if (!port_equal(r.destination_ports, port)) return false;
    return source_contains(r.sources, cidr);
}

bool rule_exists(const std::vector<Rule>& rules, const std::string& proto,
                 const std::string& port, const std::string& cidr) {
    for (const auto& r : rules) {
        if (rule_matches(r, proto, port, cidr)) return true;
    }
    return false;
}

bool rule_matches_managed(const Rule& r, const std::string& desc_prefix,
                          const std::string& proto, const std::string& port,
                          const std::string& cidr) {
    if (!desc_prefix.empty() && r.description.rfind(desc_prefix, 0) != 0) return false;
    return rule_matches(r, proto, port, cidr);
}

Rule rule_from_json(const nlohmann::json& j) {
    Rule r;
    r.description = j.value("description", std::string{});
    r.direction = j.value("direction", std::string{});
    r.protocol = j.value("protocol", std::string{});
    r.action = j.value("action", std::string{});
    if (j.contains("sources") && j["sources"].is_array()) {
        for (const auto& s : j["sources"]) {
            if (s.is_string()) r.sources.push_back(s.get<std::string>());
        }
    }
    if (j.contains("destinations") && j["destinations"].is_array()) {
        for (const auto& d : j["destinations"]) {
            if (d.is_string()) r.destinations.push_back(d.get<std::string>());
        }
    }
    if (j.contains("sourcePorts") && !j["sourcePorts"].is_null()) {
        r.source_ports = j["sourcePorts"].get<std::string>();
    }
    if (j.contains("destinationPorts") && !j["destinationPorts"].is_null()) {
        r.destination_ports = j["destinationPorts"].get<std::string>();
    }
    return r;
}

nlohmann::json rule_to_json(const Rule& r) {
    nlohmann::json j = {
        {"direction", r.direction},
        {"protocol", r.protocol},
        {"action", r.action},
    };
    if (!r.description.empty()) j["description"] = r.description;
    if (!r.sources.empty()) j["sources"] = r.sources;
    if (!r.destinations.empty()) j["destinations"] = r.destinations;
    if (r.source_ports.has_value()) j["sourcePorts"] = *r.source_ports;
    if (r.destination_ports.has_value()) j["destinationPorts"] = *r.destination_ports;
    return j;
}

}  // namespace

FirewallPolicyClient::FirewallPolicyClient(std::string refresh_token, std::string access_token,
                                           std::string base_url, int user_id, int policy_id)
    : api_(std::move(refresh_token), std::move(access_token), std::move(base_url)),
      user_id_(user_id),
      policy_id_(policy_id) {}

std::string FirewallPolicyClient::path() const {
    return "/users/" + std::to_string(user_id_) + "/firewall-policies/" +
           std::to_string(policy_id_);
}

FirewallPolicy FirewallPolicyClient::get() {
    nlohmann::json resp;
    api_.do_request("GET", path(), nullptr, &resp);

    FirewallPolicy policy;
    policy.id = resp.value("id", 0);
    policy.name = resp.value("name", std::string{});
    policy.description = resp.value("description", std::string{});
    if (resp.contains("rules") && resp["rules"].is_array()) {
        for (const auto& item : resp["rules"]) policy.rules.push_back(rule_from_json(item));
    }
    return policy;
}

void FirewallPolicyClient::update(const FirewallPolicy& policy) {
    nlohmann::json body = {{"name", policy.name}, {"rules", nlohmann::json::array()}};
    if (!policy.description.empty()) body["description"] = policy.description;
    for (const auto& r : policy.rules) body["rules"].push_back(rule_to_json(r));
    api_.do_request("PUT", path(), &body, nullptr);
}

void FirewallPolicyClient::upsert_ingress(const std::string& proto, const std::string& port,
                                          const std::string& cidr, const std::string& desc) {
    auto policy = get();
    const std::string norm_proto = normalize_protocol(proto);
    const std::string port_str = format_port(port);

    if (rule_exists(policy.rules, norm_proto, port_str, cidr)) return;

    Rule r;
    r.description = desc;
    r.direction = "INGRESS";
    r.protocol = norm_proto;
    r.action = "ACCEPT";
    r.sources = {cidr};
    r.destination_ports = port_ptr(port_str);
    policy.rules.push_back(std::move(r));
    update(policy);
}

void FirewallPolicyClient::remove_ingress(const std::string& proto, const std::string& port,
                                          const std::string& cidr,
                                          const std::string& desc_prefix) {
    auto policy = get();
    const std::string norm_proto = normalize_protocol(proto);
    const std::string port_str = format_port(port);

    std::vector<Rule> kept;
    for (const auto& r : policy.rules) {
        if (rule_matches_managed(r, desc_prefix, norm_proto, port_str, cidr)) continue;
        kept.push_back(r);
    }
    if (kept.size() == policy.rules.size()) {
        APIError err;
        err.status = 404;
        err.message = "no matching firewall rule";
        err.code = "not_found";
        throw err;
    }
    policy.rules = std::move(kept);
    update(policy);
}

void reapply_server_firewall(Client& client, int server_id, const std::string& mac) {
    const std::string path =
        "/servers/" + std::to_string(server_id) + "/interfaces/" + mac + "/firewall:reapply";
    client.do_request("POST", path, nullptr, nullptr);
}

std::string first_interface_mac(Client& client, int server_id) {
    const std::string path = "/servers/" + std::to_string(server_id) + "/interfaces?loadRdns=false";
    nlohmann::json resp;
    client.do_request("GET", path, nullptr, &resp);
    if (!resp.is_array() || resp.empty()) {
        throw std::runtime_error("服务器 " + std::to_string(server_id) + " 无网卡接口");
    }
    return resp[0].value("mac", std::string{});
}

int parse_int_id(const std::string& s, const std::string& field) {
    const auto t = util::trim(s);
    if (t.empty()) throw std::runtime_error("empty " + field);
    try {
        return std::stoi(t);
    } catch (const std::exception& e) {
        throw std::runtime_error("无效 " + field + " \"" + s + "\": " + e.what());
    }
}

}  // namespace firewallkeeper::nc_api

namespace firewallkeeper::backend {

namespace {

bool is_netcup_duplicate(const std::exception& e) {
    if (const auto* api_err = dynamic_cast<const nc_api::APIError*>(&e)) {
        const auto msg = util::to_lower(api_err->code + " " + api_err->message);
        return util::contains_icase(msg, "duplicate") || util::contains_icase(msg, "already") ||
               util::contains_icase(msg, "exist");
    }
    return false;
}

bool is_netcup_not_found(const std::exception& e) {
    if (const auto* api_err = dynamic_cast<const nc_api::APIError*>(&e)) {
        return api_err->status == 404 || api_err->code == "not_found";
    }
    return false;
}

class NetcupFirewallBackend : public IBackend {
public:
    NetcupFirewallBackend(std::string name, nc_api::Client api, nc_api::FirewallPolicyClient client,
                          int server_id, std::string interface_mac, std::string desc_prefix)
        : name_(std::move(name)),
          api_(std::move(api)),
          client_(std::move(client)),
          server_id_(server_id),
          interface_mac_(std::move(interface_mac)),
          desc_prefix_(std::move(desc_prefix)) {}

    std::string name() const override { return name_; }

    bool upsert_whitelist(const std::string& ip, const std::optional<std::string>& old_ip,
                          const config::Config& cfg, std::string& error) override {
        const auto cidr = ip::to_cidr(ip);
        const auto proto = cfg.protocol;
        if (!sync_whitelist_ports(
                ip, old_ip, cfg,
                [&](const std::string& port, std::string& err) {
                    return upsert_rule(proto, port, cidr, rule_description(cfg, port, 255), err);
                },
                [&](const std::string& port, std::string& err) {
                    return remove_rule(proto, port, ip::to_cidr(*old_ip), err);
                },
                error)) {
            return false;
        }
        return reapply_if_configured(error);
    }

private:
    bool upsert_rule(const std::string& proto, const std::string& port, const std::string& cidr,
                     const std::string& desc, std::string& error) {
        try {
            client_.upsert_ingress(proto, port, cidr, desc);
            std::cout << "[" << name_ << "] 已添加 Netcup SCP 防火墙规则: " << cidr << " " << proto
                      << " " << port << '\n';
            return true;
        } catch (const std::exception& e) {
            if (is_netcup_duplicate(e) || is_duplicate(e.what())) {
                std::cout << "[" << name_ << "] 防火墙规则已存在，跳过: " << cidr << " " << proto
                          << " " << port << '\n';
                return true;
            }
            error = std::string("update firewall policy: ") + e.what();
            return false;
        }
    }

    bool remove_rule(const std::string& proto, const std::string& port, const std::string& cidr,
                     std::string& error) {
        try {
            client_.remove_ingress(proto, port, cidr, desc_prefix_);
            std::cout << "[" << name_ << "] 已删除旧 Netcup SCP 防火墙规则: " << cidr << " " << proto
                      << " " << port << '\n';
            return true;
        } catch (const std::exception& e) {
            if (is_netcup_not_found(e) || is_not_found(e.what())) {
                std::cout << "[" << name_ << "] 旧防火墙规则不存在，跳过: " << cidr << " " << port
                          << '\n';
                return true;
            }
            error = std::string("update firewall policy: ") + e.what();
            return false;
        }
    }

    bool reapply_if_configured(std::string& error) {
        if (server_id_ == 0) return true;

        try {
            auto mac = interface_mac_;
            if (mac.empty()) {
                try {
                    mac = nc_api::first_interface_mac(api_, server_id_);
                } catch (const std::exception& e) {
                    error = std::string("获取 interface_mac: ") + e.what();
                    return false;
                }
            }
            nc_api::reapply_server_firewall(api_, server_id_, mac);
            std::cout << "[" << name_ << "] 已在服务器 " << server_id_ << " 网卡 " << mac
                      << " 上重新应用防火墙\n";
            return true;
        } catch (const std::exception& e) {
            error = std::string("firewall reapply: ") + e.what();
            return false;
        }
    }

    std::string name_;
    nc_api::Client api_;
    nc_api::FirewallPolicyClient client_;
    int server_id_ = 0;
    std::string interface_mac_;
    std::string desc_prefix_;
};

}  // namespace

std::unique_ptr<IBackend> new_netcup_firewall(const config::Target& t, const config::Config& cfg,
                                              std::string& error) {
    error.clear();
    try {
        const auto policy_id_str = util::first_non_empty({t.firewall_id, t.security_group_id});
        const int policy_id = nc_api::parse_int_id(policy_id_str, "firewall_policy_id");

        nc_api::Client api(t.refresh_token, t.api_token, t.endpoint);

        int user_id = 0;
        if (!util::trim(t.user_id).empty()) {
            user_id = nc_api::parse_int_id(t.user_id, "user_id");
        } else {
            try {
                user_id = api.current_user_id();
            } catch (const std::exception& e) {
                error = std::string("获取 user_id: ") + e.what() + "（请在配置中填写 user_id）";
                return nullptr;
            }
        }

        nc_api::FirewallPolicyClient client(t.refresh_token, t.api_token, t.endpoint, user_id,
                                               policy_id);

        int server_id = 0;
        if (!t.instance_id.empty()) {
            server_id = nc_api::parse_int_id(t.instance_id, "server_id");
        }

        return std::make_unique<NetcupFirewallBackend>(t.name, std::move(api), std::move(client),
                                                       server_id, util::trim(t.interface_mac),
                                                       cfg.rule_description);
    } catch (const std::exception& e) {
        error = e.what();
        return nullptr;
    }
}

}  // namespace firewallkeeper::backend
