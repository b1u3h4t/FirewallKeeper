// Hetzner Robot 无官方 C++ SDK，REST 内联于本文件
#include "firewallkeeper/backend/backend.hpp"
#include "firewallkeeper/ip/ip.hpp"
#include "firewallkeeper/util/http.hpp"
#include "firewallkeeper/util/string_util.hpp"
#include <map>
#include <sstream>
#include <iostream>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace firewallkeeper::hr_api {


struct APIError : std::runtime_error {
    int api_status = 0;
    std::string code;
    std::string message;
    int http = 0;
    std::string body;

    APIError() : std::runtime_error("") {}

    const char* what() const noexcept override {
        static thread_local std::string msg;
        if (!code.empty()) {
            msg = code + ": " + message;
        } else {
            msg = "HTTP " + std::to_string(http) + ": " + body;
        }
        return msg.c_str();
    }
};

class Client {
public:
    Client(std::string user, std::string password,
           std::string base_url = "https://robot-ws.your-server.de");

    void do_request(const std::string& method, const std::string& path,
                    const std::map<std::string, std::string>* form, nlohmann::json* out);

private:
    std::string basic_auth_header() const;
    std::string url_encode_form(const std::map<std::string, std::string>& form) const;

    std::string user_;
    std::string password_;
    std::string base_url_;
    util::HttpClient http_;
};

struct InputRule {
    std::string name;
    std::string ip_version;
    std::optional<std::string> src_ip;
    std::optional<std::string> dst_ip;
    std::optional<std::string> dst_port;
    std::optional<std::string> src_port;
    std::optional<std::string> protocol;
    std::optional<std::string> tcp_flags;
    std::string action;
};

struct OutputRule {
    std::string name;
    std::optional<std::string> ip_version;
    std::optional<std::string> src_ip;
    std::optional<std::string> dst_ip;
    std::optional<std::string> dst_port;
    std::optional<std::string> src_port;
    std::optional<std::string> protocol;
    std::optional<std::string> tcp_flags;
    std::string action;
};

struct Rules {
    std::vector<InputRule> input;
    std::vector<OutputRule> output;
};

struct Firewall {
    std::string server_ip;
    int server_number = 0;
    std::string status;
    bool filter_ipv6 = false;
    bool whitelist_hos = false;
    std::string port;
    Rules rules;
};

class FirewallClient {
public:
    FirewallClient(std::string user, std::string password, std::string base_url,
                   std::string server_number);

    Firewall get();
    void apply(const Firewall& fw);
    void upsert_inbound(const std::string& proto, const std::string& port,
                        const std::string& cidr, const std::string& rule_name);
    void remove_inbound(const std::string& proto, const std::string& port,
                        const std::string& cidr, const std::string& name_prefix);

private:
    std::string path() const;

    Client api_;
    std::string server_number_;
};


Client::Client(std::string user, std::string password, std::string base_url)
    : user_(std::move(user)),
      password_(std::move(password)),
      base_url_(std::move(base_url)) {
    while (!base_url_.empty() && base_url_.back() == '/') base_url_.pop_back();
}

namespace {

std::string base64_encode(std::string_view data) {
    static const char* table =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string encoded;
    encoded.reserve(((data.size() + 2) / 3) * 4);
    for (size_t i = 0; i < data.size(); i += 3) {
        uint32_t n = static_cast<uint32_t>(static_cast<unsigned char>(data[i])) << 16;
        if (i + 1 < data.size()) n |= static_cast<uint32_t>(static_cast<unsigned char>(data[i + 1])) << 8;
        if (i + 2 < data.size()) n |= static_cast<uint32_t>(static_cast<unsigned char>(data[i + 2]));
        encoded.push_back(table[(n >> 18) & 63]);
        encoded.push_back(table[(n >> 12) & 63]);
        encoded.push_back(i + 1 < data.size() ? table[(n >> 6) & 63] : '=');
        encoded.push_back(i + 2 < data.size() ? table[n & 63] : '=');
    }
    return encoded;
}

std::string percent_encode_form(std::string_view s) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : s) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(hex[c >> 4]);
            out.push_back(hex[c & 0x0F]);
        }
    }
    return out;
}

}  // namespace

std::string Client::url_encode_form(const std::map<std::string, std::string>& form) const {
    std::ostringstream oss;
    bool first = true;
    for (const auto& [k, v] : form) {
        if (!first) oss << '&';
        first = false;
        oss << percent_encode_form(k) << '=' << percent_encode_form(v);
    }
    return oss.str();
}

void Client::do_request(const std::string& method, const std::string& path,
                        const std::map<std::string, std::string>* form, nlohmann::json* out) {
    util::HttpRequest req;
    req.method = method;
    req.url = base_url_ + path;
    req.timeout_seconds = 60;
    req.headers = {{"Authorization", "Basic " + base64_encode(user_ + ":" + password_)}};

    if (form != nullptr) {
        req.body = url_encode_form(*form);
        req.headers["Content-Type"] = "application/x-www-form-urlencoded";
    }

    const auto resp = http_.request(req);

    if (resp.status < 200 || resp.status >= 300) {
        APIError err;
        try {
            const auto j = nlohmann::json::parse(resp.body);
            if (j.contains("error")) {
                err.api_status = j["error"].value("status", 0);
                err.code = j["error"].value("code", std::string{});
                err.message = j["error"].value("message", std::string{});
            }
        } catch (...) {
        }
        err.http = static_cast<int>(resp.status);
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
    if (p == "tcp" || p == "udp" || p == "icmp" || p == "gre" || p == "esp") return p;
    return "tcp";
}

std::string normalize_cidr(std::string s) { return util::trim(s); }

InputRule input_from_json(const nlohmann::json& j) {
    InputRule r;
    r.name = j.value("name", std::string{});
    r.ip_version = j.value("ip_version", std::string{});
    r.action = j.value("action", std::string{});
    if (j.contains("src_ip") && !j["src_ip"].is_null())
        r.src_ip = j["src_ip"].get<std::string>();
    if (j.contains("dst_ip") && !j["dst_ip"].is_null())
        r.dst_ip = j["dst_ip"].get<std::string>();
    if (j.contains("dst_port") && !j["dst_port"].is_null())
        r.dst_port = j["dst_port"].get<std::string>();
    if (j.contains("src_port") && !j["src_port"].is_null())
        r.src_port = j["src_port"].get<std::string>();
    if (j.contains("protocol") && !j["protocol"].is_null())
        r.protocol = j["protocol"].get<std::string>();
    if (j.contains("tcp_flags") && !j["tcp_flags"].is_null())
        r.tcp_flags = j["tcp_flags"].get<std::string>();
    return r;
}

OutputRule output_from_json(const nlohmann::json& j) {
    OutputRule r;
    r.name = j.value("name", std::string{});
    r.action = j.value("action", std::string{});
    if (j.contains("ip_version") && !j["ip_version"].is_null())
        r.ip_version = j["ip_version"].get<std::string>();
    if (j.contains("src_ip") && !j["src_ip"].is_null())
        r.src_ip = j["src_ip"].get<std::string>();
    if (j.contains("dst_ip") && !j["dst_ip"].is_null())
        r.dst_ip = j["dst_ip"].get<std::string>();
    if (j.contains("dst_port") && !j["dst_port"].is_null())
        r.dst_port = j["dst_port"].get<std::string>();
    if (j.contains("src_port") && !j["src_port"].is_null())
        r.src_port = j["src_port"].get<std::string>();
    if (j.contains("protocol") && !j["protocol"].is_null())
        r.protocol = j["protocol"].get<std::string>();
    if (j.contains("tcp_flags") && !j["tcp_flags"].is_null())
        r.tcp_flags = j["tcp_flags"].get<std::string>();
    return r;
}

void set_input_rule(std::map<std::string, std::string>& form, const std::string& prefix,
                    const InputRule& r) {
    form[prefix + "[name]"] = r.name;
    if (!r.ip_version.empty()) form[prefix + "[ip_version]"] = r.ip_version;
    if (r.src_ip && !r.src_ip->empty()) form[prefix + "[src_ip]"] = *r.src_ip;
    if (r.dst_ip && !r.dst_ip->empty()) form[prefix + "[dst_ip]"] = *r.dst_ip;
    if (r.dst_port && !r.dst_port->empty()) form[prefix + "[dst_port]"] = *r.dst_port;
    if (r.src_port && !r.src_port->empty()) form[prefix + "[src_port]"] = *r.src_port;
    if (r.protocol && !r.protocol->empty()) form[prefix + "[protocol]"] = *r.protocol;
    if (r.tcp_flags && !r.tcp_flags->empty()) form[prefix + "[tcp_flags]"] = *r.tcp_flags;
    form[prefix + "[action]"] = r.action;
}

void set_output_rule(std::map<std::string, std::string>& form, const std::string& prefix,
                     const OutputRule& r) {
    form[prefix + "[name]"] = r.name;
    if (r.ip_version && !r.ip_version->empty()) form[prefix + "[ip_version]"] = *r.ip_version;
    if (r.src_ip && !r.src_ip->empty()) form[prefix + "[src_ip]"] = *r.src_ip;
    if (r.dst_ip && !r.dst_ip->empty()) form[prefix + "[dst_ip]"] = *r.dst_ip;
    if (r.dst_port && !r.dst_port->empty()) form[prefix + "[dst_port]"] = *r.dst_port;
    if (r.src_port && !r.src_port->empty()) form[prefix + "[src_port]"] = *r.src_port;
    if (r.protocol && !r.protocol->empty()) form[prefix + "[protocol]"] = *r.protocol;
    if (r.tcp_flags && !r.tcp_flags->empty()) form[prefix + "[tcp_flags]"] = *r.tcp_flags;
    form[prefix + "[action]"] = r.action;
}

std::map<std::string, std::string> build_form(const Firewall& fw) {
    std::map<std::string, std::string> form;
    form["status"] = (fw.status == "disabled") ? "disabled" : "active";
    form["filter_ipv6"] = fw.filter_ipv6 ? "true" : "false";
    form["whitelist_hos"] = fw.whitelist_hos ? "true" : "false";

    for (size_t i = 0; i < fw.rules.input.size(); ++i) {
        set_input_rule(form, "rules[input][" + std::to_string(i) + "]", fw.rules.input[i]);
    }
    for (size_t i = 0; i < fw.rules.output.size(); ++i) {
        set_output_rule(form, "rules[output][" + std::to_string(i) + "]", fw.rules.output[i]);
    }
    return form;
}

bool input_rule_matches(const InputRule& r, const std::string& rule_name,
                        const std::string& proto, const std::string& port,
                        const std::string& cidr) {
    if (!rule_name.empty() && r.name != rule_name) return false;
    if (!r.src_ip || normalize_cidr(*r.src_ip) != normalize_cidr(cidr)) return false;
    if (!r.dst_port || *r.dst_port != port) return false;
    if (r.protocol && !r.protocol->empty() && !util::iequals(*r.protocol, proto)) return false;
    return util::iequals(r.action, "accept");
}

bool input_rule_matches_managed(const InputRule& r, const std::string& name_prefix,
                                const std::string& proto, const std::string& port,
                                const std::string& cidr) {
    if (!name_prefix.empty() && r.name.rfind(name_prefix, 0) != 0) return false;
    return input_rule_matches(r, "", proto, port, cidr);
}

}  // namespace

FirewallClient::FirewallClient(std::string user, std::string password, std::string base_url,
                               std::string server_number)
    : api_(std::move(user), std::move(password), std::move(base_url)),
      server_number_(util::trim(server_number)) {}

std::string FirewallClient::path() const { return "/firewall/" + server_number_; }

Firewall FirewallClient::get() {
    nlohmann::json resp;
    api_.do_request("GET", path(), nullptr, &resp);

    Firewall fw;
    if (!resp.contains("firewall")) return fw;
    const auto& j = resp["firewall"];
    fw.server_ip = j.value("server_ip", std::string{});
    fw.server_number = j.value("server_number", 0);
    fw.status = j.value("status", std::string{});
    fw.filter_ipv6 = j.value("filter_ipv6", false);
    fw.whitelist_hos = j.value("whitelist_hos", false);
    fw.port = j.value("port", std::string{});
    if (j.contains("rules")) {
        if (j["rules"].contains("input") && j["rules"]["input"].is_array()) {
            for (const auto& item : j["rules"]["input"]) {
                fw.rules.input.push_back(input_from_json(item));
            }
        }
        if (j["rules"].contains("output") && j["rules"]["output"].is_array()) {
            for (const auto& item : j["rules"]["output"]) {
                fw.rules.output.push_back(output_from_json(item));
            }
        }
    }
    return fw;
}

void FirewallClient::apply(const Firewall& fw) {
    const auto form = build_form(fw);
    api_.do_request("POST", path(), &form, nullptr);
}

void FirewallClient::upsert_inbound(const std::string& proto, const std::string& port,
                                    const std::string& cidr, const std::string& rule_name) {
    auto fw = get();
    const std::string norm_proto = normalize_protocol(proto);

    for (const auto& r : fw.rules.input) {
        if (input_rule_matches(r, rule_name, norm_proto, port, cidr)) return;
    }

    InputRule rule;
    rule.name = rule_name;
    rule.ip_version = "ipv4";
    rule.src_ip = cidr;
    rule.dst_port = port;
    rule.protocol = norm_proto;
    rule.action = "accept";
    fw.rules.input.push_back(std::move(rule));

    if (fw.status.empty() || fw.status == "disabled") fw.status = "active";
    apply(fw);
}

void FirewallClient::remove_inbound(const std::string& proto, const std::string& port,
                                    const std::string& cidr, const std::string& name_prefix) {
    auto fw = get();
    const std::string norm_proto = normalize_protocol(proto);

    std::vector<InputRule> kept;
    for (const auto& r : fw.rules.input) {
        if (input_rule_matches_managed(r, name_prefix, norm_proto, port, cidr)) continue;
        kept.push_back(r);
    }
    fw.rules.input = std::move(kept);
    apply(fw);
}

}  // namespace firewallkeeper::hr_api

namespace firewallkeeper::backend {

namespace {

bool is_hetzner_robot_in_process(const std::exception& e) {
    if (const auto* api_err = dynamic_cast<const hr_api::APIError*>(&e)) {
        return api_err->code == "FIREWALL_IN_PROCESS";
    }
    return false;
}

bool is_hetzner_robot_rule_limit(const std::exception& e) {
    if (const auto* api_err = dynamic_cast<const hr_api::APIError*>(&e)) {
        return api_err->code == "FIREWALL_RULE_LIMIT_EXCEEDED";
    }
    return false;
}

class HetznerRobotBackend : public IBackend {
public:
    HetznerRobotBackend(std::string name, hr_api::FirewallClient client, std::string desc_prefix)
        : name_(std::move(name)), client_(std::move(client)), desc_prefix_(std::move(desc_prefix)) {}

    std::string name() const override { return name_; }

    bool upsert_whitelist(const std::string& ip, const std::optional<std::string>& old_ip,
                          const config::Config& cfg, std::string& error) override {
        const auto cidr = ip::to_cidr(ip);
        return sync_whitelist_ports(
            ip, old_ip, cfg,
            [&](const std::string& port, std::string& err) {
                return upsert_rule(cfg.protocol, port, cidr, rule_description(cfg, port, 64), err);
            },
            [&](const std::string& port, std::string& err) {
                return remove_rule(cfg.protocol, port, ip::to_cidr(*old_ip), err);
            },
            error);
    }

private:
    bool upsert_rule(const std::string& proto, const std::string& port, const std::string& cidr,
                     const std::string& rule_name, std::string& error) {
        try {
            client_.upsert_inbound(proto, port, cidr, rule_name);
            std::cout << "[" << name_ << "] 已添加 Hetzner Robot 防火墙规则: " << cidr << " "
                      << proto << " " << port << '\n';
            return true;
        } catch (const std::exception& e) {
            if (is_hetzner_robot_in_process(e)) {
                error = std::string("防火墙正在更新中，请稍后重试: ") + e.what();
                return false;
            }
            if (is_hetzner_robot_rule_limit(e)) {
                error = std::string("Robot 防火墙入站规则已达上限(10条): ") + e.what();
                return false;
            }
            if (is_duplicate(e.what())) {
                std::cout << "[" << name_ << "] 防火墙规则已存在，跳过: " << cidr << " " << proto
                          << " " << port << '\n';
                return true;
            }
            error = std::string("POST firewall: ") + e.what();
            return false;
        }
    }

    bool remove_rule(const std::string& proto, const std::string& port, const std::string& cidr,
                     std::string& error) {
        try {
            client_.remove_inbound(proto, port, cidr, desc_prefix_);
            std::cout << "[" << name_ << "] 已删除旧 Hetzner Robot 防火墙规则: " << cidr << " "
                      << proto << " " << port << '\n';
            return true;
        } catch (const std::exception& e) {
            if (is_hetzner_robot_in_process(e)) {
                error = std::string("防火墙正在更新中，请稍后重试: ") + e.what();
                return false;
            }
            if (is_not_found(e.what())) {
                std::cout << "[" << name_ << "] 旧防火墙规则不存在，跳过: " << cidr << " " << port
                          << '\n';
                return true;
            }
            error = std::string("POST firewall: ") + e.what();
            return false;
        }
    }

    std::string name_;
    hr_api::FirewallClient client_;
    std::string desc_prefix_;
};

}  // namespace

std::unique_ptr<IBackend> new_hetzner_robot(const config::Target& t, const config::Config& cfg,
                                            std::string& error) {
    error.clear();
    const auto user = util::first_non_empty({t.robot_user, t.access_key_id});
    const auto pass = util::first_non_empty({t.robot_password, t.access_key_secret});
    const auto server_num = util::first_non_empty({t.instance_id, t.server_number});
    if (server_num.empty()) {
        error = "需要 server_number 或 instance_id";
        return nullptr;
    }
    return std::make_unique<HetznerRobotBackend>(
        t.name, hr_api::FirewallClient(user, pass, t.endpoint, server_num),
        cfg.rule_description);
}

}  // namespace firewallkeeper::backend
