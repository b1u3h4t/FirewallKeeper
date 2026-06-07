#include "firewallkeeper/backend/backend.hpp"

#include "firewallkeeper/ip/ip.hpp"
#include "firewallkeeper/util/string_util.hpp"

#include "volcengine/core/VolcengineClientConfig.h"
#include "volcengine/vpc/VpcClient.h"
#include "volcengine/vpc/model/AuthorizeSecurityGroupIngressRequest.h"
#include "volcengine/vpc/model/RevokeSecurityGroupIngressRequest.h"

#include <iostream>
#include <memory>
#include <utility>

namespace firewallkeeper::backend {

namespace {

using volcengine::VolcengineClientConfig;
using volcengine::vpc::AuthorizeSecurityGroupIngressRequest;
using volcengine::vpc::RevokeSecurityGroupIngressRequest;
using volcengine::vpc::VpcClient;

std::string normalize_proto(std::string p) {
    p = util::to_lower(util::trim(p));
    if (p == "tcp" || p == "udp" || p == "icmp" || p == "icmpv6" || p == "all") return p;
    return "tcp";
}

std::pair<int, int> parse_port(const std::string& port_str) {
    auto p = util::trim(port_str);
    if (p.empty()) throw std::runtime_error("empty port");
    if (auto dash = p.find('-'); dash != std::string::npos) {
        return {std::stoi(util::trim(p.substr(0, dash))), std::stoi(util::trim(p.substr(dash + 1)))};
    }
    const int n = std::stoi(p);
    return {n, n};
}

class VolcengineSgBackend : public IBackend {
public:
    VolcengineSgBackend(std::string name, std::shared_ptr<VpcClient> client,
                        std::string security_group_id)
        : name_(std::move(name)),
          client_(std::move(client)),
          security_group_id_(std::move(security_group_id)) {}

    std::string name() const override { return name_; }

    bool upsert_whitelist(const std::string& ip, const std::optional<std::string>& old_ip,
                          const config::Config& cfg, std::string& error) override {
        const auto cidr = ip::to_cidr(ip);
        const auto proto = cfg.protocol;
        return sync_whitelist_ports(
            ip, old_ip, cfg,
            [&](const std::string& port_str, std::string& err) {
                try {
                    const auto [start, end] = parse_port(port_str);
                    return authorize(proto, start, end, cidr, rule_description(cfg, port_str, 255),
                                     port_str, err);
                } catch (const std::exception& e) {
                    err = "无效端口 \"" + port_str + "\": " + e.what();
                    return false;
                }
            },
            [&](const std::string& port_str, std::string& err) {
                try {
                    const auto [start, end] = parse_port(port_str);
                    return revoke(proto, start, end, ip::to_cidr(*old_ip), port_str, err);
                } catch (const std::exception& e) {
                    err = "无效端口 \"" + port_str + "\": " + e.what();
                    return false;
                }
            },
            error);
    }

private:
    bool authorize(const std::string& proto, int port_start, int port_end, const std::string& cidr,
                   const std::string& desc, const std::string& port_str, std::string& error) {
        AuthorizeSecurityGroupIngressRequest input;
        input.setSecurityGroupId(security_group_id_);
        input.setProtocol(normalize_proto(proto));
        input.setPortStart(port_start);
        input.setPortEnd(port_end);
        input.setCidrIp(cidr);
        input.setDescription(desc);
        input.setPolicy("accept");

        const auto outcome = client_->AuthorizeSecurityGroupIngress(input);
        if (outcome.isSuccess()) {
            std::cout << "[" << name_ << "] 已添加火山引擎安全组入站规则: " << cidr << " " << proto
                      << " " << port_str << '\n';
            return true;
        }
        const auto msg = "AuthorizeSecurityGroupIngress failed";
        if (is_duplicate(msg)) {
            std::cout << "[" << name_ << "] 安全组规则已存在，跳过: " << cidr << " " << proto << " "
                      << port_str << '\n';
            return true;
        }
        error = msg;
        return false;
    }

    bool revoke(const std::string& proto, int port_start, int port_end, const std::string& cidr,
                const std::string& port_str, std::string& error) {
        RevokeSecurityGroupIngressRequest input;
        input.setSecurityGroupId(security_group_id_);
        input.setProtocol(normalize_proto(proto));
        input.setPortStart(port_start);
        input.setPortEnd(port_end);
        input.setCidrIp(cidr);

        const auto outcome = client_->RevokeSecurityGroupIngress(input);
        if (outcome.isSuccess()) {
            std::cout << "[" << name_ << "] 已删除旧火山引擎安全组入站规则: " << cidr << " " << proto
                      << " " << port_str << '\n';
            return true;
        }
        const auto msg = "RevokeSecurityGroupIngress failed";
        if (is_not_found(msg)) {
            std::cout << "[" << name_ << "] 旧安全组规则不存在，跳过: " << cidr << " " << port_str
                      << '\n';
            return true;
        }
        error = msg;
        return false;
    }

    std::string name_;
    std::shared_ptr<VpcClient> client_;
    std::string security_group_id_;
};

std::shared_ptr<VpcClient> make_client(const config::Target& t) {
    const auto region = t.region.empty() ? "cn-beijing" : t.region;
    auto cfg = std::make_shared<VolcengineClientConfig>(region, t.access_key_id, t.access_key_secret,
                                                        "");
    return std::make_shared<VpcClient>(cfg);
}

}  // namespace

std::unique_ptr<IBackend> new_volcengine_sg(const config::Target& t, const config::Config&,
                                            std::string& error) {
    error.clear();
    return std::make_unique<VolcengineSgBackend>(t.name, make_client(t), t.security_group_id);
}

}  // namespace firewallkeeper::backend
