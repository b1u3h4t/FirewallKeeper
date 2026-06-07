#include "firewallkeeper/backend/backend.hpp"

#include "firewallkeeper/ip/ip.hpp"
#include "firewallkeeper/util/string_util.hpp"

#include <iostream>
#include <memory>
#include <tencentcloud/core/Credential.h>
#include <tencentcloud/core/profile/ClientProfile.h>
#include <tencentcloud/core/profile/HttpProfile.h>
#include <tencentcloud/lighthouse/v20200324/LighthouseClient.h>
#include <tencentcloud/lighthouse/v20200324/model/CreateFirewallRulesRequest.h>
#include <tencentcloud/lighthouse/v20200324/model/DeleteFirewallRulesRequest.h>
#include <tencentcloud/lighthouse/v20200324/model/FirewallRule.h>

namespace firewallkeeper::backend {

namespace {

using namespace TencentCloud;
using namespace Lighthouse::V20200324;
using namespace Model;

std::string tencent_err(const Core::Error& e) {
    return e.GetErrorCode() + ": " + e.GetErrorMessage();
}

class LighthouseBackend : public IBackend {
public:
    LighthouseBackend(std::string name, std::string instance_id, LighthouseClient client)
        : name_(std::move(name)), instance_id_(std::move(instance_id)), client_(std::move(client)) {}

    std::string name() const override { return name_; }

    bool upsert_whitelist(const std::string& ip, const std::optional<std::string>& old_ip,
                          const config::Config& cfg, std::string& error) override {
        const auto cidr = ip::to_cidr(ip);
        return sync_whitelist_ports(
            ip, old_ip, cfg,
            [&](const std::string& port, std::string& err) { return create_rule(cfg, cidr, port, err); },
            [&](const std::string& port, std::string& err) {
                return delete_rule(cfg, ip::to_cidr(*old_ip), port, err);
            },
            error);
    }

private:
    bool create_rule(const config::Config& cfg, const std::string& cidr, const std::string& port,
                     std::string& error) {
        FirewallRule rule;
        rule.SetProtocol(cfg.protocol);
        rule.SetPort(port);
        rule.SetCidrBlock(cidr);
        rule.SetAction("ACCEPT");
        rule.SetFirewallRuleDescription(rule_description(cfg, port, 64));

        CreateFirewallRulesRequest req;
        req.SetInstanceId(instance_id_);
        req.SetFirewallRules({rule});

        auto outcome = client_.CreateFirewallRules(req);
        if (outcome.IsSuccess()) {
            std::cout << "[" << name_ << "] 已添加轻量防火墙规则: " << cidr << " " << cfg.protocol
                      << " " << port << '\n';
            return true;
        }
        const auto msg = tencent_err(outcome.GetError());
        if (is_duplicate(msg)) {
            std::cout << "[" << name_ << "] 规则已存在，跳过: " << cidr << " " << cfg.protocol << " "
                      << port << '\n';
            return true;
        }
        error = "CreateFirewallRules: " + msg;
        return false;
    }

    bool delete_rule(const config::Config& cfg, const std::string& cidr, const std::string& port,
                     std::string& error) {
        FirewallRule rule;
        rule.SetProtocol(cfg.protocol);
        rule.SetPort(port);
        rule.SetCidrBlock(cidr);
        rule.SetAction("ACCEPT");

        DeleteFirewallRulesRequest req;
        req.SetInstanceId(instance_id_);
        req.SetFirewallRules({rule});

        auto outcome = client_.DeleteFirewallRules(req);
        if (outcome.IsSuccess()) {
            std::cout << "[" << name_ << "] 已删除旧轻量防火墙规则: " << cidr << " " << cfg.protocol
                      << " " << port << '\n';
            return true;
        }
        const auto msg = tencent_err(outcome.GetError());
        if (is_not_found(msg)) {
            std::cout << "[" << name_ << "] 旧规则不存在，跳过删除: " << cidr << " " << port << '\n';
            return true;
        }
        error = "DeleteFirewallRules: " + msg;
        return false;
    }

    std::string name_;
    std::string instance_id_;
    LighthouseClient client_;
};

LighthouseClient make_client(const config::Target& t) {
    Credential cred(t.secret_id, t.secret_key);
    HttpProfile http;
    http.SetEndpoint("lighthouse.tencentcloudapi.com");
    http.SetReqTimeout(30);
    ClientProfile profile(http);
    return LighthouseClient(cred, t.region, profile);
}

}  // namespace

std::unique_ptr<IBackend> new_lighthouse(const config::Target& t, const config::Config&,
                                         std::string& error) {
    error.clear();
    return std::make_unique<LighthouseBackend>(t.name, t.instance_id, make_client(t));
}

}  // namespace firewallkeeper::backend
