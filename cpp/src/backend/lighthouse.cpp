#include "firewallkeeper/backend/backend.hpp"

#include "firewallkeeper/ip/ip.hpp"
#include "firewallkeeper/util/string_util.hpp"

#include <algorithm>
#include <iostream>
#include <memory>
#include <sstream>
#include <tencentcloud/core/Credential.h>
#include <tencentcloud/core/profile/ClientProfile.h>
#include <tencentcloud/core/profile/HttpProfile.h>
#include <tencentcloud/lighthouse/v20200324/LighthouseClient.h>
#include <tencentcloud/lighthouse/v20200324/model/CreateFirewallRulesRequest.h>
#include <tencentcloud/lighthouse/v20200324/model/DeleteFirewallRulesRequest.h>
#include <tencentcloud/lighthouse/v20200324/model/DescribeFirewallRulesRequest.h>
#include <tencentcloud/lighthouse/v20200324/model/FirewallRule.h>
#include <vector>

namespace firewallkeeper::backend {

namespace {

using namespace TencentCloud;
using namespace Lighthouse::V20200324;
using namespace Model;

std::string tencent_err(const Core::Error& e) {
    return e.GetErrorCode() + ": " + e.GetErrorMessage();
}

bool is_quota_exceeded(const std::string& msg) {
    const auto lower = util::to_lower(msg);
    return util::contains_icase(lower, "limitexceeded") || util::contains_icase(lower, "quota") ||
           util::contains_icase(lower, "firewallruleslimitexceeded");
}

// 合并为腾讯轻量 Port 字段（逗号分隔，最长 64）；超长返回空串表示回退逐端口。
// 端口按字典序排序；Describe 回传顺序可能不同，比较时用 same_firewall_ports。
std::string join_firewall_ports(const std::vector<std::string>& ports) {
    if (ports.empty()) return {};
    std::vector<std::string> parts;
    parts.reserve(ports.size());
    for (const auto& raw : ports) {
        auto p = util::trim(raw);
        if (!p.empty()) parts.push_back(std::move(p));
    }
    if (parts.empty()) return {};
    std::sort(parts.begin(), parts.end());
    std::ostringstream oss;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i) oss << ',';
        oss << parts[i];
    }
    auto joined = oss.str();
    return joined.size() > 64 ? std::string{} : joined;
}

bool same_firewall_ports(const std::string& a, const std::string& b) {
    if (a == b) return true;
    auto norm = [](const std::string& s) {
        std::vector<std::string> out;
        std::stringstream ss(s);
        std::string item;
        while (std::getline(ss, item, ',')) {
            item = util::trim(item);
            if (!item.empty()) out.push_back(std::move(item));
        }
        std::sort(out.begin(), out.end());
        return out;
    };
    return norm(a) == norm(b);
}

std::string combined_rule_desc(const config::Config& cfg, const std::string& port) {
    if (port.find(',') != std::string::npos || port.find('-') != std::string::npos) {
        auto desc = cfg.rule_description;
        if (desc.size() > 64) desc.resize(64);
        return desc;
    }
    return rule_description(cfg, port, 64);
}

class LighthouseBackend : public IBackend {
public:
    LighthouseBackend(std::string name, std::string instance_id,
                      std::unique_ptr<LighthouseClient> client)
        : name_(std::move(name)),
          instance_id_(std::move(instance_id)),
          client_(std::move(client)) {}

    std::string name() const override { return name_; }

    bool upsert_whitelist(const std::string& ip, const std::optional<std::string>& old_ip,
                          const config::Config& cfg, std::string& error) override {
        const auto cidr = ip::to_cidr(ip);
        const auto port_spec = join_firewall_ports(cfg.ports);
        if (port_spec.empty()) {
            return upsert_per_port(ip, old_ip, cfg, error);
        }

        if (cfg.remove_old_ip && old_ip && !old_ip->empty() && *old_ip != ip) {
            if (!delete_managed_for_cidr(cfg, ip::to_cidr(*old_ip), error)) return false;
        }

        if (!create_rule(cfg, cidr, port_spec, error)) return false;
        return delete_legacy_per_port_rules(cfg, cidr, port_spec, error);
    }

private:
    bool upsert_per_port(const std::string& ip, const std::optional<std::string>& old_ip,
                         const config::Config& cfg, std::string& error) {
        const auto cidr = ip::to_cidr(ip);
        if (cfg.remove_old_ip && old_ip && !old_ip->empty() && *old_ip != ip) {
            const auto old_cidr = ip::to_cidr(*old_ip);
            for (const auto& port : cfg.ports) {
                if (!delete_rule_exact(cfg.protocol, old_cidr, port, error)) return false;
            }
        }
        for (const auto& port : cfg.ports) {
            if (!create_rule(cfg, cidr, port, error)) return false;
        }
        return true;
    }

    bool create_rule(const config::Config& cfg, const std::string& cidr, const std::string& port,
                     std::string& error) {
        const auto desc = combined_rule_desc(cfg, port);
        if (create_rule_once(cfg, cidr, port, desc, error)) return true;
        if (!is_quota_exceeded(error)) return false;

        int freed = 0;
        std::string clean_err;
        if (!cleanup_stale_managed(cfg, cidr, freed, clean_err)) {
            error = error + " (清理旧规则失败: " + clean_err + ")";
            return false;
        }
        if (freed == 0) return false;

        std::cout << "[" << name_ << "] 防火墙规则配额已满，已清理 " << freed
                  << " 条本工具管理的过期规则，重试添加\n";
        error.clear();
        return create_rule_once(cfg, cidr, port, desc, error);
    }

    bool create_rule_once(const config::Config& cfg, const std::string& cidr,
                          const std::string& port, const std::string& desc, std::string& error) {
        FirewallRule rule;
        rule.SetProtocol(cfg.protocol);
        rule.SetPort(port);
        rule.SetCidrBlock(cidr);
        rule.SetAction("ACCEPT");
        rule.SetFirewallRuleDescription(desc);

        CreateFirewallRulesRequest req;
        req.SetInstanceId(instance_id_);
        req.SetFirewallRules({rule});

        auto outcome = client_->CreateFirewallRules(req);
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

    bool delete_rule_exact(const std::string& protocol, const std::string& cidr,
                           const std::string& port, std::string& error) {
        FirewallRule rule;
        rule.SetProtocol(protocol);
        rule.SetPort(port);
        rule.SetCidrBlock(cidr);
        rule.SetAction("ACCEPT");

        DeleteFirewallRulesRequest req;
        req.SetInstanceId(instance_id_);
        req.SetFirewallRules({rule});

        auto outcome = client_->DeleteFirewallRules(req);
        if (outcome.IsSuccess()) {
            std::cout << "[" << name_ << "] 已删除旧轻量防火墙规则: " << cidr << " " << protocol
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

    bool list_managed(const config::Config& cfg, std::vector<FirewallRule>& out, std::string& error) {
        DescribeFirewallRulesRequest req;
        req.SetInstanceId(instance_id_);
        req.SetLimit(100);
        req.SetOffset(0);
        auto outcome = client_->DescribeFirewallRules(req);
        if (!outcome.IsSuccess()) {
            error = "DescribeFirewallRules: " + tencent_err(outcome.GetError());
            return false;
        }
        const auto& prefix = cfg.rule_description;
        out.clear();
        for (const auto& r : outcome.GetResult().GetFirewallRuleSet()) {
            const auto desc = r.GetFirewallRuleDescription();
            if (!prefix.empty() && desc.rfind(prefix, 0) != 0) continue;
            if (!util::iequals(r.GetAction(), "ACCEPT")) continue;
            FirewallRule item;
            item.SetProtocol(r.GetProtocol());
            item.SetPort(r.GetPort());
            item.SetCidrBlock(r.GetCidrBlock());
            item.SetAction(r.GetAction());
            out.push_back(std::move(item));
        }
        return true;
    }

    bool delete_rules(const std::vector<FirewallRule>& rules, std::string& error) {
        if (rules.empty()) return true;
        DeleteFirewallRulesRequest req;
        req.SetInstanceId(instance_id_);
        req.SetFirewallRules(rules);
        auto outcome = client_->DeleteFirewallRules(req);
        if (!outcome.IsSuccess()) {
            error = "DeleteFirewallRules: " + tencent_err(outcome.GetError());
            return false;
        }
        return true;
    }

    bool delete_managed_for_cidr(const config::Config& cfg, const std::string& cidr,
                                 std::string& error) {
        std::vector<FirewallRule> managed;
        if (!list_managed(cfg, managed, error)) return false;
        std::vector<FirewallRule> to_delete;
        for (const auto& r : managed) {
            if (r.GetCidrBlock() == cidr) to_delete.push_back(r);
        }
        if (!delete_rules(to_delete, error)) return false;
        for (const auto& r : to_delete) {
            std::cout << "[" << name_ << "] 已删除旧轻量防火墙规则: " << r.GetCidrBlock() << " "
                      << r.GetProtocol() << " " << r.GetPort() << '\n';
        }
        return true;
    }

    bool delete_legacy_per_port_rules(const config::Config& cfg, const std::string& cidr,
                                      const std::string& keep_port, std::string& error) {
        std::vector<FirewallRule> managed;
        if (!list_managed(cfg, managed, error)) return false;
        std::vector<FirewallRule> to_delete;
        for (const auto& r : managed) {
            if (r.GetCidrBlock() != cidr) continue;
            if (same_firewall_ports(r.GetPort(), keep_port)) continue;
            to_delete.push_back(r);
        }
        if (!delete_rules(to_delete, error)) return false;
        for (const auto& r : to_delete) {
            std::cout << "[" << name_ << "] 已清理同 IP 旧逐端口规则: " << r.GetCidrBlock() << " "
                      << r.GetProtocol() << " " << r.GetPort() << '\n';
        }
        return true;
    }

    bool cleanup_stale_managed(const config::Config& cfg, const std::string& keep_cidr, int& freed,
                               std::string& error) {
        freed = 0;
        std::vector<FirewallRule> managed;
        if (!list_managed(cfg, managed, error)) return false;
        std::vector<FirewallRule> stale;
        for (const auto& r : managed) {
            if (r.GetCidrBlock() != keep_cidr) stale.push_back(r);
        }
        if (!delete_rules(stale, error)) return false;
        for (const auto& r : stale) {
            std::cout << "[" << name_ << "] 已清理过期规则以释放配额: " << r.GetCidrBlock() << " "
                      << r.GetProtocol() << " " << r.GetPort() << '\n';
        }
        freed = static_cast<int>(stale.size());
        return true;
    }

    std::string name_;
    std::string instance_id_;
    std::unique_ptr<LighthouseClient> client_;
};

std::unique_ptr<LighthouseClient> make_client(const config::Target& t) {
    Credential cred(t.secret_id, t.secret_key);
    HttpProfile http;
    http.SetEndpoint("lighthouse.tencentcloudapi.com");
    http.SetReqTimeout(30);
    ClientProfile profile(http);
    return std::make_unique<LighthouseClient>(cred, t.region, profile);
}

}  // namespace

std::unique_ptr<IBackend> new_lighthouse(const config::Target& t, const config::Config&,
                                         std::string& error) {
    error.clear();
    return std::make_unique<LighthouseBackend>(t.name, t.instance_id, make_client(t));
}

}  // namespace firewallkeeper::backend
