#include "firewallkeeper/backend/backend.hpp"

#include "firewallkeeper/ip/ip.hpp"
#include "firewallkeeper/util/string_util.hpp"

#include <iostream>
#include <memory>
#include <tencentcloud/core/Credential.h>
#include <tencentcloud/core/profile/ClientProfile.h>
#include <tencentcloud/core/profile/HttpProfile.h>
#include <tencentcloud/vpc/v20170312/VpcClient.h>
#include <tencentcloud/vpc/v20170312/model/CreateSecurityGroupPoliciesRequest.h>
#include <tencentcloud/vpc/v20170312/model/DeleteSecurityGroupPoliciesRequest.h>
#include <tencentcloud/vpc/v20170312/model/SecurityGroupPolicy.h>
#include <tencentcloud/vpc/v20170312/model/SecurityGroupPolicySet.h>

namespace firewallkeeper::backend {

namespace {

using namespace TencentCloud;
using namespace Vpc::V20170312;
using namespace Model;

std::string tencent_err(const Core::Error& e) {
    return e.GetErrorCode() + ": " + e.GetErrorMessage();
}

class CvmBackend : public IBackend {
public:
    CvmBackend(std::string name, std::string sg_id, std::unique_ptr<VpcClient> client)
        : name_(std::move(name)), sg_id_(std::move(sg_id)), client_(std::move(client)) {}

    std::string name() const override { return name_; }

    bool upsert_whitelist(const std::string& ip, const std::optional<std::string>& old_ip,
                          const config::Config& cfg, std::string& error) override {
        const auto cidr = ip::to_cidr(ip);
        return sync_whitelist_ports(
            ip, old_ip, cfg,
            [&](const std::string& port, std::string& err) { return create_ingress(cfg, cidr, port, err); },
            [&](const std::string& port, std::string& err) {
                return delete_ingress(cfg, ip::to_cidr(*old_ip), port, err);
            },
            error);
    }

private:
    bool create_ingress(const config::Config& cfg, const std::string& cidr, const std::string& port,
                        std::string& error) {
        SecurityGroupPolicy policy;
        policy.SetProtocol(util::to_lower(cfg.protocol));
        policy.SetPort(port);
        policy.SetCidrBlock(cidr);
        policy.SetAction("ACCEPT");
        policy.SetPolicyDescription(rule_description(cfg, port, 100));

        SecurityGroupPolicySet set;
        set.SetIngress({policy});

        CreateSecurityGroupPoliciesRequest req;
        req.SetSecurityGroupId(sg_id_);
        req.SetSecurityGroupPolicySet(set);

        auto outcome = client_->CreateSecurityGroupPolicies(req);
        if (outcome.IsSuccess()) {
            std::cout << "[" << name_ << "] 已添加安全组入站规则: " << cidr << " " << cfg.protocol
                      << " " << port << '\n';
            return true;
        }
        const auto msg = tencent_err(outcome.GetError());
        if (is_duplicate(msg)) {
            std::cout << "[" << name_ << "] 安全组规则已存在，跳过: " << cidr << " " << cfg.protocol
                      << " " << port << '\n';
            return true;
        }
        error = "CreateSecurityGroupPolicies: " + msg;
        return false;
    }

    bool delete_ingress(const config::Config& cfg, const std::string& cidr, const std::string& port,
                        std::string& error) {
        SecurityGroupPolicy policy;
        policy.SetProtocol(util::to_lower(cfg.protocol));
        policy.SetPort(port);
        policy.SetCidrBlock(cidr);
        policy.SetAction("ACCEPT");

        SecurityGroupPolicySet set;
        set.SetIngress({policy});

        DeleteSecurityGroupPoliciesRequest req;
        req.SetSecurityGroupId(sg_id_);
        req.SetSecurityGroupPolicySet(set);

        auto outcome = client_->DeleteSecurityGroupPolicies(req);
        if (outcome.IsSuccess()) {
            std::cout << "[" << name_ << "] 已删除旧安全组入站规则: " << cidr << " " << cfg.protocol
                      << " " << port << '\n';
            return true;
        }
        const auto msg = tencent_err(outcome.GetError());
        if (is_not_found(msg)) {
            std::cout << "[" << name_ << "] 旧安全组规则不存在，跳过: " << cidr << " " << port << '\n';
            return true;
        }
        error = "DeleteSecurityGroupPolicies: " + msg;
        return false;
    }

    std::string name_;
    std::string sg_id_;
    std::unique_ptr<VpcClient> client_;
};

std::unique_ptr<VpcClient> make_client(const config::Target& t) {
    Credential cred(t.secret_id, t.secret_key);
    HttpProfile http;
    http.SetEndpoint("vpc.tencentcloudapi.com");
    http.SetReqTimeout(30);
    ClientProfile profile(http);
    return std::make_unique<VpcClient>(cred, t.region, profile);
}

}  // namespace

std::unique_ptr<IBackend> new_cvm(const config::Target& t, const config::Config&, std::string& error) {
    error.clear();
    return std::make_unique<CvmBackend>(t.name, t.security_group_id, make_client(t));
}

}  // namespace firewallkeeper::backend
