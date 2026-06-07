#include "firewallkeeper/backend/backend.hpp"

#include "firewallkeeper/util/string_util.hpp"

#include <iostream>
#include <sstream>

namespace firewallkeeper::backend {

namespace {

using util::contains_icase;
using util::to_lower;

std::unique_ptr<IBackend> new_target(const config::Target& t, const config::Config& cfg,
                                     std::string& error) {
    if (t.provider == config::kProviderTencentLighthouse) return new_lighthouse(t, cfg, error);
    if (t.provider == config::kProviderTencentCVM) return new_cvm(t, cfg, error);
    if (t.provider == config::kProviderAliyunSWAS) return new_aliyun_swas(t, cfg, error);
    if (t.provider == config::kProviderScalewaySG) return new_scaleway_sg(t, cfg, error);
    if (t.provider == config::kProviderHetznerCloudFirewall) return new_hetzner_cloud(t, cfg, error);
    if (t.provider == config::kProviderHetznerRobotFirewall) return new_hetzner_robot(t, cfg, error);
    if (t.provider == config::kProviderAWSLightsail) return new_aws_lightsail(t, cfg, error);
    if (t.provider == config::kProviderVolcengineSG) return new_volcengine_sg(t, cfg, error);
    if (t.provider == config::kProviderNetcupSCPFirewall) return new_netcup_firewall(t, cfg, error);
    error = "unsupported provider: " + t.provider;
    return nullptr;
}

}  // namespace

std::vector<std::unique_ptr<IBackend>> new_all(const config::Config& cfg, std::string& error) {
    error.clear();
    std::vector<std::unique_ptr<IBackend>> backends;
    for (const auto& t : cfg.targets) {
        auto b = new_target(t, cfg, error);
        if (!b) {
            if (!error.empty()) error = t.name + ": " + error;
            return {};
        }
        backends.push_back(std::move(b));
    }
    if (backends.empty()) {
        error = "没有已启用的 targets";
        return {};
    }
    return backends;
}

bool upsert_all(const std::vector<std::unique_ptr<IBackend>>& backends,
                const std::string& ip,
                const std::optional<std::string>& old_ip,
                const config::Config& cfg,
                std::string& error) {
    error.clear();
    std::ostringstream errs;
    bool ok = true;
    for (const auto& b : backends) {
        std::string one_err;
        if (!b->upsert_whitelist(ip, old_ip, cfg, one_err)) {
            ok = false;
            if (!errs.str().empty()) errs << '\n';
            errs << "[" << b->name() << "] " << one_err;
        }
    }
    if (!ok) error = errs.str();
    return ok;
}

std::string rule_description(const config::Config& cfg, const std::string& port, size_t max_len) {
    auto desc = cfg.rule_description + ":" + port;
    if (desc.size() > max_len) desc.resize(max_len);
    return desc;
}

bool is_duplicate(const std::string& error) {
    if (error.empty()) return false;
    const auto msg = to_lower(error);
    return contains_icase(msg, "exist") || contains_icase(msg, "duplicate") ||
           contains_icase(msg, "already") || contains_icase(msg, "已存在");
}

bool is_not_found(const std::string& error) {
    if (error.empty()) return false;
    const auto msg = to_lower(error);
    return contains_icase(msg, "notfound") || contains_icase(msg, "not found") ||
           contains_icase(msg, "不存在");
}

bool sync_whitelist_ports(const std::string& ip, const std::optional<std::string>& old_ip,
                          const config::Config& cfg, const PortAction& add,
                          const PortAction& remove, std::string& error) {
    error.clear();
    for (const auto& port : cfg.ports) {
        if (!add(port, error)) return false;
    }
    if (cfg.remove_old_ip && old_ip && !old_ip->empty() && *old_ip != ip) {
        for (const auto& port : cfg.ports) {
            if (!remove(port, error)) return false;
        }
    }
    return true;
}

void log_added(const std::string& backend, const std::string& msg) {
    std::cout << "[" << backend << "] " << msg << '\n';
}

void log_skip_dup(const std::string& backend, const std::string& msg) {
    std::cout << "[" << backend << "] " << msg << '\n';
}

void log_removed(const std::string& backend, const std::string& msg) {
    std::cout << "[" << backend << "] " << msg << '\n';
}

void log_skip_missing(const std::string& backend, const std::string& msg) {
    std::cout << "[" << backend << "] " << msg << '\n';
}

}  // namespace firewallkeeper::backend
