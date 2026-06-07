#pragma once

#include "firewallkeeper/config/config.hpp"

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace firewallkeeper::backend {

class IBackend {
public:
    virtual ~IBackend() = default;

    virtual std::string name() const = 0;
    virtual bool upsert_whitelist(const std::string& ip,
                                  const std::optional<std::string>& old_ip,
                                  const config::Config& cfg,
                                  std::string& error) = 0;
};

std::vector<std::unique_ptr<IBackend>> new_all(const config::Config& cfg, std::string& error);
bool upsert_all(const std::vector<std::unique_ptr<IBackend>>& backends,
                const std::string& ip,
                const std::optional<std::string>& old_ip,
                const config::Config& cfg,
                std::string& error);

std::string rule_description(const config::Config& cfg, const std::string& port, size_t max_len);
bool is_duplicate(const std::string& error);
bool is_not_found(const std::string& error);

using PortAction = std::function<bool(const std::string& port, std::string& error)>;
bool sync_whitelist_ports(const std::string& ip, const std::optional<std::string>& old_ip,
                          const config::Config& cfg, const PortAction& add,
                          const PortAction& remove, std::string& error);

void log_added(const std::string& backend, const std::string& msg);
void log_skip_dup(const std::string& backend, const std::string& msg);
void log_removed(const std::string& backend, const std::string& msg);
void log_skip_missing(const std::string& backend, const std::string& msg);

std::unique_ptr<IBackend> new_lighthouse(const config::Target& t, const config::Config& cfg,
                                           std::string& error);
std::unique_ptr<IBackend> new_cvm(const config::Target& t, const config::Config& cfg,
                                  std::string& error);
std::unique_ptr<IBackend> new_aliyun_swas(const config::Target& t, const config::Config& cfg,
                                          std::string& error);
std::unique_ptr<IBackend> new_scaleway_sg(const config::Target& t, const config::Config& cfg,
                                          std::string& error);
std::unique_ptr<IBackend> new_hetzner_cloud(const config::Target& t, const config::Config& cfg,
                                            std::string& error);
std::unique_ptr<IBackend> new_hetzner_robot(const config::Target& t, const config::Config& cfg,
                                            std::string& error);
std::unique_ptr<IBackend> new_aws_lightsail(const config::Target& t, const config::Config& cfg,
                                             std::string& error);
std::unique_ptr<IBackend> new_volcengine_sg(const config::Target& t, const config::Config& cfg,
                                            std::string& error);
std::unique_ptr<IBackend> new_netcup_firewall(const config::Target& t, const config::Config& cfg,
                                              std::string& error);

}  // namespace firewallkeeper::backend
