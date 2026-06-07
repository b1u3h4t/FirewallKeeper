#pragma once

#include <optional>
#include <string>
#include <vector>

namespace firewallkeeper::config {

inline constexpr const char* kProviderTencentLighthouse = "tencent_lighthouse";
inline constexpr const char* kProviderTencentCVM = "tencent_cvm";
inline constexpr const char* kProviderAliyunSWAS = "aliyun_swas";
inline constexpr const char* kProviderScalewaySG = "scaleway_security_group";
inline constexpr const char* kProviderHetznerCloudFirewall = "hetzner_cloud_firewall";
inline constexpr const char* kProviderHetznerRobotFirewall = "hetzner_robot_firewall";
inline constexpr const char* kProviderAWSLightsail = "aws_lightsail";
inline constexpr const char* kProviderVolcengineSG = "volcengine_security_group";
inline constexpr const char* kProviderNetcupSCPFirewall = "netcup_scp_firewall";

struct Target {
    std::string name;
    std::string provider;
    bool enabled = true;
    std::string region;
    std::string secret_id;
    std::string secret_key;
    std::string instance_id;
    std::string security_group_id;
    std::string access_key_id;
    std::string access_key_secret;
    std::string endpoint;
    std::string zone;
    std::string firewall_id;
    std::string robot_user;
    std::string robot_password;
    std::string server_number;
    std::string instance_name;
    std::string refresh_token;
    std::string api_token;
    std::string user_id;
    std::string interface_mac;
};

struct Config {
    std::vector<std::string> ports;
    std::string protocol;
    std::string rule_description;
    bool remove_old_ip = true;
    std::vector<std::string> ip_check_urls;
    int interval_seconds = 300;
    std::string state_file;
    std::vector<Target> targets;
};

Config load(const std::string& path, std::string& error);

}  // namespace firewallkeeper::config
