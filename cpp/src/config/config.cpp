#include "firewallkeeper/config/config.hpp"

#include "firewallkeeper/util/string_util.hpp"

#include <yaml-cpp/yaml.h>

#include <boost/filesystem.hpp>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

namespace firewallkeeper::config {

namespace fs = boost::filesystem;
using util::env_or;
using util::first_non_empty;
using util::split_ports;
using util::to_lower;
using util::to_upper;
using util::trim;

namespace {

struct LegacyTencent {
    std::string secret_id;
    std::string secret_key;
    std::string region;
};

struct LegacyAliyun {
    std::string access_key_id;
    std::string access_key_secret;
    std::string region;
    std::string endpoint;
};

struct LegacyLighthouse {
    std::string instance_id;
};

struct LegacyAliyunSWAS {
    std::string instance_id;
};

struct LegacyCVM {
    std::string security_group_id;
};

struct TargetYAML {
    std::string provider;
    std::optional<bool> enabled;
    std::string region;
    std::string secret_id;
    std::string secret_key;
    std::string instance_id;
    std::string security_group_id;
    std::string access_key_id;
    std::string access_key_secret;
    std::string endpoint;
    std::string zone;
    std::string api_token;
    std::string firewall_id;
    std::string firewall_policy_id;
    std::string robot_user;
    std::string robot_password;
    std::string server_number;
    std::string instance_name;
    std::string refresh_token;
    std::string access_token;
    std::string user_id;
    std::string interface_mac;
};

struct FileConfig {
    std::unordered_map<std::string, TargetYAML> targets;
    std::string backend;
    LegacyTencent tencent;
    LegacyAliyun aliyun;
    LegacyLighthouse lighthouse;
    LegacyAliyunSWAS aliyun_swas;
    LegacyCVM cvm;
    std::vector<std::string> ports;
    std::string protocol;
    std::string rule_description;
    std::optional<bool> remove_old_ip;
    std::vector<std::string> ip_check_urls;
    int interval_seconds = 0;
    std::string state_file;
};

std::string env_or_empty(const std::string& value, const char* env_name) {
    if (auto v = env_or(value, env_name)) return *v;
    return {};
}

bool in_docker() {
    if (const char* d = std::getenv("DOCKER")) {
        if (trim(d) == "1") return true;
    }
    boost::system::error_code ec;
    return fs::exists("/.dockerenv", ec);
}

bool is_unsafe_container_home_path(const std::string& path) {
    return path.rfind("/.cache/", 0) == 0 || path == "/.cache";
}

std::string expand_home(const std::string& path) {
    if (path.rfind("~/", 0) != 0) return path;
    std::string home;
    if (const char* h = std::getenv("HOME")) home = trim(h);
    if (home.empty()) {
        if (const char* h = std::getenv("USERPROFILE")) home = trim(h);
    }
    if (home.empty()) return path;
    return (fs::path(home) / path.substr(2)).string();
}

std::string default_state_file() {
    if (in_docker()) return "/data/state.json";
    return "~/.cache/FirewallKeeper/state.json";
}

std::string resolve_state_path(std::string path) {
    path = trim(path);
    if (path.empty()) return default_state_file();
    if (path.rfind("~/", 0) == 0) {
        auto expanded = expand_home(path);
        if (expanded.rfind("~/", 0) == 0 || is_unsafe_container_home_path(expanded)) {
            if (in_docker()) return "/data/state.json";
            return expanded;
        }
        return expanded;
    }
    return path;
}

std::vector<std::string> parse_ports_node(const YAML::Node& node) {
    if (!node || node.IsNull()) return {};
    if (node.IsScalar()) return split_ports(node.as<std::string>());
    if (node.IsSequence()) {
        std::vector<std::string> ports;
        for (const auto& item : node) {
            if (item.IsScalar()) {
                auto p = trim(item.as<std::string>());
                if (!p.empty()) ports.push_back(p);
            }
        }
        return ports;
    }
    throw std::runtime_error("ports: unsupported YAML type");
}

std::optional<bool> parse_optional_bool(const YAML::Node& node) {
    if (!node || node.IsNull()) return std::nullopt;
    return node.as<bool>();
}

TargetYAML parse_target_yaml(const YAML::Node& node) {
    TargetYAML t;
    if (!node || !node.IsMap()) return t;
    auto get = [&](const char* key) -> std::string {
        if (node[key] && node[key].IsScalar()) return trim(node[key].as<std::string>());
        return {};
    };
    t.provider = get("provider");
    t.enabled = parse_optional_bool(node["enabled"]);
    t.region = get("region");
    t.secret_id = get("secret_id");
    t.secret_key = get("secret_key");
    t.instance_id = get("instance_id");
    t.security_group_id = get("security_group_id");
    t.access_key_id = get("access_key_id");
    t.access_key_secret = get("access_key_secret");
    t.endpoint = get("endpoint");
    t.zone = get("zone");
    t.api_token = get("api_token");
    t.firewall_id = get("firewall_id");
    t.firewall_policy_id = get("firewall_policy_id");
    t.robot_user = get("robot_user");
    t.robot_password = get("robot_password");
    t.server_number = get("server_number");
    t.instance_name = get("instance_name");
    t.refresh_token = get("refresh_token");
    t.access_token = get("access_token");
    t.user_id = get("user_id");
    t.interface_mac = get("interface_mac");
    return t;
}

Target target_from_yaml(const std::string& name, const TargetYAML& t) {
    Target target;
    target.name = name;
    target.provider = t.provider.empty() ? name : t.provider;
    target.enabled = true;
    target.region = t.region;
    target.secret_id = t.secret_id;
    target.secret_key = t.secret_key;
    target.instance_id = t.instance_id;
    target.security_group_id = t.security_group_id;
    target.access_key_id = t.access_key_id;
    target.access_key_secret = t.access_key_secret;
    target.endpoint = t.endpoint;
    target.zone = first_non_empty({t.zone, t.region});
    target.firewall_id = first_non_empty({t.firewall_id, t.firewall_policy_id, t.security_group_id});
    target.robot_user = t.robot_user;
    target.robot_password = t.robot_password;
    target.server_number = first_non_empty({t.server_number, t.instance_id});
    target.instance_name = first_non_empty({t.instance_name, t.instance_id});
    target.refresh_token = t.refresh_token;
    target.api_token = first_non_empty({t.access_token, t.api_token});
    target.user_id = t.user_id;
    target.interface_mac = t.interface_mac;
    if (target.secret_key.empty() && target.provider != kProviderNetcupSCPFirewall) {
        target.secret_key = t.api_token;
    }
    return target;
}

void apply_target_env_defaults(Target& t) {
    if (t.provider == kProviderTencentLighthouse || t.provider == kProviderTencentCVM) {
        t.secret_id = env_or_empty(t.secret_id, "TENCENT_SECRET_ID");
        t.secret_key = env_or_empty(t.secret_key, "TENCENT_SECRET_KEY");
        if (t.region.empty()) t.region = env_or_empty("", "TENCENT_REGION");
        if (t.provider == kProviderTencentLighthouse && t.instance_id.empty()) {
            t.instance_id = env_or_empty("", "LIGHTHOUSE_INSTANCE_ID");
        }
        if (t.provider == kProviderTencentCVM && t.security_group_id.empty()) {
            t.security_group_id = env_or_empty("", "SECURITY_GROUP_ID");
        }
    } else if (t.provider == kProviderAliyunSWAS) {
        t.access_key_id = env_or_empty(t.access_key_id, "ALIBABA_CLOUD_ACCESS_KEY_ID");
        t.access_key_secret = env_or_empty(t.access_key_secret, "ALIBABA_CLOUD_ACCESS_KEY_SECRET");
        if (t.region.empty()) t.region = env_or_empty("", "ALIBABA_CLOUD_REGION");
        if (t.instance_id.empty()) t.instance_id = env_or_empty("", "ALIBABA_CLOUD_SWAS_INSTANCE_ID");
        if (t.endpoint.empty()) t.endpoint = env_or_empty("", "ALIBABA_CLOUD_ENDPOINT");
    } else if (t.provider == kProviderScalewaySG) {
        t.secret_key = env_or_empty(t.secret_key, "SCW_SECRET_KEY");
        if (t.secret_key.empty()) t.secret_key = env_or_empty("", "SCW_API_TOKEN");
        if (t.zone.empty()) t.zone = env_or_empty(t.region, "SCW_DEFAULT_ZONE");
        if (t.security_group_id.empty()) t.security_group_id = env_or_empty("", "SCW_SECURITY_GROUP_ID");
    } else if (t.provider == kProviderHetznerCloudFirewall) {
        t.secret_key = env_or_empty(t.secret_key, "HCLOUD_TOKEN");
        if (t.firewall_id.empty()) t.firewall_id = env_or_empty(t.security_group_id, "HCLOUD_FIREWALL_ID");
        if (t.endpoint.empty()) t.endpoint = env_or_empty("", "HCLOUD_ENDPOINT");
    } else if (t.provider == kProviderHetznerRobotFirewall) {
        t.robot_user = env_or_empty(t.robot_user, "HETZNER_ROBOT_USER");
        if (t.robot_user.empty()) t.robot_user = env_or_empty(t.access_key_id, "ROBOT_USER");
        t.robot_password = env_or_empty(t.robot_password, "HETZNER_ROBOT_PASSWORD");
        if (t.robot_password.empty()) t.robot_password = env_or_empty(t.access_key_secret, "ROBOT_PASSWORD");
        if (t.server_number.empty()) t.server_number = env_or_empty(t.instance_id, "HETZNER_ROBOT_SERVER_NUMBER");
        if (t.endpoint.empty()) t.endpoint = env_or_empty("", "HETZNER_ROBOT_ENDPOINT");
    } else if (t.provider == kProviderAWSLightsail) {
        t.access_key_id = env_or_empty(t.access_key_id, "AWS_ACCESS_KEY_ID");
        if (t.access_key_id.empty()) t.access_key_id = env_or_empty("", "AWS_ACCESS_KEY");
        t.access_key_secret = env_or_empty(t.access_key_secret, "AWS_SECRET_ACCESS_KEY");
        if (t.region.empty()) t.region = env_or_empty("", "AWS_REGION");
        if (t.instance_name.empty()) t.instance_name = env_or_empty(t.instance_id, "AWS_LIGHTSAIL_INSTANCE_NAME");
    } else if (t.provider == kProviderVolcengineSG) {
        t.access_key_id = env_or_empty(t.access_key_id, "VOLCENGINE_ACCESS_KEY_ID");
        if (t.access_key_id.empty()) t.access_key_id = env_or_empty("", "VOLC_ACCESSKEY");
        t.access_key_secret = env_or_empty(t.access_key_secret, "VOLCENGINE_SECRET_ACCESS_KEY");
        if (t.access_key_secret.empty()) t.access_key_secret = env_or_empty("", "VOLC_SECRETKEY");
        if (t.region.empty()) t.region = env_or_empty("", "VOLCENGINE_REGION");
        if (t.security_group_id.empty()) t.security_group_id = env_or_empty("", "VOLCENGINE_SECURITY_GROUP_ID");
        if (t.endpoint.empty()) t.endpoint = env_or_empty("", "VOLCENGINE_ENDPOINT");
    } else if (t.provider == kProviderNetcupSCPFirewall) {
        t.refresh_token = env_or_empty(t.refresh_token, "NETCUP_SCP_REFRESH_TOKEN");
        t.api_token = env_or_empty(t.api_token, "NETCUP_SCP_ACCESS_TOKEN");
        if (t.firewall_id.empty()) t.firewall_id = env_or_empty(t.security_group_id, "NETCUP_FIREWALL_POLICY_ID");
        if (t.endpoint.empty()) t.endpoint = env_or_empty("", "NETCUP_SCP_API_URL");
    }
}

bool validate_target(const Target& t, std::string& error) {
    error.clear();
    if (t.provider == kProviderTencentLighthouse) {
        if (t.secret_id.empty() || t.secret_key.empty() || t.region.empty()) {
            error = "需要 secret_id、secret_key、region";
            return false;
        }
        if (t.instance_id.empty()) {
            error = "需要 instance_id";
            return false;
        }
    } else if (t.provider == kProviderTencentCVM) {
        if (t.secret_id.empty() || t.secret_key.empty() || t.region.empty()) {
            error = "需要 secret_id、secret_key、region";
            return false;
        }
        if (t.security_group_id.empty()) {
            error = "需要 security_group_id";
            return false;
        }
    } else if (t.provider == kProviderAliyunSWAS) {
        if (t.access_key_id.empty() || t.access_key_secret.empty() || t.region.empty()) {
            error = "需要 access_key_id、access_key_secret、region";
            return false;
        }
        if (t.instance_id.empty()) {
            error = "需要 instance_id";
            return false;
        }
    } else if (t.provider == kProviderScalewaySG) {
        if (t.secret_key.empty()) {
            error = "需要 secret_key 或 api_token（Scaleway API Secret Key）";
            return false;
        }
        if (t.zone.empty()) {
            error = "需要 zone（可用区，如 fr-par-1）或 region";
            return false;
        }
        if (t.security_group_id.empty()) {
            error = "需要 security_group_id";
            return false;
        }
    } else if (t.provider == kProviderHetznerCloudFirewall) {
        if (t.secret_key.empty()) {
            error = "需要 api_token 或 secret_key（HCLOUD_TOKEN）";
            return false;
        }
        if (t.firewall_id.empty()) {
            error = "需要 firewall_id（HCLOUD_FIREWALL_ID）";
            return false;
        }
    } else if (t.provider == kProviderHetznerRobotFirewall) {
        if (t.robot_user.empty() || t.robot_password.empty()) {
            error = "需要 robot_user、robot_password（或 access_key_id/access_key_secret）";
            return false;
        }
        if (t.server_number.empty()) {
            error = "需要 server_number 或 instance_id";
            return false;
        }
    } else if (t.provider == kProviderAWSLightsail) {
        if (t.access_key_id.empty() || t.access_key_secret.empty()) {
            error = "需要 access_key_id、access_key_secret（或 AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY）";
            return false;
        }
        if (t.region.empty()) {
            error = "需要 region（如 us-east-1）";
            return false;
        }
        if (t.instance_name.empty()) {
            error = "需要 instance_name（Lightsail 控制台中的实例名称）";
            return false;
        }
    } else if (t.provider == kProviderVolcengineSG) {
        if (t.access_key_id.empty() || t.access_key_secret.empty() || t.region.empty()) {
            error = "需要 access_key_id、access_key_secret、region";
            return false;
        }
        if (t.security_group_id.empty()) {
            error = "需要 security_group_id";
            return false;
        }
    } else if (t.provider == kProviderNetcupSCPFirewall) {
        if (t.refresh_token.empty() && t.api_token.empty()) {
            error = "需要 refresh_token 或 access_token（SCP OAuth，见 netcup-cli auth login）";
            return false;
        }
        if (t.firewall_id.empty()) {
            error = "需要 firewall_policy_id 或 firewall_id";
            return false;
        }
    } else {
        std::ostringstream oss;
        oss << "不支持的 provider: " << t.provider << "（已知: " << kProviderTencentLighthouse << ", "
            << kProviderTencentCVM << ", " << kProviderAliyunSWAS << ", " << kProviderScalewaySG << ", "
            << kProviderHetznerCloudFirewall << ", " << kProviderHetznerRobotFirewall << ", "
            << kProviderAWSLightsail << ", " << kProviderVolcengineSG << ", " << kProviderNetcupSCPFirewall
            << "）";
        error = oss.str();
        return false;
    }
    return true;
}

bool parse_targets_map(const std::unordered_map<std::string, TargetYAML>& m,
                       std::vector<Target>& out,
                       std::string& error) {
    out.clear();
    for (const auto& [name, ty] : m) {
        if (ty.enabled.has_value() && !*ty.enabled) continue;
        auto target = target_from_yaml(name, ty);
        apply_target_env_defaults(target);
        std::string verr;
        if (!validate_target(target, verr)) {
            error = "targets." + name + ": " + verr;
            return false;
        }
        out.push_back(std::move(target));
    }
    if (out.empty()) {
        error = "targets 中没有任何 enabled: true 的目标";
        return false;
    }
    return true;
}

std::string normalize_legacy_backend(std::string backend) {
    backend = to_lower(trim(backend));
    if (backend == "lighthouse") return kProviderTencentLighthouse;
    if (backend == "cvm") return kProviderTencentCVM;
    if (backend == "aliyun_swas") return kProviderAliyunSWAS;
    if (backend == "scaleway_security_group" || backend == "scaleway_sg" || backend == "scaleway") {
        return kProviderScalewaySG;
    }
    if (backend == "hetzner_cloud_firewall" || backend == "hetzner_cloud" || backend == "hcloud") {
        return kProviderHetznerCloudFirewall;
    }
    if (backend == "hetzner_robot_firewall" || backend == "hetzner_robot" || backend == "hetzner_dedicated") {
        return kProviderHetznerRobotFirewall;
    }
    if (backend == "aws_lightsail" || backend == "lightsail") return kProviderAWSLightsail;
    if (backend == "volcengine_security_group" || backend == "volcengine_sg" || backend == "volcengine") {
        return kProviderVolcengineSG;
    }
    if (backend == "netcup_scp_firewall" || backend == "netcup_firewall" || backend == "netcup") {
        return kProviderNetcupSCPFirewall;
    }
    return backend;
}

std::optional<Target> legacy_target(const FileConfig& raw) {
    auto backend = to_lower(trim(raw.backend));
    if (backend.empty() && raw.lighthouse.instance_id.empty() && raw.cvm.security_group_id.empty() &&
        raw.aliyun_swas.instance_id.empty()) {
        return std::nullopt;
    }
    if (backend.empty()) backend = kProviderTencentLighthouse;
    backend = normalize_legacy_backend(backend);

    Target t;
    t.name = backend;
    t.provider = backend;
    t.enabled = true;
    t.region = env_or_empty(raw.tencent.region, "TENCENT_REGION");
    t.secret_id = env_or_empty(raw.tencent.secret_id, "TENCENT_SECRET_ID");
    t.secret_key = env_or_empty(raw.tencent.secret_key, "TENCENT_SECRET_KEY");
    t.instance_id = env_or_empty(raw.lighthouse.instance_id, "LIGHTHOUSE_INSTANCE_ID");
    t.security_group_id = env_or_empty(raw.cvm.security_group_id, "SECURITY_GROUP_ID");
    t.access_key_id = env_or_empty(raw.aliyun.access_key_id, "ALIBABA_CLOUD_ACCESS_KEY_ID");
    t.access_key_secret = env_or_empty(raw.aliyun.access_key_secret, "ALIBABA_CLOUD_ACCESS_KEY_SECRET");
    t.endpoint = env_or_empty(raw.aliyun.endpoint, "ALIBABA_CLOUD_ENDPOINT");

    if (backend == kProviderAliyunSWAS) {
        t.region = env_or_empty(raw.aliyun.region, "ALIBABA_CLOUD_REGION");
        t.instance_id = env_or_empty(raw.aliyun_swas.instance_id, "ALIBABA_CLOUD_SWAS_INSTANCE_ID");
    } else if (t.region.empty()) {
        t.region = env_or_empty(raw.tencent.region, "TENCENT_REGION");
    }

    apply_target_env_defaults(t);
    std::string verr;
    if (!validate_target(t, verr)) return std::nullopt;
    return t;
}

bool build_targets(const FileConfig& raw, std::vector<Target>& out, std::string& error) {
    if (!raw.targets.empty()) return parse_targets_map(raw.targets, out, error);
    if (auto legacy = legacy_target(raw)) {
        out = {*legacy};
        return true;
    }
    error = "未配置任何 targets，请在 targets 下启用至少一个厂商目标";
    return false;
}

FileConfig parse_file_config(const YAML::Node& root) {
    FileConfig raw;
    if (!root || !root.IsMap()) return raw;

    auto get_str = [&](const char* key) -> std::string {
        if (root[key] && root[key].IsScalar()) return trim(root[key].as<std::string>());
        return {};
    };

    if (root["targets"] && root["targets"].IsMap()) {
        for (const auto& item : root["targets"]) {
            raw.targets[item.first.as<std::string>()] = parse_target_yaml(item.second);
        }
    }

    raw.backend = get_str("backend");
    if (root["tencent"]) {
        raw.tencent.secret_id = trim(root["tencent"]["secret_id"].as<std::string>(""));
        raw.tencent.secret_key = trim(root["tencent"]["secret_key"].as<std::string>(""));
        raw.tencent.region = trim(root["tencent"]["region"].as<std::string>(""));
    }
    if (root["aliyun"]) {
        raw.aliyun.access_key_id = trim(root["aliyun"]["access_key_id"].as<std::string>(""));
        raw.aliyun.access_key_secret = trim(root["aliyun"]["access_key_secret"].as<std::string>(""));
        raw.aliyun.region = trim(root["aliyun"]["region"].as<std::string>(""));
        raw.aliyun.endpoint = trim(root["aliyun"]["endpoint"].as<std::string>(""));
    }
    if (root["lighthouse"]) {
        raw.lighthouse.instance_id = trim(root["lighthouse"]["instance_id"].as<std::string>(""));
    }
    if (root["aliyun_swas"]) {
        raw.aliyun_swas.instance_id = trim(root["aliyun_swas"]["instance_id"].as<std::string>(""));
    }
    if (root["cvm"]) {
        raw.cvm.security_group_id = trim(root["cvm"]["security_group_id"].as<std::string>(""));
    }

    raw.ports = parse_ports_node(root["ports"]);
    raw.protocol = get_str("protocol");
    raw.rule_description = get_str("rule_description");
    raw.remove_old_ip = parse_optional_bool(root["remove_old_ip"]);

    if (root["ip_check"]) {
        if (root["ip_check"]["urls"] && root["ip_check"]["urls"].IsSequence()) {
            for (const auto& u : root["ip_check"]["urls"]) {
                if (u.IsScalar()) {
                    auto url = trim(u.as<std::string>());
                    if (!url.empty()) raw.ip_check_urls.push_back(url);
                }
            }
        }
        if (root["ip_check"]["interval_seconds"] && root["ip_check"]["interval_seconds"].IsScalar()) {
            raw.interval_seconds = root["ip_check"]["interval_seconds"].as<int>();
        }
    }

    raw.state_file = get_str("state_file");
    return raw;
}

}  // namespace

Config load(const std::string& path, std::string& error) {
    error.clear();
    Config cfg;

    std::ifstream in(path);
    if (!in) {
        error = "无法打开配置文件: " + path;
        return cfg;
    }

    YAML::Node root;
    try {
        root = YAML::Load(in);
    } catch (const std::exception& e) {
        error = e.what();
        return cfg;
    }

    FileConfig raw;
    try {
        raw = parse_file_config(root);
    } catch (const std::exception& e) {
        error = e.what();
        return cfg;
    }

    if (!build_targets(raw, cfg.targets, error)) return cfg;

    cfg.ports = raw.ports;
    if (cfg.ports.empty()) cfg.ports = {"22"};

    cfg.ip_check_urls = raw.ip_check_urls;
    if (cfg.ip_check_urls.empty()) {
        cfg.ip_check_urls = {
            "https://ddns.oray.com/checkip",
            "https://4.ipw.cn",
        };
    }

    cfg.interval_seconds = raw.interval_seconds > 0 ? raw.interval_seconds : 300;

    auto state_file = env_or_empty(raw.state_file, "STATE_FILE");
    if (state_file.empty()) state_file = default_state_file();
    cfg.state_file = resolve_state_path(state_file);

    cfg.remove_old_ip = !raw.remove_old_ip.has_value() || *raw.remove_old_ip;

    cfg.protocol = to_upper(trim(raw.protocol));
    if (cfg.protocol.empty()) cfg.protocol = "TCP";

    cfg.rule_description = raw.rule_description.empty() ? "auto-ddns-whitelist" : raw.rule_description;
    return cfg;
}

}  // namespace firewallkeeper::config
