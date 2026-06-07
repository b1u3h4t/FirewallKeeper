#include "firewallkeeper/config/config.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>

namespace fs = std::filesystem;

static int failures = 0;

#define CHECK(cond, msg)                         \
    do {                                         \
        if (!(cond)) {                           \
            std::cerr << "FAIL: " << msg << '\n'; \
            ++failures;                          \
        }                                        \
    } while (0)

int main() {
    auto dir = fs::temp_directory_path() / "fk_cpp_cfg_test";
    fs::create_directories(dir);
    auto path = (dir / "config.yaml").string();

    {
        std::ofstream out(path);
        out << R"(
ports: "22,443"
protocol: TCP
rule_description: test
remove_old_ip: false
ip_check:
  interval_seconds: 60
  urls:
    - "https://example.com/checkip"
state_file: "/tmp/fk-state.json"
targets:
  hetzner_cloud:
    enabled: true
    provider: hetzner_cloud_firewall
    api_token: "token"
    firewall_id: "123"
)";
    }

    std::string err;
    auto cfg = firewallkeeper::config::load(path, err);
    CHECK(err.empty(), "load error: " + err);
    CHECK(cfg.ports.size() == 2, "ports count");
    CHECK(cfg.interval_seconds == 60, "interval");
    CHECK(cfg.targets.size() == 1, "targets count");
    CHECK(cfg.targets[0].provider == firewallkeeper::config::kProviderHetznerCloudFirewall,
          "provider");

    fs::remove_all(dir);
    return failures == 0 ? 0 : 1;
}
