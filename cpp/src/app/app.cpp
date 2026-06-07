#include "firewallkeeper/app/app.hpp"

#include "firewallkeeper/backend/backend.hpp"
#include "firewallkeeper/ip/ip.hpp"
#include "firewallkeeper/state/state.hpp"
#include "firewallkeeper/util/string_util.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <thread>
#include <vector>

namespace firewallkeeper::app {

namespace po = boost::program_options;

namespace {

std::atomic<bool> g_stop{false};

void on_signal(int) { g_stop.store(true); }

}  // namespace

boost::program_options::options_description make_options_description(
    const std::string& default_config) {
    po::options_description desc("FirewallKeeper — 公网 IP 变更时自动更新云防火墙白名单");
    desc.add_options()("help,h", "显示帮助信息")(
        "config,c", po::value<std::string>()->default_value(default_config),
        "配置文件路径（默认 config.yaml 或环境变量 CONFIG_PATH）")(
        "once", po::bool_switch()->default_value(false),
        "只执行一次后退出（支持 -once / --once，适合 cron / systemd timer）")(
        "force", po::bool_switch()->default_value(false),
        "即使 IP 与端口均未变化也强制更新（支持 -force / --force）")(
        "verbose,v", po::bool_switch()->default_value(false), "输出详细日志");
    return desc;
}

CliOptions parse_cli(int argc, char* argv[]) {
    std::string default_config = "config.yaml";
    if (auto from_env = util::env_or("", "CONFIG_PATH")) {
        default_config = *from_env;
    }

    const auto desc = make_options_description(default_config);

    std::vector<std::string> normalized;
    normalized.reserve(static_cast<size_t>(argc));
    normalized.emplace_back(argv[0]);
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-once") {
            arg = "--once";
        } else if (arg == "-force") {
            arg = "--force";
        }
        normalized.push_back(std::move(arg));
    }
    std::vector<const char*> argv_ptrs;
    argv_ptrs.reserve(normalized.size());
    for (const auto& s : normalized) argv_ptrs.push_back(s.c_str());

    po::variables_map vm;
    po::store(po::parse_command_line(static_cast<int>(argv_ptrs.size()), argv_ptrs.data(), desc), vm);

    if (vm.count("help")) {
        std::cout << desc << '\n';
        std::exit(0);
    }

    po::notify(vm);

    CliOptions opts;
    opts.config_path = vm["config"].as<std::string>();
    opts.once = vm["once"].as<bool>();
    opts.force = vm["force"].as<bool>();
    opts.verbose = vm["verbose"].as<bool>();
    return opts;
}

Application::Application(CliOptions opts, config::Config cfg)
    : opts_(std::move(opts)), cfg_(std::move(cfg)) {}

bool Application::run_once(bool force) {
    std::string err;
    const auto current_ip = ip::fetch_public_ipv4(cfg_.ip_check_urls, err);
    if (current_ip.empty()) {
        std::cerr << err << '\n';
        return false;
    }

    const auto last = state::load(cfg_.state_file, err);
    if (!err.empty()) {
        std::cerr << "读取状态: " << err << '\n';
        return false;
    }

    const bool ip_unchanged = last.ip == current_ip;
    const bool ports_unchanged = state::ports_equal(last.ports, cfg_.ports);
    if (!force && ip_unchanged && ports_unchanged) {
        std::cout << "公网 IP 与端口均未变化 (" << current_ip << ")，无需更新\n";
        return true;
    }

    if (last.ip.empty()) {
        std::cout << "公网 IP: (无) -> " << current_ip << '\n';
    } else if (!ip_unchanged) {
        std::cout << "公网 IP: " << last.ip << " -> " << current_ip << '\n';
    }
    if (!ports_unchanged) {
        std::cout << "端口: " << util::join(last.ports, ", ") << " -> "
                  << util::join(cfg_.ports, ", ") << '\n';
    }

    auto backends = backend::new_all(cfg_, err);
    if (backends.empty()) {
        std::cerr << err << '\n';
        return false;
    }

    std::vector<std::string> names;
    names.reserve(backends.size());
    for (const auto& b : backends) names.push_back(b->name());

    if (opts_.verbose) {
        std::cout << "[verbose] state_file=" << cfg_.state_file << '\n';
    }
    std::cout << "已启用 " << backends.size() << " 个目标: " << util::join(names, ", ") << '\n';

    std::optional<std::string> old_ip;
    if (!last.ip.empty()) old_ip = last.ip;

    if (!backend::upsert_all(backends, current_ip, old_ip, cfg_, err)) {
        std::cerr << err << '\n';
        return false;
    }

    state::Snapshot snap{current_ip, cfg_.ports};
    if (!state::save(cfg_.state_file, snap, err)) {
        std::cerr << "保存状态: " << err << '\n';
        return false;
    }

    std::cout << "全部目标防火墙白名单已更新为 " << current_ip << '\n';
    return true;
}

void Application::run_daemon() {
    std::cout << "守护模式启动，检测间隔 " << cfg_.interval_seconds << " 秒\n";

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    bool first_force = opts_.force;
    while (!g_stop.load()) {
        if (!run_once(first_force) && opts_.verbose) {
            std::cerr << "[verbose] 本轮更新未完成\n";
        }
        first_force = false;

        for (int i = 0; i < cfg_.interval_seconds && !g_stop.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
    std::cout << "已退出\n";
}

int Application::run() {
    if (opts_.once) {
        return run_once(opts_.force) ? 0 : 1;
    }
    run_daemon();
    return 0;
}

}  // namespace firewallkeeper::app
