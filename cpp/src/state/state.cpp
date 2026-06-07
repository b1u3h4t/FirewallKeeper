#include "firewallkeeper/state/state.hpp"

#include "firewallkeeper/util/string_util.hpp"

#include <boost/filesystem.hpp>
#include <fstream>
#include <nlohmann/json.hpp>
#include <set>

namespace firewallkeeper::state {

namespace fs = boost::filesystem;
using json = nlohmann::json;

std::vector<std::string> normalize_ports(const std::vector<std::string>& ports) {
    std::set<std::string> seen;
    for (auto p : ports) {
        util::trim_inplace(p);
        if (!p.empty()) seen.insert(std::move(p));
    }
    return {seen.begin(), seen.end()};
}

bool ports_equal(const std::vector<std::string>& a, const std::vector<std::string>& b) {
    return normalize_ports(a) == normalize_ports(b);
}

Snapshot load(const std::string& path, std::string& error) {
    error.clear();
    if (!fs::exists(path)) return {};

    std::ifstream in(path);
    if (!in) {
        error = "无法读取状态文件: " + path;
        return {};
    }

    json j;
    try {
        in >> j;
    } catch (...) {
        return {};
    }

    Snapshot snap;
    snap.ip = j.value("last_ip", std::string{});
    if (j.contains("last_ports") && j["last_ports"].is_array()) {
        for (const auto& p : j["last_ports"]) {
            if (p.is_string()) snap.ports.push_back(p.get<std::string>());
        }
    }
    return snap;
}

bool save(const std::string& path, const Snapshot& snap, std::string& error) {
    error.clear();
    fs::path p(path);
    if (p.has_parent_path()) {
        boost::system::error_code ec;
        fs::create_directories(p.parent_path(), ec);
    }

    json j;
    j["last_ip"] = snap.ip;
    j["last_ports"] = normalize_ports(snap.ports);

    std::ofstream out(path);
    if (!out) {
        error = "无法写入状态文件: " + path;
        return false;
    }
    out << j.dump(2) << '\n';
    return true;
}

}  // namespace firewallkeeper::state
