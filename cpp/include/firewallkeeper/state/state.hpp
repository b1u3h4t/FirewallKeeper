#pragma once

#include <string>
#include <vector>

namespace firewallkeeper::state {

struct Snapshot {
    std::string ip;
    std::vector<std::string> ports;
};

Snapshot load(const std::string& path, std::string& error);
bool save(const std::string& path, const Snapshot& snap, std::string& error);

std::vector<std::string> normalize_ports(const std::vector<std::string>& ports);
bool ports_equal(const std::vector<std::string>& a, const std::vector<std::string>& b);

}  // namespace firewallkeeper::state
