#pragma once

#include <string>
#include <vector>

namespace firewallkeeper::ip {

std::string fetch_public_ipv4(const std::vector<std::string>& urls, std::string& error);
std::string to_cidr(const std::string& ip);

}  // namespace firewallkeeper::ip
