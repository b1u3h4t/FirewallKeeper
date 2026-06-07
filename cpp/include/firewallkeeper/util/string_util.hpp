#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace firewallkeeper::util {

std::string trim(std::string_view s);
void trim_inplace(std::string& s);
std::string to_lower(std::string s);
std::string to_upper(std::string s);
bool iequals(std::string_view a, std::string_view b);
bool contains_icase(std::string_view haystack, std::string_view needle);
std::string truncate_str(std::string_view s, size_t n);
std::string first_non_empty(std::initializer_list<std::string_view> values);
std::vector<std::string> split_ports(std::string_view s);
std::string join(const std::vector<std::string>& parts, std::string_view sep);
std::optional<std::string> env_or(std::string_view value, std::string_view env_name);

}  // namespace firewallkeeper::util
