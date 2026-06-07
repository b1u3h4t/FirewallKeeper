#include "firewallkeeper/util/string_util.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <sstream>

namespace firewallkeeper::util {

std::string trim(std::string_view s) {
    const auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string_view::npos) return {};
    const auto end = s.find_last_not_of(" \t\r\n");
    return std::string(s.substr(start, end - start + 1));
}

void trim_inplace(std::string& s) { s = trim(s); }

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string to_upper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return s;
}

std::string truncate_str(std::string_view s, size_t n) {
    if (s.size() <= n) return std::string(s);
    return std::string(s.substr(0, n)) + "...";
}

std::string first_non_empty(std::initializer_list<std::string_view> values) {
    for (auto v : values) {
        auto t = trim(v);
        if (!t.empty()) return t;
    }
    return {};
}

bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

bool contains_icase(std::string_view haystack, std::string_view needle) {
    const auto h = to_lower(std::string(haystack));
    const auto n = to_lower(std::string(needle));
    return h.find(n) != std::string::npos;
}

std::vector<std::string> split_ports(std::string_view s) {
    std::vector<std::string> out;
    std::string_view rest = s;
    while (!rest.empty()) {
        const auto pos = rest.find(',');
        const auto part = trim(pos == std::string_view::npos ? rest : rest.substr(0, pos));
        if (!part.empty()) out.push_back(part);
        if (pos == std::string_view::npos) break;
        rest = rest.substr(pos + 1);
    }
    return out;
}

std::string join(const std::vector<std::string>& parts, std::string_view sep) {
    std::ostringstream oss;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) oss << sep;
        oss << parts[i];
    }
    return oss.str();
}

std::optional<std::string> env_or(std::string_view value, std::string_view env_name) {
    auto t = trim(value);
    if (!t.empty()) return t;
    if (env_name.empty()) return std::nullopt;
    if (const char* raw = std::getenv(std::string(env_name).c_str())) {
        auto ev = trim(std::string_view(raw));
        if (!ev.empty()) return ev;
    }
    return std::nullopt;
}

}  // namespace firewallkeeper::util
