#pragma once

#include <map>
#include <optional>
#include <string>
#include <vector>

namespace firewallkeeper::util {

struct HttpResponse {
    long status = 0;
    std::string body;
    std::map<std::string, std::string> headers;
};

struct HttpRequest {
    std::string method = "GET";
    std::string url;
    std::map<std::string, std::string> headers;
    std::string body;
    long timeout_seconds = 30;
};

class HttpClient {
public:
    HttpResponse request(const HttpRequest& req) const;
};

}  // namespace firewallkeeper::util
