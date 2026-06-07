#include "firewallkeeper/backend/backend.hpp"

#include "firewallkeeper/ip/ip.hpp"
#include "firewallkeeper/util/string_util.hpp"

#include <aws/core/auth/AWSCredentials.h>
#include <aws/lightsail/LightsailClient.h>
#include <aws/lightsail/model/CloseInstancePublicPortsRequest.h>
#include <aws/lightsail/model/GetInstancePortStatesRequest.h>
#include <aws/lightsail/model/OpenInstancePublicPortsRequest.h>
#include <aws/lightsail/model/PortInfo.h>
#include <aws/lightsail/model/NetworkProtocol.h>
#include <iostream>
#include <memory>

namespace firewallkeeper::backend {

namespace {

using Aws::Lightsail::Model::NetworkProtocol;
using Aws::Lightsail::Model::NetworkProtocolMapper::GetNameForNetworkProtocol;
using Aws::Lightsail::Model::NetworkProtocolMapper::GetNetworkProtocolForName;

NetworkProtocol parse_network_protocol(const std::string& proto) {
    return GetNetworkProtocolForName(Aws::String(util::to_lower(proto).c_str()));
}

bool is_aws_not_found(const std::string& msg) {
    const auto lower = util::to_lower(msg);
    return util::contains_icase(lower, "notfound") || util::contains_icase(lower, "not found");
}

int parse_port(const std::string& port_str) {
    auto p = util::trim(port_str);
    if (p.empty()) throw std::runtime_error("empty port");
    if (auto dash = p.find('-'); dash != std::string::npos) {
        p = util::trim(p.substr(0, dash));
    }
    return std::stoi(p);
}

bool port_exists(const Aws::Vector<Aws::Lightsail::Model::InstancePortState>& states,
                 const std::string& proto, int port, const std::string& cidr) {
    const auto want_proto = parse_network_protocol(proto);
    for (const auto& s : states) {
        if (s.GetProtocol() != want_proto) continue;
        if (s.GetFromPort() != port || s.GetToPort() != port) continue;
        for (const auto& ip : s.GetCidrs()) {
            if (util::trim(ip) == cidr) return true;
        }
    }
    return false;
}

class AwsLightsailBackend : public IBackend {
public:
    AwsLightsailBackend(std::string name, Aws::Lightsail::LightsailClient client,
                        std::string instance_name)
        : name_(std::move(name)), client_(std::move(client)), instance_name_(std::move(instance_name)) {}

    std::string name() const override { return name_; }

    bool upsert_whitelist(const std::string& ip, const std::optional<std::string>& old_ip,
                          const config::Config& cfg, std::string& error) override {
        const auto cidr = ip::to_cidr(ip);
        const auto proto = cfg.protocol;

        Aws::Lightsail::Model::GetInstancePortStatesRequest get_req;
        get_req.SetInstanceName(instance_name_);
        const auto get_out = client_.GetInstancePortStates(get_req);
        if (!get_out.IsSuccess()) {
            error = "GetInstancePortStates: " + get_out.GetError().GetMessage();
            return false;
        }
        const auto states = get_out.GetResult().GetPortStates();

        for (const auto& port_str : cfg.ports) {
            int port = 0;
            try {
                port = parse_port(port_str);
            } catch (const std::exception& e) {
                error = "无效端口 \"" + port_str + "\": " + e.what();
                return false;
            }

            if (port_exists(states, proto, port, cidr)) {
                std::cout << "[" << name_ << "] 防火墙规则已存在，跳过: " << cidr << " " << proto
                          << " " << port << '\n';
                continue;
            }

            Aws::Lightsail::Model::PortInfo info;
            info.SetFromPort(port);
            info.SetToPort(port);
            info.SetProtocol(parse_network_protocol(proto));
            info.SetCidrs({cidr});

            Aws::Lightsail::Model::OpenInstancePublicPortsRequest open_req;
            open_req.SetInstanceName(instance_name_);
            open_req.SetPortInfo(info);
            const auto open_out = client_.OpenInstancePublicPorts(open_req);
            if (!open_out.IsSuccess()) {
                const auto msg = open_out.GetError().GetMessage();
                if (is_duplicate(msg)) {
                    std::cout << "[" << name_ << "] 防火墙规则已存在，跳过: " << cidr << " " << proto
                              << " " << port << '\n';
                    continue;
                }
                error = "OpenInstancePublicPorts: " + msg;
                return false;
            }
            std::cout << "[" << name_ << "] 已添加 AWS Lightsail 防火墙规则: " << cidr << " " << proto
                      << " " << port << '\n';
        }

        if (cfg.remove_old_ip && old_ip && !old_ip->empty() && *old_ip != ip) {
            const auto old_cidr = ip::to_cidr(*old_ip);
            for (const auto& port_str : cfg.ports) {
                try {
                    if (!close_port(proto, parse_port(port_str), old_cidr, port_str, error)) return false;
                } catch (const std::exception& e) {
                    error = "无效端口 \"" + port_str + "\": " + e.what();
                    return false;
                }
            }
        }
        return true;
    }

private:
    bool close_port(const std::string& proto, int port, const std::string& cidr,
                    const std::string& port_str, std::string& error) {
        Aws::Lightsail::Model::PortInfo info;
        info.SetFromPort(port);
        info.SetToPort(port);
        info.SetProtocol(parse_network_protocol(proto));
        info.SetCidrs({cidr});

        Aws::Lightsail::Model::CloseInstancePublicPortsRequest req;
        req.SetInstanceName(instance_name_);
        req.SetPortInfo(info);
        const auto out = client_.CloseInstancePublicPorts(req);
        if (out.IsSuccess()) {
            std::cout << "[" << name_ << "] 已删除旧 AWS Lightsail 防火墙规则: " << cidr << " "
                      << proto << " " << port << '\n';
            return true;
        }
        const auto msg = out.GetError().GetMessage();
        if (is_aws_not_found(msg) || is_not_found(msg)) {
            std::cout << "[" << name_ << "] 旧防火墙规则不存在，跳过: " << cidr << " " << port_str
                      << '\n';
            return true;
        }
        error = "CloseInstancePublicPorts: " + msg;
        return false;
    }

    std::string name_;
    Aws::Lightsail::LightsailClient client_;
    std::string instance_name_;
};

Aws::Lightsail::LightsailClient make_client(const config::Target& t) {
    Aws::Client::ClientConfiguration config;
    config.region = t.region.empty() ? "us-east-1" : t.region;
    config.requestTimeoutMs = 30000;
    Aws::Auth::AWSCredentials creds(t.access_key_id, t.access_key_secret);
    return Aws::Lightsail::LightsailClient(creds, config);
}

}  // namespace

std::unique_ptr<IBackend> new_aws_lightsail(const config::Target& t, const config::Config&,
                                             std::string& error) {
    error.clear();
    const auto instance_name = util::first_non_empty({t.instance_name, t.instance_id});
    if (instance_name.empty()) {
        error = "需要 instance_name 或 instance_id（Lightsail 实例名称）";
        return nullptr;
    }
    return std::make_unique<AwsLightsailBackend>(t.name, make_client(t), instance_name);
}

}  // namespace firewallkeeper::backend
