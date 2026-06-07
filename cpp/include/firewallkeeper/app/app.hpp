#pragma once

#include "firewallkeeper/config/config.hpp"

#include <boost/program_options.hpp>
#include <string>

namespace firewallkeeper::app {

struct CliOptions {
    std::string config_path{"config.yaml"};
    bool once{false};
    bool force{false};
    bool verbose{false};
};

boost::program_options::options_description make_options_description(
    const std::string& default_config = "config.yaml");

CliOptions parse_cli(int argc, char* argv[]);

class Application {
public:
    Application(CliOptions opts, config::Config cfg);
    int run();

private:
    bool run_once(bool force);
    void run_daemon();

    CliOptions opts_;
    config::Config cfg_;
};

}  // namespace firewallkeeper::app
