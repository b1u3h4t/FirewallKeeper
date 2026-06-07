#include "firewallkeeper/state/state.hpp"

#include <cassert>
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
    auto dir = fs::temp_directory_path() / "fk_cpp_test";
    fs::create_directories(dir);
    auto path = (dir / "state.json").string();

    firewallkeeper::state::Snapshot snap;
    snap.ip = "203.0.113.1";
    snap.ports = {"443", "22", "22"};

    std::string err;
    CHECK(firewallkeeper::state::save(path, snap, err), "save failed: " + err);

    auto got = firewallkeeper::state::load(path, err);
    CHECK(err.empty(), "load error: " + err);
    CHECK(got.ip == snap.ip, "ip mismatch");
    CHECK(firewallkeeper::state::ports_equal(got.ports, {"22", "443"}), "ports mismatch");

    auto legacy_path = (dir / "legacy.json").string();
    {
        std::ofstream out(legacy_path);
        out << R"({"last_ip":"203.0.113.1"})" << '\n';
    }
    got = firewallkeeper::state::load(legacy_path, err);
    CHECK(got.ports.empty(), "legacy ports should be empty");
    CHECK(firewallkeeper::state::ports_equal({}, {}), "nil ports equal");

    fs::remove_all(dir);
    return failures == 0 ? 0 : 1;
}
