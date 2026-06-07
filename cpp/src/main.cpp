#include "firewallkeeper/app/app.hpp"
#include "firewallkeeper/config/config.hpp"

#ifdef FK_HAS_AWS_SDK
#include <aws/core/Aws.h>
#endif
#ifdef FK_HAS_TENCENT_SDK
#include <tencentcloud/core/TencentCloud.h>
#endif
#ifdef FK_HAS_VOLCENGINE_SDK
#include "volcengine/core/Volcengine.h"
#endif

#include <iostream>

namespace {

class SdkGuard {
public:
    SdkGuard() {
#ifdef FK_HAS_AWS_SDK
        Aws::InitAPI(aws_options_);
#endif
#ifdef FK_HAS_TENCENT_SDK
        TencentCloud::InitAPI();
#endif
#ifdef FK_HAS_VOLCENGINE_SDK
        volcengine::InitializeSdk();
#endif
    }

    ~SdkGuard() {
#ifdef FK_HAS_VOLCENGINE_SDK
        volcengine::CloseSdk();
#endif
#ifdef FK_HAS_TENCENT_SDK
        TencentCloud::ShutdownAPI();
#endif
#ifdef FK_HAS_AWS_SDK
        Aws::ShutdownAPI(aws_options_);
#endif
    }

    SdkGuard(const SdkGuard&) = delete;
    SdkGuard& operator=(const SdkGuard&) = delete;

private:
#ifdef FK_HAS_AWS_SDK
    Aws::SDKOptions aws_options_;
#endif
};

}  // namespace

int main(int argc, char* argv[]) {
    try {
        const SdkGuard sdk;
        const auto opts = firewallkeeper::app::parse_cli(argc, argv);

        std::string err;
        const auto cfg = firewallkeeper::config::load(opts.config_path, err);
        if (!err.empty()) {
            std::cerr << "加载配置失败: " << err << '\n';
            return 1;
        }

        firewallkeeper::app::Application app(opts, cfg);
        return app.run();
    } catch (const boost::program_options::error& e) {
        std::cerr << e.what() << '\n';
        std::cerr << firewallkeeper::app::make_options_description() << '\n';
        return 1;
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
