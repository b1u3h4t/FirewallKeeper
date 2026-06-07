#!/usr/bin/env bash
# Debian/Ubuntu 服务器一键编译 FirewallKeeper C++ 版
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CPP_DIR="${ROOT}/cpp"
BUILD_DIR="${CPP_DIR}/build"
JOBS="${JOBS:-$(nproc)}"
PREFIX="${PREFIX:-/usr/local}"

export DEBIAN_FRONTEND=noninteractive

if [ "${FK_SKIP_APT:-0}" != "1" ]; then
  echo "==> 安装系统依赖"
  apt-get update -qq
  apt-get install -y -qq \
    build-essential \
    cmake \
    git \
    libboost-all-dev \
    libcurl4-openssl-dev \
    libssl-dev \
    libyaml-dev \
    pkg-config
fi

install_aws_sdk() {
  if [[ -f "${PREFIX}/lib/cmake/AWSSDK/AWSSDKConfig.cmake" ]]; then
    echo "==> AWS SDK 已安装: ${PREFIX}"
    return 0
  fi
  echo "==> 编译 AWS SDK (lightsail only, 首次较慢)"
  local aws_src="/tmp/aws-sdk-cpp-build"
  rm -rf "${aws_src}"
  git clone --depth 1 --recurse-submodules --shallow-submodules \
    -b 1.11.810 https://github.com/aws/aws-sdk-cpp.git "${aws_src}"
  cmake -S "${aws_src}" -B "${aws_src}/build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="${PREFIX}" \
    -DBUILD_ONLY=lightsail \
    -DBUILD_SHARED_LIBS=ON \
    -DENABLE_TESTING=OFF \
    -DBUILD_DEPS=ON
  cmake --build "${aws_src}/build" -j"${JOBS}"
  cmake --install "${aws_src}/build"
  ldconfig 2>/dev/null || true
}

if [ "${FK_SKIP_AWS_SDK:-0}" != "1" ]; then
  install_aws_sdk
fi

echo "==> 配置 CMake (${BUILD_DIR})"
rm -rf "${BUILD_DIR}"
cmake -S "${CPP_DIR}" -B "${BUILD_DIR}" \
  -DCMAKE_BUILD_TYPE=Release \
  -DFK_CXX_STANDARD=20 \
  -DCMAKE_PREFIX_PATH="${PREFIX}"

echo "==> 编译 FirewallKeeper (jobs=${JOBS})"
cmake --build "${BUILD_DIR}" -j"${JOBS}"

if [ "${FK_SKIP_CTEST:-0}" != "1" ]; then
  echo "==> 运行测试"
  ctest --test-dir "${BUILD_DIR}" --output-on-failure
fi

echo "==> 安装二进制"
install -m 755 "${BUILD_DIR}/FirewallKeeper" "${PREFIX}/bin/FirewallKeeper"

echo "==> 完成"
"${PREFIX}/bin/FirewallKeeper" --help 2>&1 | head -5 || true
ls -la "${BUILD_DIR}/FirewallKeeper" "${PREFIX}/bin/FirewallKeeper"
