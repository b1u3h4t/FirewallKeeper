# syntax=docker/dockerfile:1
# FirewallKeeper C++ 多阶段镜像（linux/amd64 + linux/arm64）
# 本地单架构: docker build -f Dockerfile.cpp -t firewallkeeper:cpp .
# 多架构推送: bash cpp/scripts/docker-build.sh PUSH=1

ARG DEBIAN_VERSION=trixie

# ---------- 编译阶段 ----------
FROM debian:${DEBIAN_VERSION}-slim AS builder

ARG TARGETARCH
ARG AWS_SDK_VERSION=1.11.810
ARG JOBS=4

ENV DEBIAN_FRONTEND=noninteractive \
    PREFIX=/usr/local

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update \
    && apt-get install -y --no-install-recommends \
      build-essential \
      ca-certificates \
      cmake \
      git \
      libboost-all-dev \
      libcurl4-openssl-dev \
      libssl-dev \
      libyaml-dev \
      pkg-config \
    && rm -rf /var/lib/apt/lists/*

# AWS C++ SDK（Lightsail，共享库安装到 /usr/local；源码/构建目录用 cache 加速）
RUN --mount=type=cache,target=/tmp/aws-cache \
    if [ -f "${PREFIX}/lib/cmake/AWSSDK/AWSSDKConfig.cmake" ]; then exit 0; fi \
    && AWS_SRC=/tmp/aws-cache/src \
    && AWS_BUILD=/tmp/aws-cache/build \
    && if [ ! -d "${AWS_SRC}/.git" ]; then \
         rm -rf "${AWS_SRC}" "${AWS_BUILD}" \
         && git clone --depth 1 --recurse-submodules --shallow-submodules \
           -b "${AWS_SDK_VERSION}" https://github.com/aws/aws-sdk-cpp.git "${AWS_SRC}"; \
       fi \
    && cmake -S "${AWS_SRC}" -B "${AWS_BUILD}" \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX="${PREFIX}" \
      -DBUILD_ONLY=lightsail \
      -DBUILD_SHARED_LIBS=ON \
      -DENABLE_TESTING=OFF \
      -DBUILD_DEPS=ON \
    && cmake --build "${AWS_BUILD}" -j"${JOBS}" \
    && cmake --install "${AWS_BUILD}" \
    && ldconfig

WORKDIR /src
COPY cpp cpp

RUN --mount=type=cache,target=/root/.cache/ccache \
    FK_SKIP_APT=1 FK_SKIP_AWS_SDK=1 FK_SKIP_CTEST="${FK_SKIP_CTEST:-0}" JOBS="${JOBS}" \
    bash cpp/scripts/build-linux.sh

# ---------- 运行阶段 ----------
FROM debian:${DEBIAN_VERSION}-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    CONFIG_PATH=/etc/FirewallKeeper/config.yaml \
    TZ=Asia/Shanghai

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      ca-certificates \
      tzdata \
      libboost-filesystem1.83.0 \
      libboost-program-options1.83.0 \
      libcurl4 \
      libssl3 \
      libyaml-cpp0.8 \
    && rm -rf /var/lib/apt/lists/*

# AWS SDK 及其依赖（/usr/local 下由 builder 安装）
COPY --from=builder /usr/local/lib/ /usr/local/lib/
COPY --from=builder /usr/local/bin/FirewallKeeper /usr/local/bin/FirewallKeeper
COPY docker/entrypoint.sh /entrypoint.sh

RUN ldconfig \
    && chmod +x /entrypoint.sh /usr/local/bin/FirewallKeeper \
    && mkdir -p /data && chown -R 1000:1000 /data

USER 1000:1000
WORKDIR /app

VOLUME ["/data"]

ENTRYPOINT ["/entrypoint.sh"]
CMD []

LABEL org.opencontainers.image.title="FirewallKeeper (C++)" \
      org.opencontainers.image.description="公网 IP 变更时自动更新云防火墙白名单 — C++ 版"
