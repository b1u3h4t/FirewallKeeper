#!/bin/sh
# Ubuntu 24.04: 安装 docker compose V2 插件（保留现有 docker.io 与 daemon.json）
set -e

if [ "$(id -u)" -ne 0 ]; then
  echo "请使用 root 运行: sudo $0" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y docker-compose-v2

# 卸载 apt 旧版 docker-compose v1（Python 独立命令）
if dpkg -l docker-compose 2>/dev/null | grep -q '^ii'; then
  apt-get remove -y docker-compose
fi

if [ -x /usr/local/bin/docker-compose ]; then
  echo "建议移除旧二进制: rm /usr/local/bin/docker-compose"
fi

docker compose version
echo "安装完成。请使用: docker compose up -d"
