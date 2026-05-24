#!/bin/sh
set -e

# 确保状态目录可写（volume 首次挂载可能为 root 所有）
if [ -d /data ] && [ ! -w /data ] 2>/dev/null; then
  echo "警告: /data 不可写，请执行: docker compose run --user root --rm firewallkeeper sh -c 'chown -R 1000:1000 /data'" >&2
fi

CONFIG="${CONFIG_PATH:-/etc/FirewallKeeper/config.yaml}"

if [ ! -f "$CONFIG" ]; then
  echo "错误: 配置文件不存在: $CONFIG" >&2
  echo "请挂载 config.yaml，例如: -v ./config.yaml:$CONFIG:ro" >&2
  exit 1
fi

if [ "$#" -eq 0 ]; then
  set -- -c "$CONFIG"
else
  case "$1" in
    -c|--config)
      ;;
    *)
      set -- -c "$CONFIG" "$@"
      ;;
  esac
fi

exec /usr/local/bin/FirewallKeeper "$@"
