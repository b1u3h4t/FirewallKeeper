#!/usr/bin/env bash
# 登录 ghcr.io 以便 docker pull 私有/关联仓库的包
#
# 用法:
#   export GITHUB_TOKEN=ghp_xxxx   # 需 read:packages（私有包）或 public_repo（公开包）
#   export GITHUB_USER=b1u3h4t     # 可选，默认同 GITHUB_TOKEN 所属用户
#   bash cpp/scripts/ghcr-login.sh
#
# 拉取 C++ 镜像:
#   docker pull ghcr.io/b1u3h4t/firewallkeeper:cpp

set -euo pipefail

USER="${GITHUB_USER:-${GHCR_USER:-}}"
TOKEN="${GITHUB_TOKEN:-${GHCR_TOKEN:-}}"

if [ -z "${TOKEN}" ]; then
  echo "请设置 GITHUB_TOKEN 或 GHCR_TOKEN（GitHub PAT，至少 read:packages 权限）" >&2
  exit 1
fi

if [ -z "${USER}" ]; then
  echo "请设置 GITHUB_USER 或 GHCR_USER（GitHub 用户名）" >&2
  exit 1
fi

echo "${TOKEN}" | docker login ghcr.io -u "${USER}" --password-stdin
echo "已登录 ghcr.io (${USER})"
