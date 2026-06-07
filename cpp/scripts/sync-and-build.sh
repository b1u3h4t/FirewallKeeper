#!/usr/bin/env bash
# 同步源码到 Linux 服务器并编译（排除 build 目录）
set -euo pipefail

REMOTE="${1:-proxy_deb13}"
DEST="${2:-/root/git/FirewallKeeper}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

echo "==> rsync ${ROOT} -> ${REMOTE}:${DEST}"
rsync -avz --delete \
  --exclude '.git/' \
  --exclude 'cpp/build/' \
  --exclude 'build/' \
  --exclude '.cursor/' \
  "${ROOT}/" "${REMOTE}:${DEST}/"

rsync -avz "${ROOT}/cpp/cmake/" "${REMOTE}:${DEST}/cpp/cmake/"
rsync -avz "${ROOT}/cpp/scripts/" "${REMOTE}:${DEST}/cpp/scripts/"

echo "==> 远程编译"
ssh "${REMOTE}" "nohup bash ${DEST}/cpp/scripts/build-linux.sh > ${DEST}/build-linux.log 2>&1 & echo PID=\$!"
