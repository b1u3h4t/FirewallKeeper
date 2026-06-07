#!/usr/bin/env bash
# Docker Buildx 多架构构建 / 推送 C++ 镜像
#
# 本地加载（当前平台）:
#   bash cpp/scripts/docker-build.sh
#
# 多架构构建并推送到 registry:
#   IMAGE=ghcr.io/you/firewallkeeper TAG=cpp \
#   PLATFORMS=linux/amd64,linux/arm64 PUSH=1 \
#   bash cpp/scripts/docker-build.sh
#
# 多架构导出 OCI 归档:
#   PLATFORMS=linux/amd64,linux/arm64 OUTPUT=oci \
#   bash cpp/scripts/docker-build.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${ROOT}"

IMAGE="${IMAGE:-firewallkeeper}"
TAG="${TAG:-cpp}"
DOCKERFILE="${DOCKERFILE:-Dockerfile.cpp}"
BUILDER="${BUILDX_BUILDER:-fk-cpp-builder}"
PUSH="${PUSH:-0}"
LOAD="${LOAD:-1}"
OUTPUT="${OUTPUT:-}"

# 默认仅当前平台，便于 --load；多架构请 PUSH=1 或 OUTPUT=oci
if [ -z "${PLATFORMS:-}" ]; then
  PLATFORMS="linux/$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')"
fi

if ! docker buildx version >/dev/null 2>&1; then
  echo "需要 Docker Buildx（Docker 20.10+ / compose v2）" >&2
  exit 1
fi

if ! docker buildx inspect "${BUILDER}" >/dev/null 2>&1; then
  docker buildx create --name "${BUILDER}" --driver docker-container --use
else
  docker buildx use "${BUILDER}"
fi

args=(
  --file "${DOCKERFILE}"
  --tag "${IMAGE}:${TAG}"
  --platform "${PLATFORMS}"
  --progress plain
)

if [ -n "${REGISTRY:-}" ]; then
  args+=(--tag "${REGISTRY}/${IMAGE}:${TAG}")
fi

if [ "${PUSH}" = "1" ]; then
  args+=(--push)
elif [ "${OUTPUT}" = "oci" ]; then
  mkdir -p "${ROOT}/dist"
  safe_tag="${IMAGE//\//_}-${TAG}"
  args+=(--output "type=oci,dest=${ROOT}/dist/${safe_tag}.tar")
  LOAD=0
elif [ "${LOAD}" = "1" ]; then
  if [[ "${PLATFORMS}" == *","* ]]; then
    echo "多平台镜像无法用 --load 导入本地，请 PUSH=1 或 OUTPUT=oci" >&2
    exit 1
  fi
  args+=(--load)
else
  args+=(--output type=docker)
fi

echo "==> buildx ${IMAGE}:${TAG} platforms=${PLATFORMS}"
docker buildx build "${args[@]}" .

echo "==> 完成"
if [ "${PUSH}" = "1" ]; then
  echo "已推送: ${IMAGE}:${TAG} (${PLATFORMS})"
elif [ "${OUTPUT}" = "oci" ]; then
  echo "OCI 归档: ${ROOT}/dist/${IMAGE//\//_}-${TAG}.tar"
elif [ "${LOAD}" = "1" ]; then
  docker image inspect "${IMAGE}:${TAG}" >/dev/null
  echo "本地镜像: ${IMAGE}:${TAG}"
fi
