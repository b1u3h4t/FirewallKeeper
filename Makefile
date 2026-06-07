IMAGE ?= firewallkeeper
TAG ?= latest
COMPOSE ?= docker compose
COMPOSE_CPP ?= $(COMPOSE) -f docker-compose.yml -f docker-compose.cpp.yml

.PHONY: build run docker-build docker-up docker-down docker-logs docker-logs-f docker-once docker-init-data \
        docker-cpp-build docker-cpp-buildx docker-cpp-up docker-cpp-down docker-cpp-once help

help:
	@echo "make build              - 本地编译 FirewallKeeper (Go)"
	@echo "make docker-build       - 容器内构建 Go 镜像"
	@echo "make docker-up          - Go 版：构建并后台启动"
	@echo "make docker-cpp-build   - C++ 版：compose 构建镜像"
	@echo "make docker-cpp-buildx  - C++ 版：buildx 多架构（PLATFORMS/PUSH/REGISTRY）"
	@echo "make docker-cpp-up      - C++ 版：构建并后台启动"
	@echo "make docker-down        - 停止并删除容器"
	@echo "make docker-logs        - 查看最近日志"
	@echo "make docker-logs-f      - 持续跟踪日志"
	@echo "make docker-once        - 单次检测后退出 (Go compose)"
	@echo "make docker-cpp-once    - 单次检测后退出 (C++ compose)"
	@echo "make docker-init-data   - 初始化 /data 卷权限"

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o FirewallKeeper .

run: build
	./FirewallKeeper -c config.yaml

docker-build:
	$(COMPOSE) build

docker-build-image:
	docker build --network=host -t $(IMAGE):$(TAG) .

docker-init-data:
	$(COMPOSE) run --user root --rm --entrypoint sh firewallkeeper -c 'chown -R 1000:1000 /data'

docker-up: docker-init-data
	$(COMPOSE) up -d --build

docker-down:
	$(COMPOSE) down

docker-logs:
	$(COMPOSE) logs --tail=50

docker-logs-f:
	$(COMPOSE) logs -f --tail=50

docker-once:
	$(COMPOSE) run --rm firewallkeeper -once

docker-cpp-build:
	$(COMPOSE_CPP) build

docker-cpp-buildx:
	bash cpp/scripts/docker-build.sh

docker-cpp-up: docker-init-data-cpp
	$(COMPOSE_CPP) up -d --build

docker-cpp-down:
	$(COMPOSE_CPP) down

docker-cpp-once:
	$(COMPOSE_CPP) run --rm firewallkeeper -once

docker-init-data-cpp:
	$(COMPOSE_CPP) run --user root --rm --entrypoint sh firewallkeeper -c 'chown -R 1000:1000 /data'
