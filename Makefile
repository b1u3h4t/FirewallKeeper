IMAGE ?= firewallkeeper
TAG ?= latest
COMPOSE ?= docker compose

.PHONY: build run docker-build docker-up docker-down docker-logs docker-logs-f docker-once docker-init-data help

help:
	@echo "make build            - 本地编译 FirewallKeeper"
	@echo "make docker-build     - 容器内多阶段构建镜像"
	@echo "make docker-up        - 构建并后台启动（守护模式）"
	@echo "make docker-down      - 停止并删除容器"
	@echo "make docker-logs      - 查看最近日志（立即退出）"
	@echo "make docker-logs-f    - 持续跟踪日志（Ctrl+C 结束，会一直占用终端）"
	@echo "make docker-once      - 单次检测后退出"
	@echo "make docker-init-data - 初始化 /data 卷权限"

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
