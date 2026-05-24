# FirewallKeeper

当本地公网 IP 发生变化时，自动调用腾讯云 API，将当前 IP 加入服务器防火墙白名单（指定端口）。

| 后端 | 场景 | API |
|------|------|-----|
| `lighthouse` | 轻量应用服务器 | CreateFirewallRules / DeleteFirewallRules |
| `cvm` | 云服务器安全组 | CreateSecurityGroupPolicies / DeleteSecurityGroupPolicies |

## 构建与运行

### 本地编译

```bash
cd FirewallKeeper

cp config.example.yaml config.yaml
# 编辑 config.yaml

make build
# 或 go build -o FirewallKeeper .

# 单次检测（cron / systemd timer）
./FirewallKeeper -once -c config.yaml

# 守护进程轮询
./FirewallKeeper -c config.yaml
```

### Docker 一键部署（推荐）

**asus 等内网机器建议先配置镜像加速**（示例 `deploy/docker-daemon.json.example`）：

```bash
sudo cp deploy/docker-daemon.json.example /etc/docker/daemon.json
sudo systemctl restart docker
```

```bash
# 1. 准备配置（Docker 建议 state 写到 /data）
cp config.docker.example.yaml config.yaml
# 编辑 config.yaml：密钥、地域、lhins 实例 ID、端口

# 2. 可选：用 .env 注入密钥（覆盖 config 中同名环境变量）
cp .env.example .env

# 3. 容器内多阶段构建并后台运行（Go: goproxy.cn，需 Docker 镜像加速）
make docker-up
# 等价于: docker compose up -d --build

# 查看日志
make docker-logs

# 单次检测（适合宿主机 cron）
make docker-once

# 停止
make docker-down
```

仅使用 Docker（容器内编译）：

```bash
docker build --network=host -t firewallkeeper:latest .
docker run -d --name FirewallKeeper --restart unless-stopped \
  -v "$(pwd)/config.yaml:/etc/FirewallKeeper/config.yaml:ro" \
  -v firewallkeeper-data:/data \
  -e TZ=Asia/Shanghai \
  firewallkeeper:latest
```

> 构建说明：`Dockerfile` 多阶段编译，Go 依赖通过 `GOPROXY=https://goproxy.cn` 拉取；`docker compose` 使用 `build.network: host` 避免构建容器 DNS/出网问题；拉取 `golang`/`alpine` 基础镜像需配置 `registry-mirrors`（如 `https://docker.deepflood.xyz`）。

### 安装 Docker Compose 插件（Ubuntu）

宿主机需 `docker compose`（V2 插件），不要用旧版 `docker-compose` 独立命令：

```bash
sudo apt-get update
sudo apt-get install -y docker-compose-v2
docker compose version
```

可选：卸载 `/usr/local/bin/docker-compose` 以免混淆。

**说明**

| 挂载 | 作用 |
|------|------|
| `config.yaml` → `/etc/FirewallKeeper/config.yaml` | 业务配置 |
| volume `firewallkeeper-data` → `/data` | 持久化上次公网 IP（`state_file: /data/state.json`） |

环境变量 `CONFIG_PATH` 可改配置文件路径；`TENCENT_SECRET_ID` 等可覆盖 yaml 中的密钥字段。

## 配置

见 [config.example.yaml](config.example.yaml)。环境变量可覆盖：

- `TENCENT_SECRET_ID` / `TENCENT_SECRET_KEY` / `TENCENT_REGION`
- `LIGHTHOUSE_INSTANCE_ID`（lighthouse）
- `SECURITY_GROUP_ID`（cvm）

## systemd 示例

```ini
[Unit]
Description=FirewallKeeper - Tencent Cloud firewall IP whitelist updater
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/path/to/FirewallKeeper
ExecStart=/path/to/FirewallKeeper/FirewallKeeper -once -c config.yaml

[Install]
WantedBy=multi-user.target
```

```ini
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
```

## CAM 权限

- 轻量：`lighthouse:CreateFirewallRules`、`lighthouse:DeleteFirewallRules`
- CVM：`vpc:CreateSecurityGroupPolicies`、`vpc:DeleteSecurityGroupPolicies`
