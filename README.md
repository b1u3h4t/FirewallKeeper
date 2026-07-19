# FirewallKeeper

当本地公网 IP 发生变化时，自动将当前 IP 加入**一个或多个**云服务器防火墙白名单（指定端口）。

**可同时启用多个目标**：例如腾讯云轻量 + 阿里云国际版 SWAS，一次 IP 变更会更新全部 `enabled: true` 的 targets。

## 支持的后端（provider）

| provider | 云厂商 | 场景 |
|----------|--------|------|
| `tencent_lighthouse` | 腾讯云 | 轻量应用服务器防火墙 |
| `tencent_cvm` | 腾讯云 | CVM 安全组入站 |
| `aliyun_swas` | 阿里云国际版 | Simple Application Server 防火墙 |
| `scaleway_security_group` | Scaleway | Instance 安全组入站规则 |
| `hetzner_cloud_firewall` | Hetzner Cloud | 云服务器 Firewall 入站规则（[api.hetzner.cloud](https://docs.hetzner.cloud/)） |
| `hetzner_robot_firewall` | Hetzner Robot | 独立服务器无状态防火墙（[Robot Web Service](https://docs.hetzner.com/robot/)） |
| `aws_lightsail` | AWS | Lightsail 实例防火墙端口（[Lightsail API](https://docs.aws.amazon.com/lightsail/)） |
| `volcengine_security_group` | 火山引擎 | ECS/VPC 安全组入站（[私有网络 API](https://www.volcengine.com/docs/6401/70748)） |
| `netcup_scp_firewall` | Netcup | SCP 防火墙策略入站规则（[netcup-cli](https://github.com/pavelpikta/netcup-cli) / [SCP API](https://www.servercontrolpanel.de)） |

后续扩展新厂商：在 `targets` 中增加对应 `provider` 配置即可。

## 配置（多目标）

```yaml
ports:
  - "22"
  - "443"

protocol: TCP
remove_old_ip: true

targets:
  tencent_lighthouse:
    enabled: true
    region: "ap-beijing"
    secret_id: "AKIDxxx"
    secret_key: "xxx"
    instance_id: "lhins-xxxx"

  aliyun_swas:
    enabled: true
    region: "us-east-1"
    access_key_id: "LTAIxxx"
    access_key_secret: "xxx"
    instance_id: "your-instance-id"

  tencent_cvm:
    enabled: false   # 关闭的目标不会调用 API

  scaleway_vps:
    provider: scaleway_security_group
    enabled: true
    zone: "fr-par-1"
    secret_key: "scw-secret-key"
    security_group_id: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

  hetzner_cloud:
    provider: hetzner_cloud_firewall
    enabled: true
    api_token: "your-hcloud-token"
    firewall_id: "12345"

  hetzner_dedicated:
    provider: hetzner_robot_firewall
    enabled: true
    robot_user: "your-robot-user"
    robot_password: "your-robot-password"
    server_number: "321"

  aws_lightsail:
    provider: aws_lightsail
    enabled: true
    region: "us-east-1"
    access_key_id: "AKIAxxx"
    access_key_secret: "xxx"
    instance_name: "MyLightsailInstance"

  volcengine_sg:
    provider: volcengine_security_group
    enabled: true
    region: "cn-beijing"
    access_key_id: "AKLTxxx"
    access_key_secret: "xxx"
    security_group_id: "sg-xxxxxxxx"
```

同一 `provider` 可配置多个实例（自定义 key 并指定 `provider` 字段）：

```yaml
  aliyun_swas_us:
    provider: aliyun_swas
    enabled: true
    region: "us-east-1"
    ...
  aliyun_swas_eu:
    provider: aliyun_swas
    enabled: true
    region: "eu-central-1"
    ...
```

## 端口与规则条数（腾讯轻量 / CVM）

腾讯云轻量防火墙单实例约 **100 条**规则上限。Go / C++ 版对 **腾讯轻量**、**CVM 安全组**会把配置里的多个端口**自动合并成 1 条规则**（`Port=22,443,6000`），显著降低配额占用。

```yaml
ports:
  - "22"
  - "443"
  - "6000"
# 等价于一条规则 Port=22,443,6000
# 也可直接写: ports: ["22,443,6000-6002"]
```

其它云厂商仍按各自 API 能力逐端口处理。建议开启 `remove_old_ip: true`，IP 变更时先删旧再加新。

## 运行

```bash
cp config.example.yaml config.yaml
make build
./FirewallKeeper -once -c config.yaml
./FirewallKeeper -c config.yaml    # 守护模式
```

日志示例：

```
已启用 2 个目标: tencent_lighthouse, aliyun_swas
[tencent_lighthouse] 已添加轻量防火墙规则: ...
[aliyun_swas] 已添加阿里云 SWAS 防火墙规则: ...
全部目标防火墙白名单已更新为 x.x.x.x
```

任一目标失败则**不会写入状态文件**，下次轮询会重试全部目标。

## Docker

**Go 版（默认，镜像小、构建快）：**

```bash
cp config.docker.example.yaml config.yaml
make docker-up
make docker-logs
```

**C++ 版（含 AWS / 腾讯云 / 火山官方 SDK）：**

```bash
cp config.docker.example.yaml config.yaml
make docker-cpp-up          # compose 单架构构建并启动
make docker-cpp-once        # 单次检测
```

多架构构建与推送（Buildx，`linux/amd64` + `linux/arm64`）：

```bash
# 本地加载当前平台
bash cpp/scripts/docker-build.sh

# 推送到 registry（示例 GHCR）
IMAGE=ghcr.io/<user>/firewallkeeper TAG=cpp \
PLATFORMS=linux/amd64,linux/arm64 PUSH=1 \
REGISTRY=ghcr.io/<user> \
bash cpp/scripts/docker-build.sh
```

也可通过环境变量切换 compose 使用的 Dockerfile：

```bash
DOCKERFILE=Dockerfile.cpp IMAGE=firewallkeeper:cpp make docker-up
```

## 环境变量

全局密钥仍可通过环境变量注入（对所有未在 yaml 填写的同类型字段生效）：

- 腾讯云：`TENCENT_SECRET_ID`、`TENCENT_SECRET_KEY`、`TENCENT_REGION`、`LIGHTHOUSE_INSTANCE_ID`、`SECURITY_GROUP_ID`
- 阿里云：`ALIBABA_CLOUD_ACCESS_KEY_ID`、`ALIBABA_CLOUD_ACCESS_KEY_SECRET`、`ALIBABA_CLOUD_REGION`、`ALIBABA_CLOUD_SWAS_INSTANCE_ID`
- Scaleway：`SCW_SECRET_KEY`（或 `SCW_API_TOKEN`）、`SCW_DEFAULT_ZONE`、`SCW_SECURITY_GROUP_ID`
- Hetzner Cloud：`HCLOUD_TOKEN`、`HCLOUD_FIREWALL_ID`
- Hetzner Robot：`HETZNER_ROBOT_USER`、`HETZNER_ROBOT_PASSWORD`、`HETZNER_ROBOT_SERVER_NUMBER`
- AWS Lightsail：`AWS_ACCESS_KEY_ID`、`AWS_SECRET_ACCESS_KEY`、`AWS_REGION`、`AWS_LIGHTSAIL_INSTANCE_NAME`
- 火山引擎：`VOLCENGINE_ACCESS_KEY_ID`、`VOLCENGINE_SECRET_ACCESS_KEY`、`VOLCENGINE_REGION`、`VOLCENGINE_SECURITY_GROUP_ID`
- Netcup SCP：`NETCUP_SCP_REFRESH_TOKEN`、`NETCUP_FIREWALL_POLICY_ID`

### Netcup SCP 说明

基于 [netcup-cli](https://github.com/pavelpikta/netcup-cli) 使用的 **Server Control Panel REST API**：

1. 安装 netcup-cli 并登录：`netcup auth login`（浏览器设备码 OAuth）。
2. 从 `~/.config/netcup-cli/credentials` 复制 `refresh_token` 到配置 `refresh_token`。
3. 在 SCP 控制台创建或选定**防火墙策略**，将 `firewall_policy_id` 填为策略数字 ID；策略需已绑定到目标 VPS 网卡。
4. 可选：填写 `server_id` + `interface_mac`，更新策略后调用 `firewall:reapply` 立即生效（不填则依赖 SCP 自动同步）。
5. 规则写入策略的 `INGRESS` / `ACCEPT`，`sources` 为 CIDR，`destinationPorts` 为端口。

### AWS Lightsail 说明

1. IAM 用户需具备 Lightsail 网络相关权限（如 `lightsail:OpenInstancePublicPorts`、`CloseInstancePublicPorts`、`GetInstancePortStates`）。
2. `instance_name` 为 Lightsail 控制台中的**实例名称**（非 ARN/ID）。
3. 使用 `OpenInstancePublicPorts` 追加规则，不会关闭已有其他 IP 的端口规则；删除旧 IP 时调用 `CloseInstancePublicPorts`。

### 火山引擎说明

1. 适用于绑定到 ECS 实例的 **VPC 安全组**（与腾讯云 CVM 安全组类似）。
2. 在 [火山引擎控制台](https://console.volcengine.com/) 创建 Access Key，并复制安全组 ID。
3. API：`AuthorizeSecurityGroupIngress` / `RevokeSecurityGroupIngress`（服务 `vpc`，版本 `2020-04-01`）。
4. 默认 endpoint：`https://open.volcengineapi.com`，可通过 `endpoint` 覆盖。

### Hetzner 说明

**Cloud VPS**（`hetzner_cloud_firewall`）：

1. 在 [Hetzner Cloud Console](https://console.hetzner.cloud/) 创建 API Token（读写）。
2. 创建 Firewall 并绑定到 Cloud Server（控制台 → Firewalls）。
3. 配置 `firewall_id` 为防火墙数字 ID；工具通过 `set_rules` 在保留既有规则的前提下追加/删除白名单入站规则。

**Dedicated Server**（`hetzner_robot_firewall`）：

1. 使用 [Robot](https://robot.hetzner.com/) 的 Webservice 用户名与密码。
2. `server_number` 为 Robot 中的 Server ID（非 IP）。
3. 入站方向最多 **10 条** 规则；更新会替换整组 input/output 规则，工具会先 GET 再合并后 POST。
4. API 基址默认 `https://robot-ws.your-server.de`，可通过 `endpoint` 覆盖。

### Scaleway 说明

1. 在 [Scaleway 控制台](https://console.scaleway.com/) 创建 API Key，使用 **Secret Key** 作为 `secret_key`（也可用 `api_token` 字段）。
2. 在 Instance → Security groups 中复制安全组 UUID（与 VPS 同可用区）。
3. `zone` 为可用区 ID，例如 `fr-par-1`、`nl-ams-1`（与 `region` 二选一，优先 `zone`）。
4. API 权限需能管理 Instance 安全组规则（Create/List/Delete rules）。

## 兼容旧配置

仍支持旧版单 `backend: lighthouse` + `tencent:` / `lighthouse:` 结构；推荐使用 `targets` 多目标配置。

## 权限

见各云厂商 RAM/CAM 文档（Create/Delete/List 防火墙或安全组规则）。
