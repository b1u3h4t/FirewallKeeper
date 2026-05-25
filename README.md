# FirewallKeeper

当本地公网 IP 发生变化时，自动将当前 IP 加入云服务器防火墙白名单（指定端口）。

| 后端 | 云厂商 | 场景 | API |
|------|--------|------|-----|
| `lighthouse` | 腾讯云 | 轻量应用服务器 | CreateFirewallRules / DeleteFirewallRules |
| `cvm` | 腾讯云 | 云服务器安全组 | CreateSecurityGroupPolicies / DeleteSecurityGroupPolicies |
| `aliyun_swas` | 阿里云国际版 | Simple Application Server（轻量） | CreateFirewallRules / DeleteFirewallRules / ListFirewallRules |

## 构建与运行

### 本地编译

```bash
cd FirewallKeeper

cp config.example.yaml config.yaml
# 阿里云国际版轻量: cp config.aliyun.example.yaml config.yaml

make build
./FirewallKeeper -once -c config.yaml   # 单次
./FirewallKeeper -c config.yaml         # 守护轮询
```

### 配置示例（阿里云国际版 SWAS）

```yaml
backend: aliyun_swas

aliyun:
  access_key_id: "LTAIxxxxxxxx"
  access_key_secret: "xxxxxxxxxxxxxxxx"
  region: "us-east-1"          # 与实例地域一致

aliyun_swas:
  instance_id: "your-instance-id"

ports:
  - "22"
  - "443"

protocol: TCP
remove_old_ip: true
```

国际地域 Endpoint 自动为 `swas.{region}.aliyuncs.com`（如 `swas.us-east-1.aliyuncs.com`）。

### Docker 一键部署

```bash
cp config.docker.example.yaml config.yaml   # 或 config.aliyun.example.yaml
cp .env.example .env                        # 可选
make docker-up
make docker-logs      # 最近 50 行，立即退出
make docker-logs-f    # 实时跟踪，Ctrl+C 结束
```

### 安装 Docker Compose 插件（Ubuntu）

```bash
sudo apt-get install -y docker-compose-v2
docker compose version
```

## 环境变量

| 变量 | 用途 |
|------|------|
| `TENCENT_SECRET_ID` / `TENCENT_SECRET_KEY` / `TENCENT_REGION` | 腾讯云 |
| `LIGHTHOUSE_INSTANCE_ID` | 腾讯轻量实例 |
| `SECURITY_GROUP_ID` | 腾讯安全组 |
| `ALIBABA_CLOUD_ACCESS_KEY_ID` / `ALIBABA_CLOUD_ACCESS_KEY_SECRET` | 阿里云 |
| `ALIBABA_CLOUD_REGION` | 阿里云地域 |
| `ALIBABA_CLOUD_SWAS_INSTANCE_ID` | 阿里云轻量实例 |
| `STATE_FILE` | 状态文件路径 |
| `CONFIG_PATH` | 配置文件路径 |

## 权限（RAM）

**腾讯云**

- 轻量：`lighthouse:CreateFirewallRules`、`lighthouse:DeleteFirewallRules`
- CVM：`vpc:CreateSecurityGroupPolicies`、`vpc:DeleteSecurityGroupPolicies`

**阿里云国际版 SWAS**

- `swas-open:CreateFirewallRules`
- `swas-open:DeleteFirewallRules`
- `swas-open:ListFirewallRules`（删除旧 IP 时匹配规则）

## systemd 示例

```ini
[Service]
Type=oneshot
WorkingDirectory=/opt/FirewallKeeper
ExecStart=/opt/FirewallKeeper/FirewallKeeper -once -c /opt/FirewallKeeper/config.yaml
```

```ini
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
```
