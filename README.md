# FirewallKeeper

当本地公网 IP 发生变化时，自动将当前 IP 加入**一个或多个**云服务器防火墙白名单（指定端口）。

**可同时启用多个目标**：例如腾讯云轻量 + 阿里云国际版 SWAS，一次 IP 变更会更新全部 `enabled: true` 的 targets。

## 支持的后端（provider）

| provider | 云厂商 | 场景 |
|----------|--------|------|
| `tencent_lighthouse` | 腾讯云 | 轻量应用服务器防火墙 |
| `tencent_cvm` | 腾讯云 | CVM 安全组入站 |
| `aliyun_swas` | 阿里云国际版 | Simple Application Server 防火墙 |

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

```bash
cp config.docker.example.yaml config.yaml
make docker-up
make docker-logs
```

## 环境变量

全局密钥仍可通过环境变量注入（对所有未在 yaml 填写的同类型字段生效）：

- 腾讯云：`TENCENT_SECRET_ID`、`TENCENT_SECRET_KEY`、`TENCENT_REGION`、`LIGHTHOUSE_INSTANCE_ID`、`SECURITY_GROUP_ID`
- 阿里云：`ALIBABA_CLOUD_ACCESS_KEY_ID`、`ALIBABA_CLOUD_ACCESS_KEY_SECRET`、`ALIBABA_CLOUD_REGION`、`ALIBABA_CLOUD_SWAS_INSTANCE_ID`

## 兼容旧配置

仍支持旧版单 `backend: lighthouse` + `tencent:` / `lighthouse:` 结构；推荐使用 `targets` 多目标配置。

## 权限

见各云厂商 RAM/CAM 文档（Create/Delete/List 防火墙或安全组规则）。
