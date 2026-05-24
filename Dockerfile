# 多阶段构建：容器内编译，Go 使用 goproxy.cn
# 拉取基础镜像需配置 registry-mirrors（如 https://docker.deepflood.xyz）
# 若构建阶段 DNS/网络异常，compose 已设置 build.network: host

FROM golang:1.22-alpine AS builder

ENV GOPROXY=https://goproxy.cn,direct \
    GOSUMDB=sum.golang.google.cn \
    CGO_ENABLED=0 \
    GODEBUG=netdns=go

# Alpine APK 使用国内源，带重试（构建环境外网不稳定时）
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories \
    && for i in 1 2 3 4 5; do \
         apk add --no-cache ca-certificates tzdata && break \
         || { echo "apk retry $i"; sleep 3; }; \
       done

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -trimpath -ldflags="-s -w" -o /out/FirewallKeeper .

# 运行镜像：从 builder 复制证书与时区，最终阶段不再 apk install
FROM alpine:3.20

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /out/FirewallKeeper /usr/local/bin/FirewallKeeper
COPY docker/entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh /usr/local/bin/FirewallKeeper \
    && mkdir -p /data && chown -R 1000:1000 /data

USER 1000:1000
WORKDIR /app

ENV CONFIG_PATH=/etc/FirewallKeeper/config.yaml
ENV TZ=Asia/Shanghai

VOLUME ["/data"]

ENTRYPOINT ["/entrypoint.sh"]
CMD []
