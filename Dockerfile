# vpngate-agg 镜像：多阶段，产物是一个静态二进制 + 一套 CA 证书。
#
# 构建:   docker build -t vpngate-agg .
# 跑起来: docker run -d -p 8080:8080 -v vpngate-agg-data:/data vpngate-agg
#
# 想换 Go 版本（go.mod 里写的是最低要求）:
#   docker build --build-arg GOVERSION=1.27 -t vpngate-agg .
#
# 追求更小可以把运行阶段换成 scratch：二进制已经是 CGO_ENABLED=0 静态的，
# 但要自己把 /etc/ssl/certs/ca-certificates.crt 拷进去（不拷 HTTPS 会全部失败），
# 而且 scratch 里没有 wget，HEALTHCHECK 就没了。这里用 alpine 换个省心。
ARG GOVERSION=1.26
FROM docker.io/library/golang:${GOVERSION}-alpine AS build

WORKDIR /src

# 先只拷 go.mod：源码改动不会破坏依赖层缓存（目前零第三方依赖，将来加了也照用）。
COPY go.mod ./
RUN go mod download || true

COPY . .

ARG VERSION=docker
# -buildvcs=false：.dockerignore 排掉了 .git，不关掉 VCS 打戳会报错。
# -s -w 已经把符号表和 DWARF 去掉（顺带也就没有 buildinfo 了）。
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} go build \
      -trimpath -buildvcs=false \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/vpngate-agg .

FROM docker.io/library/alpine:3.20

RUN apk add --no-cache ca-certificates tzdata wget \
    && addgroup -S -g 10001 vpngate \
    && adduser -S -u 10001 -G vpngate -D -H vpngate \
    && mkdir -p /data \
    && chown -R 10001:10001 /data

COPY --from=build /out/vpngate-agg /usr/local/bin/vpngate-agg

# 环境变量就是配置的覆盖项，见 README 的「环境变量」。
ENV VPNGATE_AGG_LISTEN=:8080 \
    VPNGATE_AGG_DATA_DIR=/data \
    VPNGATE_AGG_CONFIG=/data/config.json \
    TZ=Asia/Shanghai

VOLUME ["/data"]
EXPOSE 8080

USER 10001:10001
WORKDIR /data

HEALTHCHECK --interval=60s --timeout=5s --start-period=70s --retries=3 \
  CMD wget -q -O /dev/null "http://127.0.0.1:${VPNGATE_AGG_LISTEN##*:}/healthz" || exit 1

ENTRYPOINT ["/usr/local/bin/vpngate-agg"]
CMD ["serve"]
