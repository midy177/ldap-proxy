# 使用多阶段构建
FROM --platform=$BUILDPLATFORM golang:alpine AS builder

# 定义项目名称
ARG TARGETOS
ARG TARGETARCH

WORKDIR /build
COPY . .

RUN go env -w GO111MODULE=on \
    && GOPROXY=https://goproxy.io \
    && go env -w CGO_ENABLED=0 \
    && go env \
    && go mod tidy \
    && GOOS=$TARGETOS GOARCH=$TARGETARCH go build -tags=sonic -trimpath -ldflags "-s -w" \
    -o ldap-proxy

# 使用 alpine 作为运行时镜像
FROM alpine:latest

WORKDIR /app

COPY --from=builder /build/ldap-proxy /bin/ldap-proxy
RUN chmod +x /bin/ldap-proxy && \
    apk update && apk add --no-cache tzdata && \
    cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo "Asia/Shanghai" > /etc/timezone

CMD ["ldap-proxy"]