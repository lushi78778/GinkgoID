# -----------------------------------------------------------------------------
# GinkgoID Dockerfile (multi-stage build)
# -----------------------------------------------------------------------------
# 可调节参数（如需自定义请在构建时使用 --build-arg 覆盖）：
#   GO_VERSION       - Go 版本号，用于构建阶段（默认 1.24）
#   ALPINE_VERSION   - 运行阶段的基础镜像（默认 3.20）
#   APP_NAME         - 最终生成的可执行文件名称
#   TARGET_OS        - 目标操作系统 (linux)；如需交叉编译可覆盖
#   TARGET_ARCH      - 目标架构 (amd64)；可设置为 arm64 等
# -----------------------------------------------------------------------------

ARG GO_VERSION=1.24
ARG ALPINE_VERSION=3.20
ARG APP_NAME=ginkgoid
ARG TARGET_OS=linux
ARG TARGET_ARCH=amd64

# ------------------------------ Builder Stage --------------------------------
FROM golang:${GO_VERSION} AS builder

WORKDIR /src

# 缓存依赖，确保 go mod tidy 已在仓库中执行
COPY go.mod go.sum ./
RUN go mod download

# 拷贝剩余源代码
COPY . .

# 设置交叉编译目标并构建
ENV CGO_ENABLED=0 GOOS=${TARGET_OS} GOARCH=${TARGET_ARCH}
RUN go build -ldflags "-s -w" -o /out/${APP_NAME} ./cmd/server

# ------------------------------ Runtime Stage --------------------------------
FROM alpine:${ALPINE_VERSION}

# 运行时依赖（ca-certificates 用于 https 调用）
RUN apk add --no-cache ca-certificates tzdata

# 创建非 root 用户以提升安全性
ARG APP_USER=app
ARG APP_UID=10001
RUN adduser -S -u ${APP_UID} -h /app ${APP_USER}

WORKDIR /app

# 拷贝二进制和需要的静态文件
COPY --from=builder /out/${APP_NAME} /app/${APP_NAME}
COPY config.yaml /app/config.yaml.example
COPY web /app/web
COPY docs /app/docs

# 挂载点：可在运行时挂载实际 config.yaml、静态资源等
VOLUME ["/app/config"]

# 暴露端口（与 http_addr 对应）
EXPOSE 8080

USER ${APP_USER}

ENTRYPOINT ["/app/ginkgoid"]
CMD ["--config", "/app/config/config.yaml"]
