#FROM golang:1.22-alpine AS build
#WORKDIR /app
#COPY . .
#RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
#    go build -o /out/sso ./cmd/sso-server
#
#FROM alpine:3.19
#WORKDIR /app
#ENV GIN_MODE=release
#COPY --from=build /out/sso /usr/local/bin/sso
#COPY manifest/config /app/config
#EXPOSE 8080
#CMD ["/usr/local/bin/sso"]
#
