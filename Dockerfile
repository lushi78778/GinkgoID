FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/server ./cmd/server

FROM alpine:3.20
WORKDIR /app
COPY --from=build /out/server /app/server
COPY config.yaml /app/config.yaml
COPY web /app/web
COPY docs /app/docs
EXPOSE 8080
ENTRYPOINT ["/app/server"]

