GO ?= go

.PHONY: dev build e2e create-client rotate-jwk migrate

dev:
	$(GO) run ./cmd/sso-server

build:
	$(GO) build ./cmd/sso-server

e2e:
	$(GO) run ./hack/test-e2e

create-client:
	$(GO) run ./hack/create-client demo DemoApp http://localhost:8081/callback public

rotate-jwk:
	$(GO) run ./hack/rotate-jwk

migrate:
	$(GO) run ./hack/migrate

## 文档相关目标已移除（按需可在本地使用 `go doc` 查看）

.PHONY: docker-up docker-down docker-logs
docker-up:
	docker compose -f manifest/docker/docker-compose.yml up --build -d

docker-down:
	docker compose -f manifest/docker/docker-compose.yml down -v

docker-logs:
	docker compose -f manifest/docker/docker-compose.yml logs -f sso
