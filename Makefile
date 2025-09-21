SHELL := /bin/bash

.PHONY: build run fmt vet lint e2e docker docker-up docker-down ci swagger clean

build:
	go build ./...

run:
	go run ./cmd/server

fmt:
	gofmt -s -w .

vet:
	go vet ./...

lint: vet
	@echo "lint ok (vet only)"

swagger:
	@echo "Generating OpenAPI specification..."
	@go run github.com/swaggo/swag/cmd/swag init --generalInfo cmd/server/main.go --output docs
	@echo "Done."

e2e:
	go run ./cmd/e2e -base http://127.0.0.1:8080

docker:
	docker build -t ginkgoid:latest .

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down -v

ci: fmt vet build
	@echo "CI checks passed"

clean:
	@echo "Cleaning build artifacts and caches..."
	@go clean -cache -testcache >/dev/null 2>&1 || true
	@rm -f server e2e ginkgoid
	@rm -rf frontend/.next frontend/out frontend/node_modules
	@echo "Done."
