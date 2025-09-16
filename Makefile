SHELL := /bin/bash

.PHONY: build run fmt vet lint e2e docker docker-up docker-down ci swagger

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

